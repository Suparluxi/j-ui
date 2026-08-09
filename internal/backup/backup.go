package backup

import (
	"archive/tar"
	"compress/gzip"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Suparluxi/j-ui/internal/auth"
	"github.com/Suparluxi/j-ui/internal/model"
	"github.com/Suparluxi/j-ui/internal/secure"
	_ "modernc.org/sqlite"
)

func Create(destination, dataDir, configDir string) error {
	return create(destination, dataDir, configDir, "")
}

func CreateWithDatabaseSnapshot(destination, dataDir, configDir, databaseSnapshot string) error {
	if !filepath.IsAbs(databaseSnapshot) {
		return errors.New("database snapshot path must be absolute")
	}
	return create(destination, dataDir, configDir, databaseSnapshot)
}

func create(destination, dataDir, configDir, databaseSnapshot string) error {
	if err := validateDestination(destination, dataDir, configDir); err != nil {
		return err
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	success := false
	defer func() {
		file.Close()
		if !success {
			os.Remove(destination)
		}
	}()
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)

	for _, source := range []struct{ path, prefix string }{
		{dataDir, "data"},
		{configDir, "config"},
	} {
		if err := addTree(tarWriter, source.path, source.prefix, databaseSnapshot); err != nil {
			return err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return err
	}
	if err := gzipWriter.Close(); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	success = true
	return nil
}

func Restore(archive, dataDir, configDir string) error {
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzipReader.Close()

	staging, err := os.MkdirTemp("", "j-ui-restore-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	tarReader := tar.NewReader(gzipReader)
	var extractedBytes int64
	const maximumBackupBytes = int64(1 << 30)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		clean := filepath.Clean(header.Name)
		if clean == "." || filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return errors.New("backup contains an unsafe path")
		}
		target := filepath.Join(staging, clean)
		if !strings.HasPrefix(target, staging+string(filepath.Separator)) {
			return errors.New("backup path escapes staging directory")
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if header.Size < 0 || header.Size > maximumBackupBytes-extractedBytes {
				return errors.New("backup exceeds the 1 GiB extraction limit")
			}
			extractedBytes += header.Size
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(header.Mode)&0o700)
			if err != nil {
				return err
			}
			_, copyErr := io.CopyN(output, tarReader, header.Size)
			closeErr := output.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		default:
			return fmt.Errorf("unsupported backup entry %q", header.Name)
		}
	}
	databasePath := filepath.Join(staging, "data", "j-ui.db")
	if _, err := os.Stat(databasePath); err != nil {
		return errors.New("backup does not contain j-ui.db")
	}
	if _, err := os.Stat(filepath.Join(staging, "config", "secret.key")); err != nil {
		return errors.New("backup does not contain the instance encryption key")
	}
	if err := validateDatabase(databasePath); err != nil {
		return err
	}
	if err := validateEncryptionKey(databasePath, filepath.Join(staging, "config", "secret.key")); err != nil {
		return err
	}
	if err := validateLogicalState(databasePath, filepath.Join(staging, "config", "secret.key")); err != nil {
		return err
	}
	stagedData, err := stageTree(filepath.Join(staging, "data"), filepath.Dir(dataDir), ".j-ui-data-restore-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stagedData)
	stagedConfig, err := stageTree(filepath.Join(staging, "config"), filepath.Dir(configDir), ".j-ui-config-restore-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stagedConfig)
	return replaceTree(stagedData, dataDir, stagedConfig, configDir)
}

func DefaultName() string {
	return "j-ui-backup-" + time.Now().UTC().Format("20060102T150405Z") + ".tar.gz"
}

func addTree(writer *tar.Writer, root, prefix, databaseSnapshot string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if strings.HasSuffix(path, "-shm") || strings.HasSuffix(path, "-wal") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(filepath.Join(prefix, relative))
		contentPath := path
		if databaseSnapshot != "" && prefix == "data" && relative == "j-ui.db" {
			snapshotInfo, err := os.Stat(databaseSnapshot)
			if err != nil {
				return err
			}
			info = snapshotInfo
			contentPath = databaseSnapshot
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = name
		header.Mode &= 0o700
		if err := writer.WriteHeader(header); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		file, err := os.Open(contentPath)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(writer, file)
		return err
	})
}

func replaceTree(stagedData, dataDir, stagedConfig, configDir string) error {
	return replaceTreeWithOps(stagedData, dataDir, stagedConfig, configDir, os.Rename, os.RemoveAll)
}

func replaceTreeWithOps(
	stagedData, dataDir, stagedConfig, configDir string,
	rename func(string, string) error,
	removeAll func(string) error,
) error {
	if err := os.MkdirAll(filepath.Dir(dataDir), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(configDir), 0o755); err != nil {
		return err
	}
	suffix := fmt.Sprintf(".pre-restore-%d", time.Now().UnixNano())
	oldData, oldConfig := dataDir+suffix, configDir+suffix
	hadData, hadConfig := true, true
	if err := rename(dataDir, oldData); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		hadData = false
	}
	if err := rename(configDir, oldConfig); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			hadConfig = false
		} else {
			return joinRollback(err, restoreTree(rename, oldData, dataDir, hadData))
		}
	}
	if err := rename(stagedData, dataDir); err != nil {
		return joinRollback(err,
			restoreTree(rename, oldData, dataDir, hadData),
			restoreTree(rename, oldConfig, configDir, hadConfig),
		)
	}
	if err := rename(stagedConfig, configDir); err != nil {
		removeErr := removeAll(dataDir)
		var restoreDataErr error
		if removeErr == nil {
			restoreDataErr = restoreTree(rename, oldData, dataDir, hadData)
		}
		return joinRollback(err, removeErr, restoreDataErr,
			restoreTree(rename, oldConfig, configDir, hadConfig),
		)
	}
	return joinRollback(nil, removeIfPresent(removeAll, oldData, hadData), removeIfPresent(removeAll, oldConfig, hadConfig))
}

func restoreTree(rename func(string, string) error, oldPath, livePath string, existed bool) error {
	if !existed {
		return nil
	}
	if err := rename(oldPath, livePath); err != nil {
		return fmt.Errorf("restore %s: %w", livePath, err)
	}
	return nil
}

func removeIfPresent(removeAll func(string) error, path string, present bool) error {
	if !present {
		return nil
	}
	if err := removeAll(path); err != nil {
		return fmt.Errorf("remove rollback tree %s: %w", path, err)
	}
	return nil
}

func joinRollback(primary error, rollbackErrors ...error) error {
	joined := make([]error, 0, len(rollbackErrors)+1)
	if primary != nil {
		joined = append(joined, primary)
	}
	for _, err := range rollbackErrors {
		if err != nil {
			joined = append(joined, err)
		}
	}
	if len(joined) == 0 {
		return nil
	}
	return errors.Join(joined...)
}

func stageTree(source, parent, pattern string) (string, error) {
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", err
	}
	destination, err := os.MkdirTemp(parent, pattern)
	if err != nil {
		return "", err
	}
	if err := copyTree(source, destination); err != nil {
		os.RemoveAll(destination)
		return "", err
	}
	return destination, nil
}

func copyTree(source, destination string) error {
	return filepath.Walk(source, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm()&0o700)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported staged file %q", relative)
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		defer input.Close()
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm()&0o700)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(output, input)
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}

func validateDatabase(path string) error {
	db, err := sql.Open("sqlite", path+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	var result string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&result); err != nil {
		return err
	}
	if result != "ok" {
		return fmt.Errorf("backup database integrity check failed: %s", result)
	}
	return nil
}

func validateEncryptionKey(databasePath, keyPath string) error {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	sealer, err := secure.NewSealer(key)
	if err != nil {
		return errors.New("backup contains an invalid instance encryption key")
	}
	db, err := sql.Open("sqlite", databasePath+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	var encrypted string
	if err := db.QueryRow(`SELECT subscription_token_enc FROM users WHERE id = 1`).Scan(&encrypted); err != nil {
		return err
	}
	if _, err := sealer.Open(encrypted); err != nil {
		return errors.New("backup encryption key does not match the database")
	}
	for _, source := range []struct {
		query string
		name  string
	}{
		{`SELECT secret_enc FROM nodes`, "node secret"},
		{`SELECT credential_enc FROM node_clients`, "client credential"},
	} {
		rows, err := db.Query(source.query)
		if err != nil {
			return err
		}
		for rows.Next() {
			if err := rows.Scan(&encrypted); err != nil {
				rows.Close()
				return err
			}
			plain, err := sealer.Open(encrypted)
			if err != nil || !json.Valid(plain) {
				rows.Close()
				return fmt.Errorf("backup contains an undecryptable %s", source.name)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}
	return nil
}

func validateLogicalState(databasePath, keyPath string) error {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	sealer, err := secure.NewSealer(key)
	if err != nil {
		return errors.New("backup contains an invalid instance encryption key")
	}
	db, err := sql.Open("sqlite", databasePath+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	foreignKeyRows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		return err
	}
	if foreignKeyRows.Next() {
		foreignKeyRows.Close()
		return errors.New("backup contains a foreign-key integrity violation")
	}
	if err := foreignKeyRows.Err(); err != nil {
		foreignKeyRows.Close()
		return err
	}
	foreignKeyRows.Close()
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version < 1 || version > 9 {
		return fmt.Errorf("backup has unsupported schema version %d", version)
	}
	var adminID, adminCount int
	var username, passwordHash string
	if err := db.QueryRow(`SELECT COUNT(*), COALESCE(MIN(id), 0), COALESCE(MIN(username), ''), COALESCE(MIN(password_hash), '') FROM administrators`).
		Scan(&adminCount, &adminID, &username, &passwordHash); err != nil {
		return err
	}
	if adminCount != 1 || adminID != 1 || !auth.ValidAdministratorUsername(username) || !auth.ValidPasswordHash(passwordHash) {
		return errors.New("backup contains an invalid administrator account")
	}
	var userCount, userID, userEnabled int
	var tokenHash, tokenEncrypted string
	if err := db.QueryRow(`SELECT COUNT(*), COALESCE(MIN(id), 0),
		COALESCE(MIN(subscription_token_hash), ''), COALESCE(MIN(subscription_token_enc), ''),
		COALESCE(MIN(enabled), 0) FROM users`).
		Scan(&userCount, &userID, &tokenHash, &tokenEncrypted, &userEnabled); err != nil {
		return err
	}
	token, openErr := sealer.Open(tokenEncrypted)
	if userCount != 1 || userID != 1 || userEnabled != 1 || openErr != nil ||
		len(token) < 32 || tokenHash != secure.HashToken(string(token)) {
		return errors.New("backup contains an invalid default subscription user")
	}
	var adminPath string
	if err := db.QueryRow(`SELECT value FROM system_settings WHERE key = 'admin_path'`).Scan(&adminPath); err != nil {
		return errors.New("backup does not contain a management path")
	}
	suffix := strings.TrimPrefix(adminPath, "manage-")
	decoded, decodeErr := hex.DecodeString(suffix)
	if !strings.HasPrefix(adminPath, "manage-") || decodeErr != nil || len(decoded) != 12 {
		return errors.New("backup contains an invalid management path")
	}
	rows, err := db.Query(`
		SELECT n.id, n.protocol, n.listen, n.port, n.settings_json, n.secret_enc,
		       COUNT(c.id), COALESCE(MIN(c.user_id), 0), COALESCE(MAX(c.user_id), 0)
		FROM nodes n
		LEFT JOIN node_clients c ON c.node_id = n.id
		GROUP BY n.id
	`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var nodeID int64
		var protocol, listen, settingsJSON, secretEncrypted string
		var port, clientCount, minimumUserID, maximumUserID int
		if err := rows.Scan(
			&nodeID, &protocol, &listen, &port, &settingsJSON, &secretEncrypted,
			&clientCount, &minimumUserID, &maximumUserID,
		); err != nil {
			return err
		}
		if !model.SupportedProtocol(protocol) || net.ParseIP(listen) == nil || port < 1 || port > 65535 ||
			clientCount < 1 || minimumUserID != 1 || maximumUserID != 1 {
			return errors.New("backup contains an invalid node")
		}
		var settings, secret map[string]any
		secretJSON, secretErr := sealer.Open(secretEncrypted)
		if json.Unmarshal([]byte(settingsJSON), &settings) != nil ||
			secretErr != nil || json.Unmarshal(secretJSON, &secret) != nil ||
			!validNodeMaterial(protocol, settings, secret) {
			return errors.New("backup contains invalid node protocol material")
		}
		clientRows, err := db.Query(
			`SELECT credential_enc FROM node_clients WHERE node_id = ?`, nodeID,
		)
		if err != nil {
			return err
		}
		for clientRows.Next() {
			var credentialEncrypted string
			if err := clientRows.Scan(&credentialEncrypted); err != nil {
				clientRows.Close()
				return err
			}
			credentialJSON, err := sealer.Open(credentialEncrypted)
			var credential map[string]any
			if err != nil || json.Unmarshal(credentialJSON, &credential) != nil ||
				!validCredential(protocol, credential) {
				clientRows.Close()
				return errors.New("backup contains invalid client protocol material")
			}
		}
		if err := clientRows.Err(); err != nil {
			clientRows.Close()
			return err
		}
		clientRows.Close()
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if version >= 7 {
		outboundRows, err := db.Query(
			`SELECT type, server, port, enabled, credential_enc FROM outbounds`,
		)
		if err != nil {
			return err
		}
		for outboundRows.Next() {
			var outboundType, server, encrypted string
			var port, enabled int
			if err := outboundRows.Scan(&outboundType, &server, &port, &enabled, &encrypted); err != nil {
				outboundRows.Close()
				return err
			}
			plain, openErr := sealer.Open(encrypted)
			var credential map[string]string
			if !model.SupportedOutbound(outboundType) || strings.TrimSpace(server) == "" ||
				strings.Contains(server, "://") || port < 1 || port > 65535 ||
				(enabled != 0 && enabled != 1) || openErr != nil ||
				json.Unmarshal(plain, &credential) != nil {
				outboundRows.Close()
				return errors.New("backup contains an invalid manual outbound")
			}
		}
		if err := outboundRows.Err(); err != nil {
			outboundRows.Close()
			return err
		}
		outboundRows.Close()
	}
	if version >= 8 {
		var invalidManagedKinds int
		if err := db.QueryRow(
			`SELECT COUNT(*) FROM outbounds WHERE managed_kind NOT IN ('manual', 'vpngate')`,
		).Scan(&invalidManagedKinds); err != nil || invalidManagedKinds != 0 {
			return errors.New("backup contains an invalid managed outbound type")
		}
		candidateRows, err := db.Query(
			`SELECT host_name, ip, country_short, config_enc FROM vpngate_candidates`,
		)
		if err != nil {
			return err
		}
		for candidateRows.Next() {
			var hostName, ip, country, encrypted string
			if err := candidateRows.Scan(&hostName, &ip, &country, &encrypted); err != nil {
				candidateRows.Close()
				return err
			}
			config, openErr := sealer.Open(encrypted)
			parsedIP := net.ParseIP(ip)
			if strings.TrimSpace(hostName) == "" || parsedIP == nil || parsedIP.To4() == nil ||
				len(country) != 2 || openErr != nil || len(config) == 0 {
				candidateRows.Close()
				return errors.New("backup contains an invalid VPNGate candidate")
			}
		}
		if err := candidateRows.Err(); err != nil {
			candidateRows.Close()
			return err
		}
		candidateRows.Close()

		exitRows, err := db.Query(`
			SELECT e.slot, e.namespace, e.local_address, e.local_port, e.status,
			       e.failure_policy, e.permanent, e.candidate_ip, e.remote_protocol,
			       e.remote_port, o.managed_kind, o.type, o.server, o.port
			FROM vpngate_exits e
			JOIN outbounds o ON o.id = e.outbound_id
		`)
		if err != nil {
			return err
		}
		for exitRows.Next() {
			var namespace, localAddress, status, policy, candidateIP, remoteProtocol string
			var managedKind, outboundType, outboundServer string
			var slot, localPort, permanent, remotePort, outboundPort int
			if err := exitRows.Scan(
				&slot, &namespace, &localAddress, &localPort, &status, &policy,
				&permanent, &candidateIP, &remoteProtocol, &remotePort,
				&managedKind, &outboundType, &outboundServer, &outboundPort,
			); err != nil {
				exitRows.Close()
				return err
			}
			expectedAddress := fmt.Sprintf("10.254.%d.2", slot)
			if slot < 1 || slot > 5 || namespace != fmt.Sprintf("jui-vpn-%d", slot) ||
				localAddress != expectedAddress || localPort != 1080 ||
				managedKind != "vpngate" || outboundType != model.OutboundSOCKS5 ||
				outboundServer != expectedAddress || outboundPort != 1080 ||
				(policy != "block" && policy != "auto_swap") ||
				(permanent != 0 && permanent != 1) || !validVPNGateStatus(status) {
				exitRows.Close()
				return errors.New("backup contains invalid VPNGate exit metadata")
			}
			parsedCandidateIP := net.ParseIP(candidateIP)
			if candidateIP == "" || parsedCandidateIP == nil || parsedCandidateIP.To4() == nil {
				exitRows.Close()
				return errors.New("backup contains an invalid VPNGate endpoint")
			}
			if status == "running" &&
				((remoteProtocol != "udp" && remoteProtocol != "tcp-client") ||
					remotePort < 1 || remotePort > 65535) {
				exitRows.Close()
				return errors.New("backup contains an invalid running VPNGate transport")
			}
		}
		if err := exitRows.Err(); err != nil {
			exitRows.Close()
			return err
		}
		exitRows.Close()
	}
	if version >= 6 {
		configRows, err := db.Query(`SELECT config FROM config_versions`)
		if err != nil {
			return err
		}
		for configRows.Next() {
			var encrypted string
			if err := configRows.Scan(&encrypted); err != nil {
				configRows.Close()
				return err
			}
			config, err := sealer.Open(encrypted)
			if err != nil || !json.Valid(config) {
				configRows.Close()
				return errors.New("backup contains an invalid encrypted configuration version")
			}
		}
		if err := configRows.Err(); err != nil {
			configRows.Close()
			return err
		}
		configRows.Close()
	}
	return nil
}

func validVPNGateStatus(status string) bool {
	switch status {
	case "provisioning", "running", "swapping", "faulted", "expired":
		return true
	default:
		return false
	}
}

func validNodeMaterial(protocol string, settings, secret map[string]any) bool {
	switch protocol {
	case model.ProtocolVLESSReality, model.ProtocolVLESSH2Reality,
		model.ProtocolVLESSGRPCReality, model.ProtocolAnyTLSReality:
		valid := nonemptyString(secret, "private_key") &&
			nonemptyString(settings, "public_key") &&
			nonemptyString(settings, "short_id") &&
			nonemptyString(settings, "handshake_server") &&
			nonemptyString(settings, "server_name") &&
			validJSONPort(settings["handshake_port"])
		if protocol == model.ProtocolVLESSH2Reality {
			path, _ := settings["transport_path"].(string)
			valid = valid && strings.HasPrefix(path, "/")
		}
		if protocol == model.ProtocolVLESSGRPCReality {
			valid = valid && nonemptyString(settings, "service_name")
		}
		return valid
	case model.ProtocolVLESSWSTLS:
		path, _ := settings["ws_path"].(string)
		return validTLSMaterial(settings) && strings.HasPrefix(path, "/")
	case model.ProtocolVLESSArgo:
		path, _ := settings["ws_path"].(string)
		return nonemptyString(settings, "server_name") && strings.HasPrefix(path, "/")
	case model.ProtocolTrojanTLS, model.ProtocolHysteria2, model.ProtocolTUIC,
		model.ProtocolAnyTLS, model.ProtocolNaive:
		return validTLSMaterial(settings)
	case model.ProtocolSOCKS5:
		return true
	default:
		return false
	}
}

func validTLSMaterial(settings map[string]any) bool {
	certificate, _ := settings["certificate_path"].(string)
	key, _ := settings["key_path"].(string)
	return nonemptyString(settings, "server_name") &&
		filepath.IsAbs(certificate) && filepath.IsAbs(key) && certificate != key
}

func validCredential(protocol string, credential map[string]any) bool {
	switch protocol {
	case model.ProtocolVLESSReality, model.ProtocolVLESSH2Reality,
		model.ProtocolVLESSGRPCReality, model.ProtocolVLESSWSTLS, model.ProtocolVLESSArgo:
		return validUUIDString(credential["uuid"])
	case model.ProtocolTrojanTLS, model.ProtocolHysteria2, model.ProtocolAnyTLS,
		model.ProtocolAnyTLSReality:
		return nonemptyString(credential, "password")
	case model.ProtocolTUIC:
		return validUUIDString(credential["uuid"]) && nonemptyString(credential, "password")
	case model.ProtocolSOCKS5, model.ProtocolNaive:
		return nonemptyString(credential, "username") && nonemptyString(credential, "password")
	default:
		return false
	}
}

func nonemptyString(values map[string]any, key string) bool {
	value, ok := values[key].(string)
	return ok && strings.TrimSpace(value) != ""
}

func validJSONPort(value any) bool {
	number, ok := value.(float64)
	return ok && number >= 1 && number <= 65535 && number == float64(int(number))
}

func validUUIDString(value any) bool {
	text, ok := value.(string)
	if !ok || len(text) != 36 ||
		text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(text, "-", ""))
	return err == nil
}

func validateDestination(destination string, roots ...string) error {
	absoluteDestination, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	for _, root := range roots {
		absoluteRoot, err := filepath.Abs(root)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(absoluteRoot, absoluteDestination)
		if err == nil && relative != ".." &&
			!strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("backup destination must be outside J-UI data and configuration directories")
		}
	}
	return nil
}
