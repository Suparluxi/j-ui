package backup_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Suparluxi/j-ui/internal/application"
	"github.com/Suparluxi/j-ui/internal/backup"
	"github.com/Suparluxi/j-ui/internal/config"
	"github.com/Suparluxi/j-ui/internal/model"
	nodeservice "github.com/Suparluxi/j-ui/internal/node"
	"github.com/Suparluxi/j-ui/internal/secure"
	_ "modernc.org/sqlite"
)

func TestBackupRestoreRoundTrip(t *testing.T) {
	root := t.TempDir()
	source := testConfig(filepath.Join(root, "source"))
	app, err := application.New(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Store.SetSetting(context.Background(), "public_host", "node.example.com"); err != nil {
		t.Fatal(err)
	}
	outbound, err := app.Nodes.CreateOutbound(context.Background(), nodeservice.OutboundInput{
		Name: "backup exit", Type: "socks5", Server: "proxy.example.com",
		Port: 1080, Enabled: true, Username: "backup-user", Password: "backup-password",
		CredentialMode: "replace",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Nodes.Create(context.Background(), nodeservice.CreateInput{
		Name: "bound node", Protocol: "vless_reality", Listen: "127.0.0.1",
		Port: 24440, Enabled: false, ClientName: "default", OutboundID: &outbound.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if err := app.Store.Checkpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(root, "backup.tar.gz")
	if err := backup.Create(archive, source.DataDir, source.ConfigDir); err != nil {
		t.Fatal(err)
	}
	restored := testConfig(filepath.Join(root, "restored"))
	if err := backup.Restore(archive, restored.DataDir, restored.ConfigDir); err != nil {
		t.Fatal(err)
	}
	restoredApp, err := application.New(context.Background(), restored)
	if err != nil {
		t.Fatal(err)
	}
	defer restoredApp.Close()
	if restoredApp.Credentials != nil {
		t.Fatal("restore unexpectedly bootstrapped a new administrator")
	}
	host, err := restoredApp.Store.Setting(context.Background(), "public_host")
	if err != nil || host != "node.example.com" {
		t.Fatalf("restored public host = %q, err=%v", host, err)
	}
	restoredOutbounds, err := restoredApp.Store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	restoredNodes, err := restoredApp.Store.ListNodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(restoredOutbounds) != 1 || restoredOutbounds[0].Username != "backup-user" ||
		restoredOutbounds[0].Password != "backup-password" ||
		len(restoredNodes) != 1 || restoredNodes[0].OutboundID == nil ||
		*restoredNodes[0].OutboundID != restoredOutbounds[0].ID {
		t.Fatalf("restored outbound binding = %#v %#v", restoredOutbounds, restoredNodes)
	}
}

func TestRestoreRejectsCorruptedOutboundCredential(t *testing.T) {
	root := t.TempDir()
	source := testConfig(filepath.Join(root, "source"))
	app, err := application.New(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Nodes.CreateOutbound(context.Background(), nodeservice.OutboundInput{
		Name: "corrupt exit", Type: "http", Server: "proxy.example.com",
		Port: 8080, Enabled: true, Username: "user", Password: "password",
		CredentialMode: "replace",
	}); err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", source.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE outbounds SET credential_enc = 'corrupted'`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	archive := filepath.Join(root, "corrupted-outbound.tar.gz")
	if err := backup.Create(archive, source.DataDir, source.ConfigDir); err != nil {
		t.Fatal(err)
	}
	restored := testConfig(filepath.Join(root, "restored"))
	if err := backup.Restore(archive, restored.DataDir, restored.ConfigDir); err == nil {
		t.Fatal("restore accepted an undecryptable outbound credential")
	}
}

func TestRestoreRejectsCorruptedVPNGateCandidate(t *testing.T) {
	root := t.TempDir()
	source := testConfig(filepath.Join(root, "source"))
	app, err := application.New(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Store.ReplaceVPNGateCandidates(context.Background(), []model.VPNGateCandidate{{
		HostName: "vpn.example", IP: "198.51.100.10",
		CountryLong: "Japan", CountryShort: "JP",
		OpenVPNConfig: "client\nremote 198.51.100.10 1194 udp\n",
		FetchedAt:     time.Now().UTC(),
	}}); err != nil {
		app.Close()
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", source.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE vpngate_candidates SET config_enc = 'corrupted'`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "corrupted-vpngate.tar.gz")
	if err := backup.Create(archive, source.DataDir, source.ConfigDir); err != nil {
		t.Fatal(err)
	}
	restored := testConfig(filepath.Join(root, "restored"))
	if err := backup.Restore(archive, restored.DataDir, restored.ConfigDir); err == nil {
		t.Fatal("restore accepted an undecryptable VPNGate candidate")
	}
}

func TestRestoreRejectsCorruptedClientCredential(t *testing.T) {
	root := t.TempDir()
	source := testConfig(filepath.Join(root, "source"))
	app, err := application.New(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Nodes.Create(context.Background(), nodeservice.CreateInput{
		Name: "corrupt", Protocol: "vless_reality", Listen: "127.0.0.1",
		Port: 24443, Enabled: false, ClientName: "default",
	}); err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", source.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE node_clients SET credential_enc = 'corrupted'`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "corrupted.tar.gz")
	if err := backup.Create(archive, source.DataDir, source.ConfigDir); err != nil {
		t.Fatal(err)
	}
	restored := testConfig(filepath.Join(root, "restored"))
	if err := backup.Restore(archive, restored.DataDir, restored.ConfigDir); err == nil {
		t.Fatal("restore accepted an undecryptable client credential")
	}
}

func TestRestoreRejectsNodeWithoutClient(t *testing.T) {
	root := t.TempDir()
	source := testConfig(filepath.Join(root, "source"))
	app, err := application.New(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	node, err := app.Nodes.Create(context.Background(), nodeservice.CreateInput{
		Name: "orphan", Protocol: "vless_reality", Listen: "127.0.0.1",
		Port: 24444, Enabled: false, ClientName: "default",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", source.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM node_clients WHERE node_id = ?`, node.ID); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "missing-client.tar.gz")
	if err := backup.Create(archive, source.DataDir, source.ConfigDir); err != nil {
		t.Fatal(err)
	}
	restored := testConfig(filepath.Join(root, "restored"))
	if err := backup.Restore(archive, restored.DataDir, restored.ConfigDir); err == nil {
		t.Fatal("restore accepted a node without a client")
	}
}

func TestRestoreRejectsForeignKeyViolation(t *testing.T) {
	root := t.TempDir()
	source := testConfig(filepath.Join(root, "source"))
	app, err := application.New(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	node, err := app.Nodes.Create(context.Background(), nodeservice.CreateInput{
		Name: "bad-user", Protocol: "vless_reality", Listen: "127.0.0.1",
		Port: 24445, Enabled: false, ClientName: "default",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", source.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE node_clients SET user_id = 999 WHERE node_id = ?`, node.ID); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "foreign-key.tar.gz")
	if err := backup.Create(archive, source.DataDir, source.ConfigDir); err != nil {
		t.Fatal(err)
	}
	restored := testConfig(filepath.Join(root, "restored"))
	if err := backup.Restore(archive, restored.DataDir, restored.ConfigDir); err == nil {
		t.Fatal("restore accepted a foreign-key violation")
	}
}

func TestRestoreRejectsMissingRealityPrivateKey(t *testing.T) {
	root := t.TempDir()
	source := testConfig(filepath.Join(root, "source"))
	app, err := application.New(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	node, err := app.Nodes.Create(context.Background(), nodeservice.CreateInput{
		Name: "bad-reality", Protocol: "vless_reality", Listen: "127.0.0.1",
		Port: 24446, Enabled: false, ClientName: "default",
	})
	if err != nil {
		app.Close()
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(source.SecretKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := secure.NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	emptySecret, err := sealer.Seal([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", source.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE nodes SET secret_enc = ? WHERE id = ?`, emptySecret, node.ID); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "bad-reality.tar.gz")
	if err := backup.Create(archive, source.DataDir, source.ConfigDir); err != nil {
		t.Fatal(err)
	}
	restored := testConfig(filepath.Join(root, "restored"))
	if err := backup.Restore(archive, restored.DataDir, restored.ConfigDir); err == nil {
		t.Fatal("restore accepted Reality material without a private key")
	}
}

func TestRestoreRejectsDisabledDefaultUser(t *testing.T) {
	root := t.TempDir()
	source := testConfig(filepath.Join(root, "source"))
	app, err := application.New(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", source.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE users SET enabled = 0 WHERE id = 1`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "disabled-user.tar.gz")
	if err := backup.Create(archive, source.DataDir, source.ConfigDir); err != nil {
		t.Fatal(err)
	}
	restored := testConfig(filepath.Join(root, "restored"))
	if err := backup.Restore(archive, restored.DataDir, restored.ConfigDir); err == nil {
		t.Fatal("restore accepted a disabled default subscription user")
	}
}

func TestBackupRejectsDestinationInsideData(t *testing.T) {
	root := t.TempDir()
	dataDir, configDir := filepath.Join(root, "data"), filepath.Join(root, "config")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := backup.Create(filepath.Join(dataDir, "backup.tar.gz"), dataDir, configDir); err == nil {
		t.Fatal("backup destination inside data directory was accepted")
	}
}

func TestRestoreRejectsMismatchedEncryptionKey(t *testing.T) {
	root := t.TempDir()
	source := testConfig(filepath.Join(root, "source"))
	app, err := application.New(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Store.Checkpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source.SecretKeyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "mismatched.tar.gz")
	if err := backup.Create(archive, source.DataDir, source.ConfigDir); err != nil {
		t.Fatal(err)
	}
	restored := testConfig(filepath.Join(root, "restored"))
	if err := backup.Restore(archive, restored.DataDir, restored.ConfigDir); err == nil {
		t.Fatal("restore accepted a mismatched encryption key")
	}
}

func TestRestoreRejectsInvalidAdministratorHash(t *testing.T) {
	root := t.TempDir()
	source := testConfig(filepath.Join(root, "source"))
	app, err := application.New(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", source.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE administrators SET password_hash = '$argon2id$v=19$m=4294967295,t=3,p=2$AA$AA'`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "invalid-admin.tar.gz")
	if err := backup.Create(archive, source.DataDir, source.ConfigDir); err != nil {
		t.Fatal(err)
	}
	restored := testConfig(filepath.Join(root, "restored"))
	if err := backup.Restore(archive, restored.DataDir, restored.ConfigDir); err == nil {
		t.Fatal("restore accepted an invalid administrator hash")
	}
}

func testConfig(root string) config.Config {
	return config.Config{
		ListenAddress: "127.0.0.1:8080",
		DataDir:       filepath.Join(root, "data"), ConfigDir: filepath.Join(root, "config"),
		DatabasePath:  filepath.Join(root, "data", "j-ui.db"),
		SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"),
		SessionTTL:    time.Hour, MockEngine: true,
	}
}
