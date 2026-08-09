package database

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Suparluxi/j-ui/internal/model"
	"github.com/Suparluxi/j-ui/internal/secure"
	_ "modernc.org/sqlite"
)

type Store struct {
	db     *sql.DB
	sealer *secure.Sealer
}

var ErrConflict = errors.New("database conflict")

func IsConflict(err error) bool {
	return errors.Is(err, ErrConflict)
}

func normalizeWriteError(err error) error {
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "unique constraint failed") {
		return fmt.Errorf("%w: %v", ErrConflict, err)
	}
	return err
}

type Bootstrap struct {
	AdminPasswordHash string
	AdminPath         string
	TokenHash         string
	TokenEncrypted    string
	NodeStartPort     int
}

type ManagedFirewallRule struct {
	Protocol  string
	Port      int
	Ownership string
	Backend   string
}

const (
	FirewallPending   = "pending"
	FirewallOwned     = "owned"
	FirewallBorrowed  = "borrowed"
	FirewallUnknown   = "unknown"
	FirewallFirewalld = "firewalld"
	FirewallUFW       = "ufw"
	FirewallNFTables  = "nftables"
)

func Open(path string, sealer *secure.Sealer) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db, sealer: sealer}
	if err := store.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	// Flush migration writes before returning. In particular, schema v6
	// securely deletes legacy plaintext configuration history and must not
	// leave the old pages readable in the main database or WAL.
	if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("checkpoint database migrations: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = db.Close()
		return nil, err
	}
	for _, related := range []string{path + "-wal", path + "-shm"} {
		if err := os.Chmod(related, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			_ = db.Close()
			return nil, err
		}
	}
	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Initialized(ctx context.Context) (bool, error) {
	var administrators, users, adminPath int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM administrators`).Scan(&administrators); err != nil {
		return false, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&users); err != nil {
		return false, err
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM system_settings WHERE key = 'admin_path' AND value != ''`,
	).Scan(&adminPath); err != nil {
		return false, err
	}
	return administrators == 1 && users >= 1 && adminPath == 1, nil
}

func (s *Store) migrate(ctx context.Context) error {
	migrations := [][]string{
		{
			`CREATE TABLE administrators (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
			`CREATE TABLE sessions (
			token_hash TEXT PRIMARY KEY,
			csrf_token TEXT NOT NULL,
			source_ip TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL
		)`,
			`CREATE TABLE users (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			subscription_token_hash TEXT NOT NULL UNIQUE,
			subscription_token_enc TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL
		)`,
			`CREATE TABLE nodes (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			protocol TEXT NOT NULL,
			listen TEXT NOT NULL,
			port INTEGER NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			public_host_override TEXT NOT NULL DEFAULT '',
			settings_json TEXT NOT NULL,
			secret_enc TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			UNIQUE(listen, port)
		)`,
			`CREATE TABLE node_clients (
			id INTEGER PRIMARY KEY,
			node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			credential_enc TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL
		)`,
			`CREATE TABLE system_settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
			`CREATE TABLE config_versions (
			id INTEGER PRIMARY KEY,
			config BLOB NOT NULL,
			healthy INTEGER NOT NULL,
			created_at INTEGER NOT NULL
		)`,
			`CREATE INDEX sessions_expires_idx ON sessions(expires_at)`,
			`CREATE INDEX clients_node_idx ON node_clients(node_id)`,
		},
		{
			`CREATE TABLE system_events (
				id INTEGER PRIMARY KEY,
				level TEXT NOT NULL,
				code TEXT NOT NULL,
				message TEXT NOT NULL,
				created_at INTEGER NOT NULL
			)`,
			`CREATE INDEX events_created_idx ON system_events(created_at DESC)`,
		},
		{
			`CREATE TABLE managed_firewall_rules (
				protocol TEXT NOT NULL CHECK(protocol IN ('tcp', 'udp')),
				port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
				created_at INTEGER NOT NULL,
				PRIMARY KEY(protocol, port)
			)`,
		},
		{
			`ALTER TABLE managed_firewall_rules
			 ADD COLUMN ownership TEXT NOT NULL DEFAULT 'pending'
			 CHECK(ownership IN ('pending', 'owned', 'borrowed'))`,
		},
		{
			`ALTER TABLE managed_firewall_rules
			 ADD COLUMN backend TEXT NOT NULL DEFAULT 'unknown'
			 CHECK(backend IN ('unknown', 'firewalld', 'ufw', 'nftables'))`,
		},
		{
			`PRAGMA secure_delete = ON`,
			`DELETE FROM config_versions`,
		},
		{
			`CREATE TABLE IF NOT EXISTS outbounds (
				id INTEGER PRIMARY KEY,
				name TEXT NOT NULL,
				type TEXT NOT NULL CHECK(type IN ('socks5', 'http')),
				server TEXT NOT NULL,
				port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
				enabled INTEGER NOT NULL DEFAULT 1,
				credential_enc TEXT NOT NULL,
				status TEXT NOT NULL DEFAULT 'unchecked',
				observed_ip TEXT NOT NULL DEFAULT '',
				country TEXT NOT NULL DEFAULT '',
				asn TEXT NOT NULL DEFAULT '',
				last_error TEXT NOT NULL DEFAULT '',
				last_checked_at INTEGER,
				created_at INTEGER NOT NULL,
				updated_at INTEGER NOT NULL
			)`,
			`ALTER TABLE nodes ADD COLUMN outbound_id INTEGER REFERENCES outbounds(id) ON DELETE RESTRICT`,
			`CREATE INDEX IF NOT EXISTS nodes_outbound_idx ON nodes(outbound_id)`,
		},
		{
			`ALTER TABLE outbounds ADD COLUMN managed_kind TEXT NOT NULL DEFAULT 'manual'
			 CHECK(managed_kind IN ('manual', 'vpngate'))`,
			`CREATE TABLE IF NOT EXISTS vpngate_candidates (
				host_name TEXT PRIMARY KEY,
				ip TEXT NOT NULL,
				score INTEGER NOT NULL,
				ping INTEGER NOT NULL,
				speed INTEGER NOT NULL,
				country_long TEXT NOT NULL,
				country_short TEXT NOT NULL,
				num_sessions INTEGER NOT NULL,
				uptime INTEGER NOT NULL,
				config_enc TEXT NOT NULL,
				fetched_at INTEGER NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS vpngate_country_idx ON vpngate_candidates(country_short, score DESC)`,
			`CREATE TABLE IF NOT EXISTS vpngate_exits (
				id INTEGER PRIMARY KEY,
				outbound_id INTEGER NOT NULL UNIQUE REFERENCES outbounds(id) ON DELETE CASCADE,
				slot INTEGER NOT NULL UNIQUE CHECK(slot BETWEEN 1 AND 5),
				name TEXT NOT NULL,
				country TEXT NOT NULL,
				candidate_host_name TEXT NOT NULL DEFAULT '',
				candidate_ip TEXT NOT NULL DEFAULT '',
				remote_protocol TEXT NOT NULL DEFAULT '',
				remote_port INTEGER NOT NULL DEFAULT 0,
				namespace TEXT NOT NULL,
				local_address TEXT NOT NULL,
				local_port INTEGER NOT NULL,
				status TEXT NOT NULL,
				observed_ip TEXT NOT NULL DEFAULT '',
				last_error TEXT NOT NULL DEFAULT '',
				failure_policy TEXT NOT NULL DEFAULT 'block'
				 CHECK(failure_policy IN ('block', 'auto_swap')),
				permanent INTEGER NOT NULL DEFAULT 0,
				expires_at INTEGER,
				last_checked_at INTEGER,
				created_at INTEGER NOT NULL,
				updated_at INTEGER NOT NULL
			)`,
		},
		{
			`INSERT INTO system_events(level, code, message, created_at)
			 SELECT 'info', 'deprecated_protocol_removed',
			        'H2+Reality 协议已移除，现有节点已自动删除', CAST(strftime('%s', 'now') AS INTEGER)
			 WHERE EXISTS (SELECT 1 FROM nodes WHERE protocol = 'vless_h2_reality')`,
			`DELETE FROM nodes WHERE protocol = 'vless_h2_reality'`,
		},
	}

	var current int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&current); err != nil {
		return fmt.Errorf("read database schema version: %w", err)
	}
	if current > len(migrations) {
		return fmt.Errorf("database schema version %d is newer than supported version %d", current, len(migrations))
	}
	for index := current; index < len(migrations); index++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin database migration %d: %w", index+1, err)
		}
		for _, statement := range migrations[index] {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				if (index == 6 && strings.Contains(statement, "ADD COLUMN outbound_id") ||
					index == 7 && strings.Contains(statement, "ADD COLUMN managed_kind")) &&
					strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
					continue
				}
				_ = tx.Rollback()
				return fmt.Errorf("apply database migration %d: %w", index+1, err)
			}
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, index+1)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record database migration %d: %w", index+1, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit database migration %d: %w", index+1, err)
		}
	}
	return nil
}

func (s *Store) Bootstrap(ctx context.Context, bootstrap Bootstrap) (bool, error) {
	if bootstrap.NodeStartPort < 1 || bootstrap.NodeStartPort > 65535 {
		bootstrap.NodeStartPort = 8881
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM administrators`).Scan(&count); err != nil {
		return false, err
	}
	if count != 0 {
		return false, nil
	}

	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO administrators(id, username, password_hash, created_at, updated_at)
		 VALUES(1, 'admin', ?, ?, ?)`,
		bootstrap.AdminPasswordHash, now, now,
	); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO users(id, name, subscription_token_hash, subscription_token_enc, created_at)
		 VALUES(1, 'default', ?, ?, ?)`,
		bootstrap.TokenHash, bootstrap.TokenEncrypted, now,
	); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO system_settings(key, value, updated_at) VALUES('admin_path', ?, ?)`,
		bootstrap.AdminPath, now,
	); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO system_settings(key, value, updated_at) VALUES('node_start_port', ?, ?)`,
		strconv.Itoa(bootstrap.NodeStartPort), now,
	); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) PasswordHash(ctx context.Context, username string) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx,
		`SELECT password_hash FROM administrators WHERE username = ?`,
		username,
	).Scan(&hash)
	return hash, err
}

func (s *Store) AdministratorUsername(ctx context.Context) (string, error) {
	var username string
	err := s.db.QueryRowContext(ctx,
		`SELECT username FROM administrators WHERE id = 1`,
	).Scan(&username)
	return username, err
}

func (s *Store) ChangePassword(ctx context.Context, hash string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`UPDATE administrators SET password_hash = ?, updated_at = ? WHERE id = 1`,
		hash, time.Now().Unix(),
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions`); err != nil {
		return err
	}
	return tx.Commit()
}

// ChangeAdministrator atomically replaces the single administrator identity
// and invalidates every existing session, so the previous credentials stop
// working immediately.
func (s *Store) ChangeAdministrator(ctx context.Context, username, hash string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx,
		`UPDATE administrators SET username = ?, password_hash = ?, updated_at = ? WHERE id = 1`,
		username, hash, time.Now().Unix(),
	)
	if err != nil {
		return normalizeWriteError(err)
	}
	if affected, affectedErr := result.RowsAffected(); affectedErr != nil || affected != 1 {
		if affectedErr != nil {
			return affectedErr
		}
		return errors.New("administrator account does not exist")
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions`); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CreateSession(ctx context.Context, session model.Session, sourceIP string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, time.Now().Unix()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO sessions(token_hash, csrf_token, source_ip, expires_at, created_at)
		 VALUES(?, ?, ?, ?, ?)`,
		session.TokenHash, session.CSRFToken, sourceIP, session.ExpiresAt.Unix(), time.Now().Unix(),
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Session(ctx context.Context, tokenHash string) (model.Session, error) {
	var session model.Session
	var expiresAt int64
	err := s.db.QueryRowContext(ctx,
		`SELECT token_hash, csrf_token, expires_at FROM sessions
		 WHERE token_hash = ? AND expires_at > ?`,
		tokenHash, time.Now().Unix(),
	).Scan(&session.TokenHash, &session.CSRFToken, &expiresAt)
	session.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	return session, err
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx,
		`SELECT value FROM system_settings WHERE key = ?`,
		key,
	).Scan(&value)
	return value, err
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO system_settings(key, value, updated_at) VALUES(?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, time.Now().Unix(),
	)
	return err
}

// SetNodePortsAndStart updates the complete managed port range atomically.
// Temporary negative ports avoid transient UNIQUE(listen, port) collisions
// while existing nodes exchange positions inside the same transaction.
func (s *Store) SetNodePortsAndStart(ctx context.Context, startPort int, nodes []model.Node) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	for _, node := range nodes {
		if _, err := tx.ExecContext(ctx,
			`UPDATE nodes SET port = ?, updated_at = ? WHERE id = ?`, -node.ID, now, node.ID,
		); err != nil {
			return normalizeWriteError(err)
		}
	}
	for _, node := range nodes {
		result, err := tx.ExecContext(ctx,
			`UPDATE nodes SET name = ?, port = ?, status = ?, updated_at = ? WHERE id = ?`,
			node.Name, node.Port, node.Status, now, node.ID,
		)
		if err != nil {
			return normalizeWriteError(err)
		}
		affected, _ := result.RowsAffected()
		if affected == 0 {
			return sql.ErrNoRows
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO system_settings(key, value, updated_at) VALUES('node_start_port', ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		strconv.Itoa(startPort), now,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DefaultUser(ctx context.Context) (model.User, error) {
	var user model.User
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, subscription_token_hash, subscription_token_enc FROM users WHERE id = 1`,
	).Scan(&user.ID, &user.Name, &user.SubscriptionTokenHash, &user.SubscriptionTokenEnc)
	return user, err
}

func (s *Store) UserByTokenHash(ctx context.Context, hash string) (model.User, error) {
	var user model.User
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, subscription_token_hash, subscription_token_enc
		 FROM users WHERE subscription_token_hash = ? AND enabled = 1`,
		hash,
	).Scan(&user.ID, &user.Name, &user.SubscriptionTokenHash, &user.SubscriptionTokenEnc)
	return user, err
}

func (s *Store) ResetSubscriptionToken(ctx context.Context, hash, encrypted string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET subscription_token_hash = ?, subscription_token_enc = ? WHERE id = 1`,
		hash, encrypted,
	)
	return err
}

func (s *Store) SubscriptionToken(ctx context.Context) (string, error) {
	user, err := s.DefaultUser(ctx)
	if err != nil {
		return "", err
	}
	plain, err := s.sealer.Open(user.SubscriptionTokenEnc)
	return string(plain), err
}

func (s *Store) ListOutbounds(ctx context.Context) ([]model.Outbound, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, type, server, port, enabled, credential_enc, managed_kind, status,
		        observed_ip, country, asn, last_error, last_checked_at, created_at, updated_at
		 FROM outbounds ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	outbounds := make([]model.Outbound, 0)
	for rows.Next() {
		outbound, err := s.scanOutbound(rows)
		if err != nil {
			return nil, err
		}
		outbounds = append(outbounds, outbound)
	}
	return outbounds, rows.Err()
}

func (s *Store) Outbound(ctx context.Context, id int64) (model.Outbound, error) {
	return s.scanOutbound(s.db.QueryRowContext(ctx,
		`SELECT id, name, type, server, port, enabled, credential_enc, managed_kind, status,
		        observed_ip, country, asn, last_error, last_checked_at, created_at, updated_at
		 FROM outbounds WHERE id = ?`, id,
	))
}

func (s *Store) scanOutbound(row scanner) (model.Outbound, error) {
	var outbound model.Outbound
	var enabled int
	var encrypted string
	var checkedAt sql.NullInt64
	var createdAt, updatedAt int64
	if err := row.Scan(
		&outbound.ID, &outbound.Name, &outbound.Type, &outbound.Server, &outbound.Port,
		&enabled, &encrypted, &outbound.ManagedKind, &outbound.Status, &outbound.ObservedIP, &outbound.Country,
		&outbound.ASN, &outbound.LastError, &checkedAt, &createdAt, &updatedAt,
	); err != nil {
		return outbound, err
	}
	plain, err := s.sealer.Open(encrypted)
	if err != nil {
		return outbound, err
	}
	var credential struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(plain, &credential); err != nil {
		return outbound, err
	}
	outbound.Enabled = enabled == 1
	outbound.Username = credential.Username
	outbound.Password = credential.Password
	outbound.HasCredential = credential.Username != "" || credential.Password != ""
	if outbound.ManagedKind == "" {
		outbound.ManagedKind = "manual"
	}
	outbound.CreatedAt = time.Unix(createdAt, 0).UTC()
	outbound.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	if checkedAt.Valid {
		value := time.Unix(checkedAt.Int64, 0).UTC()
		outbound.LastCheckedAt = &value
	}
	return outbound, nil
}

func (s *Store) CreateOutbound(ctx context.Context, outbound model.Outbound) (model.Outbound, error) {
	encrypted, err := s.encryptJSON(map[string]string{
		"username": outbound.Username,
		"password": outbound.Password,
	})
	if err != nil {
		return outbound, err
	}
	now := time.Now().Unix()
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO outbounds(name, type, server, port, enabled, credential_enc, managed_kind, status,
		 observed_ip, country, asn, last_error, last_checked_at, created_at, updated_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, '', '', '', '', NULL, ?, ?)`,
		outbound.Name, outbound.Type, outbound.Server, outbound.Port, boolInt(outbound.Enabled),
		encrypted, defaultManagedKind(outbound.ManagedKind), outbound.Status, now, now,
	)
	if err != nil {
		return outbound, normalizeWriteError(err)
	}
	outbound.ID, err = result.LastInsertId()
	if err != nil {
		return outbound, err
	}
	return s.Outbound(ctx, outbound.ID)
}

func (s *Store) UpdateOutbound(ctx context.Context, outbound model.Outbound) error {
	encrypted, err := s.encryptJSON(map[string]string{
		"username": outbound.Username,
		"password": outbound.Password,
	})
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx,
		`UPDATE outbounds SET name = ?, type = ?, server = ?, port = ?, enabled = ?,
		 credential_enc = ?, managed_kind = ?, status = ?, observed_ip = ?, country = ?, asn = ?,
		 last_error = ?, last_checked_at = ?, updated_at = ? WHERE id = ?`,
		outbound.Name, outbound.Type, outbound.Server, outbound.Port, boolInt(outbound.Enabled),
		encrypted, defaultManagedKind(outbound.ManagedKind), outbound.Status, outbound.ObservedIP, outbound.Country, outbound.ASN,
		outbound.LastError, nullableTime(outbound.LastCheckedAt), time.Now().Unix(), outbound.ID,
	)
	if err != nil {
		return normalizeWriteError(err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) DeleteOutbound(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM outbounds WHERE id = ?`, id)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "foreign key constraint") {
			return fmt.Errorf("%w: outbound is in use", ErrConflict)
		}
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) RestoreOutbound(ctx context.Context, outbound model.Outbound) error {
	encrypted, err := s.encryptJSON(map[string]string{
		"username": outbound.Username,
		"password": outbound.Password,
	})
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO outbounds(id, name, type, server, port, enabled, credential_enc, managed_kind, status,
		 observed_ip, country, asn, last_error, last_checked_at, created_at, updated_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		outbound.ID, outbound.Name, outbound.Type, outbound.Server, outbound.Port,
		boolInt(outbound.Enabled), encrypted, defaultManagedKind(outbound.ManagedKind), outbound.Status, outbound.ObservedIP,
		outbound.Country, outbound.ASN, outbound.LastError, nullableTime(outbound.LastCheckedAt),
		outbound.CreatedAt.Unix(), outbound.UpdatedAt.Unix(),
	)
	return normalizeWriteError(err)
}

func (s *Store) ReplaceVPNGateCandidates(ctx context.Context, candidates []model.VPNGateCandidate) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM vpngate_candidates`); err != nil {
		return err
	}
	for _, candidate := range candidates {
		encrypted, err := s.sealer.Seal([]byte(candidate.OpenVPNConfig))
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO vpngate_candidates(
			 host_name, ip, score, ping, speed, country_long, country_short,
			 num_sessions, uptime, config_enc, fetched_at)
			 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			candidate.HostName, candidate.IP, candidate.Score, candidate.Ping, candidate.Speed,
			candidate.CountryLong, candidate.CountryShort, candidate.NumSessions, candidate.Uptime,
			encrypted, candidate.FetchedAt.Unix(),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListVPNGateCandidates(ctx context.Context) ([]model.VPNGateCandidate, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT host_name, ip, score, ping, speed, country_long, country_short,
		        num_sessions, uptime, config_enc, fetched_at
		 FROM vpngate_candidates ORDER BY score DESC, speed DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var candidates []model.VPNGateCandidate
	for rows.Next() {
		candidate, err := s.scanVPNGateCandidate(rows)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, candidate)
	}
	if candidates == nil {
		candidates = make([]model.VPNGateCandidate, 0)
	}
	return candidates, rows.Err()
}

func (s *Store) VPNGateCandidate(ctx context.Context, hostName string) (model.VPNGateCandidate, error) {
	return s.scanVPNGateCandidate(s.db.QueryRowContext(ctx,
		`SELECT host_name, ip, score, ping, speed, country_long, country_short,
		        num_sessions, uptime, config_enc, fetched_at
		 FROM vpngate_candidates WHERE host_name = ?`, hostName,
	))
}

func (s *Store) scanVPNGateCandidate(row scanner) (model.VPNGateCandidate, error) {
	var candidate model.VPNGateCandidate
	var encrypted string
	var fetchedAt int64
	if err := row.Scan(
		&candidate.HostName, &candidate.IP, &candidate.Score, &candidate.Ping, &candidate.Speed,
		&candidate.CountryLong, &candidate.CountryShort, &candidate.NumSessions,
		&candidate.Uptime, &encrypted, &fetchedAt,
	); err != nil {
		return candidate, err
	}
	plain, err := s.sealer.Open(encrypted)
	if err != nil {
		return candidate, err
	}
	candidate.OpenVPNConfig = string(plain)
	candidate.HasOpenVPN = candidate.OpenVPNConfig != ""
	candidate.FetchedAt = time.Unix(fetchedAt, 0).UTC()
	return candidate, nil
}

func (s *Store) CreateVPNGateExit(
	ctx context.Context, outbound model.Outbound, exit model.VPNGateExit,
) (model.VPNGateExit, error) {
	encrypted, err := s.encryptJSON(map[string]string{
		"username": outbound.Username,
		"password": outbound.Password,
	})
	if err != nil {
		return exit, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return exit, err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	result, err := tx.ExecContext(ctx,
		`INSERT INTO outbounds(name, type, server, port, enabled, credential_enc,
		 managed_kind, status, observed_ip, country, asn, last_error,
		 last_checked_at, created_at, updated_at)
		 VALUES(?, 'socks5', ?, ?, 1, ?, 'vpngate', 'unchecked', '', ?, '', '', NULL, ?, ?)`,
		outbound.Name, outbound.Server, outbound.Port, encrypted, outbound.Country, now, now,
	)
	if err != nil {
		return exit, normalizeWriteError(err)
	}
	exit.OutboundID, err = result.LastInsertId()
	if err != nil {
		return exit, err
	}
	result, err = tx.ExecContext(ctx,
		`INSERT INTO vpngate_exits(
		 outbound_id, slot, name, country, candidate_host_name, candidate_ip,
		 remote_protocol, remote_port, namespace, local_address, local_port,
		 status, observed_ip, last_error, failure_policy, permanent, expires_at,
		 last_checked_at, created_at, updated_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		exit.OutboundID, exit.Slot, exit.Name, exit.Country, exit.CandidateHostName,
		exit.CandidateIP, exit.RemoteProtocol, exit.RemotePort, exit.Namespace,
		exit.LocalAddress, exit.LocalPort, exit.Status, exit.ObservedIP, exit.LastError,
		exit.FailurePolicy, boolInt(exit.Permanent), nullableTime(exit.ExpiresAt),
		nullableTime(exit.LastCheckedAt), now, now,
	)
	if err != nil {
		return exit, normalizeWriteError(err)
	}
	exit.ID, err = result.LastInsertId()
	if err != nil {
		return exit, err
	}
	if err := tx.Commit(); err != nil {
		return exit, err
	}
	return s.VPNGateExit(ctx, exit.ID)
}

func (s *Store) ListVPNGateExits(ctx context.Context) ([]model.VPNGateExit, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, outbound_id, slot, name, country, candidate_host_name, candidate_ip,
		        remote_protocol, remote_port, namespace, local_address, local_port,
		        status, observed_ip, last_error, failure_policy, permanent, expires_at,
		        last_checked_at, created_at, updated_at
		 FROM vpngate_exits ORDER BY slot`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var exits []model.VPNGateExit
	for rows.Next() {
		exit, err := scanVPNGateExit(rows)
		if err != nil {
			return nil, err
		}
		exits = append(exits, exit)
	}
	if exits == nil {
		exits = make([]model.VPNGateExit, 0)
	}
	return exits, rows.Err()
}

func (s *Store) VPNGateExit(ctx context.Context, id int64) (model.VPNGateExit, error) {
	return scanVPNGateExit(s.db.QueryRowContext(ctx,
		`SELECT id, outbound_id, slot, name, country, candidate_host_name, candidate_ip,
		        remote_protocol, remote_port, namespace, local_address, local_port,
		        status, observed_ip, last_error, failure_policy, permanent, expires_at,
		        last_checked_at, created_at, updated_at
		 FROM vpngate_exits WHERE id = ?`, id,
	))
}

func scanVPNGateExit(row scanner) (model.VPNGateExit, error) {
	var exit model.VPNGateExit
	var permanent int
	var expiresAt, checkedAt sql.NullInt64
	var createdAt, updatedAt int64
	if err := row.Scan(
		&exit.ID, &exit.OutboundID, &exit.Slot, &exit.Name, &exit.Country,
		&exit.CandidateHostName, &exit.CandidateIP, &exit.RemoteProtocol, &exit.RemotePort,
		&exit.Namespace, &exit.LocalAddress, &exit.LocalPort, &exit.Status,
		&exit.ObservedIP, &exit.LastError, &exit.FailurePolicy, &permanent,
		&expiresAt, &checkedAt, &createdAt, &updatedAt,
	); err != nil {
		return exit, err
	}
	exit.Permanent = permanent == 1
	exit.CreatedAt = time.Unix(createdAt, 0).UTC()
	exit.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	if expiresAt.Valid {
		value := time.Unix(expiresAt.Int64, 0).UTC()
		exit.ExpiresAt = &value
	}
	if checkedAt.Valid {
		value := time.Unix(checkedAt.Int64, 0).UTC()
		exit.LastCheckedAt = &value
	}
	return exit, nil
}

func (s *Store) UpdateVPNGateExit(ctx context.Context, exit model.VPNGateExit) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE vpngate_exits SET name = ?, country = ?, candidate_host_name = ?,
		 candidate_ip = ?, remote_protocol = ?, remote_port = ?, status = ?,
		 observed_ip = ?, last_error = ?, failure_policy = ?, permanent = ?,
		 expires_at = ?, last_checked_at = ?, updated_at = ? WHERE id = ?`,
		exit.Name, exit.Country, exit.CandidateHostName, exit.CandidateIP,
		exit.RemoteProtocol, exit.RemotePort, exit.Status, exit.ObservedIP,
		exit.LastError, exit.FailurePolicy, boolInt(exit.Permanent),
		nullableTime(exit.ExpiresAt), nullableTime(exit.LastCheckedAt),
		time.Now().Unix(), exit.ID,
	)
	if err != nil {
		return normalizeWriteError(err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) UpdateVPNGateExitAndHealth(
	ctx context.Context, exit model.VPNGateExit, healthy bool,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	result, err := tx.ExecContext(ctx,
		`UPDATE vpngate_exits SET name = ?, country = ?, candidate_host_name = ?,
		 candidate_ip = ?, remote_protocol = ?, remote_port = ?, status = ?,
		 observed_ip = ?, last_error = ?, failure_policy = ?, permanent = ?,
		 expires_at = ?, last_checked_at = ?, updated_at = ? WHERE id = ?`,
		exit.Name, exit.Country, exit.CandidateHostName, exit.CandidateIP,
		exit.RemoteProtocol, exit.RemotePort, exit.Status, exit.ObservedIP,
		exit.LastError, exit.FailurePolicy, boolInt(exit.Permanent),
		nullableTime(exit.ExpiresAt), nullableTime(exit.LastCheckedAt), now, exit.ID,
	)
	if err != nil {
		return normalizeWriteError(err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	status, observedIP, lastError := "healthy", exit.ObservedIP, ""
	if !healthy {
		status, observedIP, lastError = "unhealthy", "", exit.LastError
	}
	result, err = tx.ExecContext(ctx,
		`UPDATE outbounds SET status = ?, observed_ip = ?, country = ?,
		 last_error = ?, last_checked_at = ?, updated_at = ? WHERE id = ?`,
		status, observedIP, exit.Country, lastError,
		nullableTime(exit.LastCheckedAt), now, exit.OutboundID,
	)
	if err != nil {
		return normalizeWriteError(err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}

func (s *Store) DeleteVPNGateExit(ctx context.Context, id int64) error {
	exit, err := s.VPNGateExit(ctx, id)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM outbounds WHERE id = ?`, exit.OutboundID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "foreign key constraint") {
			return fmt.Errorf("%w: VPNGate outbound is in use", ErrConflict)
		}
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) ListNodes(ctx context.Context) ([]model.Node, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, protocol, listen, port, enabled, public_host_override,
		        settings_json, secret_enc, status, created_at, updated_at, outbound_id
		 FROM nodes ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	nodes := make([]model.Node, 0)
	for rows.Next() {
		node, err := s.scanNode(rows)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	return nodes, rows.Err()
}

func (s *Store) Node(ctx context.Context, id int64) (model.Node, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, protocol, listen, port, enabled, public_host_override,
		        settings_json, secret_enc, status, created_at, updated_at, outbound_id
		 FROM nodes WHERE id = ?`,
		id,
	)
	return s.scanNode(row)
}

type scanner interface {
	Scan(dest ...any) error
}

func (s *Store) scanNode(row scanner) (model.Node, error) {
	var node model.Node
	var enabled int
	var settingsJSON, secretEncrypted string
	var createdAt, updatedAt int64
	var outboundID sql.NullInt64
	if err := row.Scan(
		&node.ID, &node.Name, &node.Protocol, &node.Listen, &node.Port, &enabled,
		&node.PublicHostOverride, &settingsJSON, &secretEncrypted, &node.Status,
		&createdAt, &updatedAt, &outboundID,
	); err != nil {
		return node, err
	}
	node.Enabled = enabled == 1
	node.CreatedAt = time.Unix(createdAt, 0).UTC()
	node.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	if outboundID.Valid {
		node.OutboundID = &outboundID.Int64
	}
	if err := json.Unmarshal([]byte(settingsJSON), &node.Settings); err != nil {
		return node, err
	}
	secretJSON, err := s.sealer.Open(secretEncrypted)
	if err != nil {
		return node, err
	}
	if err := json.Unmarshal(secretJSON, &node.Secret); err != nil {
		return node, err
	}
	return node, nil
}

func (s *Store) CreateNode(ctx context.Context, node model.Node, client model.Client) (model.Node, error) {
	settingsJSON, secretEncrypted, err := s.encodeNode(node)
	if err != nil {
		return node, err
	}
	credentialEncrypted, err := s.encryptJSON(client.Credential)
	if err != nil {
		return node, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return node, err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	result, err := tx.ExecContext(ctx,
		`INSERT INTO nodes(name, protocol, listen, port, enabled, public_host_override,
		 settings_json, secret_enc, status, created_at, updated_at, outbound_id)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		node.Name, node.Protocol, node.Listen, node.Port, boolInt(node.Enabled),
		node.PublicHostOverride, settingsJSON, secretEncrypted, node.Status, now, now, node.OutboundID,
	)
	if err != nil {
		return node, normalizeWriteError(err)
	}
	node.ID, err = result.LastInsertId()
	if err != nil {
		return node, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO node_clients(node_id, user_id, name, credential_enc, enabled, created_at)
		 VALUES(?, 1, ?, ?, 1, ?)`,
		node.ID, client.Name, credentialEncrypted, now,
	); err != nil {
		return node, normalizeWriteError(err)
	}
	if err := tx.Commit(); err != nil {
		return node, err
	}
	node.CreatedAt = time.Unix(now, 0).UTC()
	node.UpdatedAt = node.CreatedAt
	return node, nil
}

func (s *Store) UpdateNode(ctx context.Context, node model.Node) error {
	settingsJSON, secretEncrypted, err := s.encodeNode(node)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx,
		`UPDATE nodes SET name = ?, listen = ?, port = ?, enabled = ?,
		 public_host_override = ?, settings_json = ?, secret_enc = ?, status = ?, updated_at = ?,
		 outbound_id = ?
		 WHERE id = ?`,
		node.Name, node.Listen, node.Port, boolInt(node.Enabled), node.PublicHostOverride,
		settingsJSON, secretEncrypted, node.Status, time.Now().Unix(), node.OutboundID, node.ID,
	)
	if err != nil {
		return normalizeWriteError(err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) DeleteNode(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM nodes WHERE id = ?`, id)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) RestoreNode(ctx context.Context, node model.Node, clients []model.Client) error {
	settingsJSON, secretEncrypted, err := s.encodeNode(node)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO nodes(id, name, protocol, listen, port, enabled, public_host_override,
		 settings_json, secret_enc, status, created_at, updated_at, outbound_id)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		node.ID, node.Name, node.Protocol, node.Listen, node.Port, boolInt(node.Enabled),
		node.PublicHostOverride, settingsJSON, secretEncrypted, node.Status,
		node.CreatedAt.Unix(), node.UpdatedAt.Unix(), node.OutboundID,
	); err != nil {
		return err
	}
	for _, client := range clients {
		encrypted, err := s.encryptJSON(client.Credential)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO node_clients(id, node_id, user_id, name, credential_enc, enabled, created_at)
			 VALUES(?, ?, ?, ?, ?, ?, ?)`,
			client.ID, node.ID, client.UserID, client.Name, encrypted,
			boolInt(client.Enabled), client.CreatedAt.Unix(),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Clients(ctx context.Context, nodeID int64) ([]model.Client, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, node_id, user_id, name, credential_enc, enabled, created_at
		 FROM node_clients WHERE node_id = ? ORDER BY id`,
		nodeID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	clients := make([]model.Client, 0)
	for rows.Next() {
		var client model.Client
		var encrypted string
		var enabled int
		var createdAt int64
		if err := rows.Scan(
			&client.ID, &client.NodeID, &client.UserID, &client.Name,
			&encrypted, &enabled, &createdAt,
		); err != nil {
			return nil, err
		}
		plain, err := s.sealer.Open(encrypted)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(plain, &client.Credential); err != nil {
			return nil, err
		}
		client.Enabled = enabled == 1
		client.CreatedAt = time.Unix(createdAt, 0).UTC()
		clients = append(clients, client)
	}
	return clients, rows.Err()
}

func (s *Store) CreateClient(ctx context.Context, client model.Client) (model.Client, error) {
	encrypted, err := s.encryptJSON(client.Credential)
	if err != nil {
		return client, err
	}
	now := time.Now().Unix()
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO node_clients(node_id, user_id, name, credential_enc, enabled, created_at)
		 VALUES(?, 1, ?, ?, 1, ?)`,
		client.NodeID, client.Name, encrypted, now,
	)
	if err != nil {
		return client, err
	}
	client.ID, err = result.LastInsertId()
	client.CreatedAt = time.Unix(now, 0).UTC()
	return client, err
}

func (s *Store) RestoreClient(ctx context.Context, client model.Client) error {
	encrypted, err := s.encryptJSON(client.Credential)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO node_clients(id, node_id, user_id, name, credential_enc, enabled, created_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?)`,
		client.ID, client.NodeID, client.UserID, client.Name, encrypted,
		boolInt(client.Enabled), client.CreatedAt.Unix(),
	)
	return err
}

func (s *Store) UpdateClient(ctx context.Context, client model.Client) error {
	encrypted, err := s.encryptJSON(client.Credential)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx,
		`UPDATE node_clients SET name = ?, credential_enc = ?, enabled = ? WHERE id = ? AND node_id = ?`,
		client.Name, encrypted, boolInt(client.Enabled), client.ID, client.NodeID,
	)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) DeleteClient(ctx context.Context, nodeID, clientID int64) error {
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM node_clients WHERE id = ? AND node_id = ?`,
		clientID, nodeID,
	)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) SaveConfigVersion(ctx context.Context, config []byte, healthy bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var latestEncrypted string
	var latestHealthy int
	err = tx.QueryRowContext(ctx,
		`SELECT config, healthy FROM config_versions ORDER BY id DESC LIMIT 1`,
	).Scan(&latestEncrypted, &latestHealthy)
	if err == nil {
		latest, openErr := s.sealer.Open(latestEncrypted)
		if openErr != nil {
			return fmt.Errorf("decrypt latest configuration version: %w", openErr)
		}
		if bytes.Equal(latest, config) && latestHealthy == boolInt(healthy) {
			return nil
		}
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	encrypted, err := s.sealer.Seal(config)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO config_versions(config, healthy, created_at) VALUES(?, ?, ?)`,
		encrypted, boolInt(healthy), time.Now().Unix(),
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM config_versions WHERE id NOT IN
		 (SELECT id FROM config_versions ORDER BY id DESC LIMIT 10)`,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) LatestConfigVersion(ctx context.Context) (int64, error) {
	var version int64
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM config_versions`).Scan(&version)
	return version, err
}

func (s *Store) ManagedFirewallRules(ctx context.Context) ([]ManagedFirewallRule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT protocol, port, ownership, backend FROM managed_firewall_rules ORDER BY protocol, port`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rules := make([]ManagedFirewallRule, 0)
	for rows.Next() {
		var rule ManagedFirewallRule
		if err := rows.Scan(&rule.Protocol, &rule.Port, &rule.Ownership, &rule.Backend); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

func (s *Store) SetFirewallRuleOwnership(
	ctx context.Context, protocol string, port int, ownership, backend string,
) error {
	if ownership != FirewallOwned && ownership != FirewallBorrowed {
		return fmt.Errorf("invalid firewall ownership %q", ownership)
	}
	if backend != FirewallFirewalld && backend != FirewallUFW && backend != FirewallNFTables {
		return fmt.Errorf("invalid firewall backend %q", backend)
	}
	result, err := s.db.ExecContext(ctx,
		`UPDATE managed_firewall_rules SET ownership = ?, backend = ? WHERE protocol = ? AND port = ?`,
		ownership, backend, protocol, port)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errors.New("managed firewall rule disappeared while recording ownership")
	}
	return nil
}

func (s *Store) TrackFirewallRule(ctx context.Context, protocol string, port int) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO managed_firewall_rules(protocol, port, created_at) VALUES(?, ?, ?)
		 ON CONFLICT(protocol, port) DO NOTHING`,
		protocol, port, time.Now().Unix())
	return err
}

func (s *Store) ForgetFirewallRule(ctx context.Context, protocol string, port int) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM managed_firewall_rules WHERE protocol = ? AND port = ?`,
		protocol, port)
	return err
}

func (s *Store) MergeFirewallRecoveryRules(ctx context.Context, rules []ManagedFirewallRule) error {
	if len(rules) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, rule := range rules {
		if rule.Protocol != "tcp" && rule.Protocol != "udp" {
			return fmt.Errorf("invalid recovery firewall protocol %q", rule.Protocol)
		}
		if rule.Port < 1 || rule.Port > 65535 {
			return fmt.Errorf("invalid recovery firewall port %d", rule.Port)
		}
		if rule.Ownership != FirewallPending && rule.Ownership != FirewallOwned {
			continue
		}
		if rule.Backend != FirewallUnknown && rule.Backend != FirewallFirewalld &&
			rule.Backend != FirewallUFW && rule.Backend != FirewallNFTables {
			return fmt.Errorf("invalid recovery firewall backend %q", rule.Backend)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO managed_firewall_rules(protocol, port, ownership, backend, created_at)
			VALUES(?, ?, ?, ?, ?)
			ON CONFLICT(protocol, port) DO UPDATE SET
				ownership = CASE
					WHEN managed_firewall_rules.ownership = 'borrowed' THEN 'borrowed'
					ELSE excluded.ownership
				END,
				backend = CASE
					WHEN managed_firewall_rules.ownership = 'borrowed'
						THEN managed_firewall_rules.backend
					ELSE excluded.backend
				END`,
			rule.Protocol, rule.Port, rule.Ownership, rule.Backend, time.Now().Unix(),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) RecordEvent(ctx context.Context, level, code, message string) error {
	if level != "info" && level != "warning" && level != "error" {
		return fmt.Errorf("unsupported event level %q", level)
	}
	if code == "" || message == "" {
		return errors.New("event code and message are required")
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO system_events(level, code, message, created_at) VALUES(?, ?, ?, ?)`,
		level, code, message, time.Now().Unix(),
	); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM system_events WHERE id NOT IN
		 (SELECT id FROM system_events ORDER BY id DESC LIMIT 200)`,
	)
	return err
}

func (s *Store) RecentEvents(ctx context.Context, limit int) ([]model.SystemEvent, error) {
	if limit < 1 || limit > 100 {
		limit = 10
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, level, code, message, created_at
		 FROM system_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]model.SystemEvent, 0)
	for rows.Next() {
		var event model.SystemEvent
		var createdAt int64
		if err := rows.Scan(&event.ID, &event.Level, &event.Code, &event.Message, &createdAt); err != nil {
			return nil, err
		}
		event.CreatedAt = time.Unix(createdAt, 0).UTC()
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) IntegrityCheck(ctx context.Context) error {
	var result string
	if err := s.db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&result); err != nil {
		return err
	}
	if result != "ok" {
		return fmt.Errorf("database integrity check failed: %s", result)
	}
	return nil
}

func (s *Store) Checkpoint(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

func (s *Store) Snapshot(ctx context.Context, destination string) error {
	if !filepath.IsAbs(destination) {
		return errors.New("database snapshot destination must be absolute")
	}
	if _, err := os.Stat(destination); err == nil {
		return errors.New("database snapshot destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, destination); err != nil {
		return fmt.Errorf("create consistent SQLite snapshot: %w", err)
	}
	if err := os.Chmod(destination, 0o600); err != nil {
		_ = os.Remove(destination)
		return err
	}
	return nil
}

func (s *Store) encodeNode(node model.Node) (string, string, error) {
	settingsJSON, err := json.Marshal(node.Settings)
	if err != nil {
		return "", "", err
	}
	secretEncrypted, err := s.encryptJSON(node.Secret)
	return string(settingsJSON), secretEncrypted, err
}

func (s *Store) encryptJSON(value any) (string, error) {
	plain, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return s.sealer.Seal(plain)
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.Unix()
}

func defaultManagedKind(value string) string {
	if value == "" {
		return "manual"
	}
	return value
}

func IsNotFound(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}
