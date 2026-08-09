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
	"strings"
	"testing"
	"time"

	"github.com/Suparluxi/j-ui/internal/model"
	"github.com/Suparluxi/j-ui/internal/secure"
)

func TestBootstrapIsIdempotent(t *testing.T) {
	sealer, err := secure.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "j-ui.db"), sealer)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	token, err := sealer.Seal([]byte("token"))
	if err != nil {
		t.Fatal(err)
	}
	input := Bootstrap{
		AdminPasswordHash: "hash", AdminPath: "manage-test",
		TokenHash: secure.HashToken("token"), TokenEncrypted: token,
	}
	created, err := store.Bootstrap(context.Background(), input)
	if err != nil || !created {
		t.Fatalf("first bootstrap: created=%v err=%v", created, err)
	}
	created, err = store.Bootstrap(context.Background(), input)
	if err != nil || created {
		t.Fatalf("second bootstrap: created=%v err=%v", created, err)
	}
	if err := store.IntegrityCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyCollectionsAreNonNil(t *testing.T) {
	sealer, err := secure.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "j-ui.db"), sealer)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	nodes, err := store.ListNodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if nodes == nil {
		t.Fatal("empty node collection must be an empty slice")
	}

	clients, err := store.Clients(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if clients == nil {
		t.Fatal("empty client collection must be an empty slice")
	}
}

func TestOutboundCredentialsAreEncryptedAndNeverSerialized(t *testing.T) {
	sealer, err := secure.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "j-ui.db"), sealer)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	outbound, err := store.CreateOutbound(context.Background(), model.Outbound{
		Name: "test", Type: model.OutboundSOCKS5, Server: "proxy.example",
		Port: 1080, Enabled: true, Username: "private-user", Password: "private-password",
		Status: "unchecked",
	})
	if err != nil {
		t.Fatal(err)
	}
	var encrypted string
	if err := store.db.QueryRow(`SELECT credential_enc FROM outbounds WHERE id = ?`, outbound.ID).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encrypted, "private-user") || strings.Contains(encrypted, "private-password") {
		t.Fatal("outbound credentials were stored in plaintext")
	}
	encoded, err := json.Marshal(outbound)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("private-user")) || bytes.Contains(encoded, []byte("private-password")) {
		t.Fatal("outbound credentials were serialized")
	}
}

func TestExplicitMigrationsAndEvents(t *testing.T) {
	sealer, err := secure.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "j-ui.db"), sealer)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var version int
	if err := store.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 9 {
		t.Fatalf("schema version = %d, want 9", version)
	}
	if err := store.RecordEvent(context.Background(), "info", "test_event", "测试事件"); err != nil {
		t.Fatal(err)
	}
	events, err := store.RecentEvents(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Code != "test_event" {
		t.Fatalf("events = %#v", events)
	}
}

func TestMigrationNineRemovesDeprecatedH2RealityNodes(t *testing.T) {
	sealer, err := secure.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "j-ui.db")
	store, err := Open(path, sealer)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := store.db.Exec(`INSERT INTO nodes(
		id, name, protocol, listen, port, enabled, public_host_override,
		settings_json, secret_enc, status, created_at, updated_at, outbound_id
	) VALUES(1, 'old H2', 'vless_h2_reality', '0.0.0.0', 8443, 1, '', '{}', 'discarded', 'running', ?, ?, NULL)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`PRAGMA user_version = 8`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(path, sealer)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM nodes WHERE protocol = 'vless_h2_reality'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("deprecated H2 nodes remaining = %d", count)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM system_events WHERE code = 'deprecated_protocol_removed'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("deprecated protocol events = %d, want 1", count)
	}
}

func TestMigrationFromRealVersionSixShape(t *testing.T) {
	sealer, err := secure.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "j-ui.db")
	store, err := Open(path, sealer)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	statements := []string{
		`DROP TABLE vpngate_exits`,
		`DROP TABLE vpngate_candidates`,
		`ALTER TABLE outbounds DROP COLUMN managed_kind`,
		`DROP INDEX nodes_outbound_idx`,
		`ALTER TABLE nodes DROP COLUMN outbound_id`,
		`DROP TABLE outbounds`,
		`PRAGMA user_version = 6`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			t.Fatalf("%s: %v", statement, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(path, sealer)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var version int
	if err := store.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 9 {
		t.Fatalf("migrated schema version = %d, want 9", version)
	}
	if outbounds, err := store.ListOutbounds(context.Background()); err != nil || len(outbounds) != 0 {
		t.Fatalf("migrated outbounds = %#v, err=%v", outbounds, err)
	}
}

func TestSaveConfigVersionRollsBackPruneFailure(t *testing.T) {
	sealer, err := secure.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "j-ui.db"), sealer)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for index := 0; index < 10; index++ {
		if err := store.SaveConfigVersion(context.Background(), []byte(fmt.Sprintf("existing-%d", index)), true); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.db.Exec(`
		CREATE TRIGGER reject_config_prune
		BEFORE DELETE ON config_versions
		BEGIN SELECT RAISE(ABORT, 'injected prune failure'); END
	`); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveConfigVersion(context.Background(), []byte("candidate"), true); err == nil {
		t.Fatal("SaveConfigVersion succeeded despite injected prune failure")
	}
	version, err := store.LatestConfigVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if version != 10 {
		t.Fatalf("config version = %d after rolled-back insert, want 10", version)
	}
}

func TestSaveConfigVersionSkipsUnchangedContent(t *testing.T) {
	sealer, err := secure.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "j-ui.db"), sealer)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.SaveConfigVersion(context.Background(), []byte("same"), true); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveConfigVersion(context.Background(), []byte("same"), true); err != nil {
		t.Fatal(err)
	}
	version, err := store.LatestConfigVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("config version = %d, want 1", version)
	}
}

func TestConfigVersionsNeverStorePlaintextSecrets(t *testing.T) {
	sealer, err := secure.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "j-ui.db")
	store, err := Open(path, sealer)
	if err != nil {
		t.Fatal(err)
	}
	fixedSecret := "fixed-private-key-and-client-password"
	if err := store.SaveConfigVersion(context.Background(), []byte(`{"private_key":"`+fixedSecret+`"}`), true); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Checkpoint(context.Background()); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(fixedSecret)) {
		t.Fatal("configuration history contains a plaintext sensitive value")
	}
}

func TestMigrationClearsLegacyPlaintextConfigHistoryAndWAL(t *testing.T) {
	sealer, err := secure.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "j-ui.db")
	store, err := Open(path, sealer)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	legacySecret := "legacy-checkpointed-private-key"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 5`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO config_versions(config, healthy, created_at) VALUES(?, 1, 1)`,
		`{"private_key":"`+legacySecret+`"}`,
	); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(path, sealer)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, candidate := range []string{path, path + "-wal"} {
		raw, readErr := os.ReadFile(candidate)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			t.Fatal(readErr)
		}
		if bytes.Contains(raw, []byte(legacySecret)) {
			t.Fatalf("%s retains legacy plaintext configuration", candidate)
		}
	}
}

func TestSnapshotIncludesCommittedWALStateAndIsPrivate(t *testing.T) {
	sealer, err := secure.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "j-ui.db"), sealer)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.SetSetting(context.Background(), "public_host", "snapshot.example.com"); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(t.TempDir(), "snapshot.db")
	if err := store.Snapshot(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode = %o, want 600", info.Mode().Perm())
	}
	db, err := sql.Open("sqlite", snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var host string
	if err := db.QueryRow(`SELECT value FROM system_settings WHERE key = 'public_host'`).Scan(&host); err != nil {
		t.Fatal(err)
	}
	if host != "snapshot.example.com" {
		t.Fatalf("snapshot public host = %q", host)
	}
}
