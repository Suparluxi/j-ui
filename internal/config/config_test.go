package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadFromFileUsesAllowlistedSystemdEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j-ui.env")
	content := []byte(`
# deployment settings
JUI_LISTEN_ADDRESS="127.0.0.1:9090"
JUI_TLS_CERTIFICATE_PATH=/etc/j-ui/panel.crt
JUI_TLS_KEY_PATH=/etc/j-ui/panel.key
JUI_DATA_DIR=/srv/j-ui/data
JUI_CONFIG_DIR='/srv/j-ui/config'
JUI_SINGBOX_BINARY=/opt/j-ui/sing-box
JUI_ENGINE_MODE=mock
JUI_VPNGATE_MAX_EXITS=3
JUI_NODE_START_PORT=9001
PATH=/attacker/bin
`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := LoadFromFile(path)
	if cfg.ListenAddress != "127.0.0.1:9090" || cfg.TLSCertificate != "/etc/j-ui/panel.crt" || cfg.TLSPrivateKey != "/etc/j-ui/panel.key" ||
		cfg.DatabasePath != "/srv/j-ui/data/j-ui.db" ||
		cfg.SecretKeyPath != "/srv/j-ui/config/secret.key" ||
		cfg.SingBoxConfig != "/srv/j-ui/config/sing-box.json" ||
		cfg.SingBoxBinary != "/opt/j-ui/sing-box" ||
		!cfg.MockEngine || cfg.VPNGateMaxExits != 3 || cfg.NodeStartPort != 9001 {
		t.Fatalf("loaded config = %#v", cfg)
	}
}

func TestVPNGateMaximumFallsBackForUnsafeValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j-ui.env")
	if err := os.WriteFile(path, []byte("JUI_VPNGATE_MAX_EXITS=99\nJUI_NODE_START_PORT=70000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg := LoadFromFile(path); cfg.VPNGateMaxExits != 5 || cfg.NodeStartPort != 8881 {
		t.Fatalf("unsafe values were not reset: %#v", cfg)
	}
}

func TestProcessEnvironmentOverridesEnvironmentFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j-ui.env")
	if err := os.WriteFile(path, []byte("JUI_DATA_DIR=/from/file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JUI_DATA_DIR", "/from/process")
	cfg := LoadFromFile(path)
	if cfg.DataDir != "/from/process" || cfg.DatabasePath != "/from/process/j-ui.db" {
		t.Fatalf("loaded config = %#v", cfg)
	}
}

func TestReloadFromFileIgnoresStaleProcessEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j-ui.env")
	if err := os.WriteFile(path, []byte(
		"JUI_LISTEN_ADDRESS=127.0.0.1:9090\nJUI_ENGINE_MODE=mock\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JUI_LISTEN_ADDRESS", "127.0.0.1:7070")
	fallback := Config{
		ListenAddress: "127.0.0.1:8080", DataDir: "/var/lib/j-ui",
		ConfigDir: "/etc/j-ui", SingBoxBinary: "/usr/local/lib/j-ui/sing-box",
		SessionTTL: time.Hour,
	}
	cfg := ReloadFromFile(path, fallback)
	if cfg.ListenAddress != "127.0.0.1:9090" || !cfg.MockEngine ||
		cfg.DataDir != fallback.DataDir || cfg.ConfigDir != fallback.ConfigDir {
		t.Fatalf("reloaded config = %#v", cfg)
	}
}
