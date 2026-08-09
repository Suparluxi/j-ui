package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	ListenAddress   string
	TLSCertificate  string
	TLSPrivateKey   string
	DataDir         string
	ConfigDir       string
	DatabasePath    string
	SecretKeyPath   string
	SingBoxBinary   string
	SingBoxConfig   string
	SessionTTL      time.Duration
	MockEngine      bool
	VPNGateMaxExits int
	NodeStartPort   int
}

func Load() Config {
	return LoadFromFile("/etc/j-ui/j-ui.env")
}

// LoadFromFile reads the same allowlisted values used by the systemd
// EnvironmentFile. Process environment values take precedence. The file is
// parsed as data and is never sourced or evaluated by a shell.
func LoadFromFile(path string) Config {
	fileValues := readEnvironmentFile(path)
	dataDir := value("JUI_DATA_DIR", "/var/lib/j-ui", fileValues)
	configDir := value("JUI_CONFIG_DIR", "/etc/j-ui", fileValues)
	return Config{
		ListenAddress:   value("JUI_LISTEN_ADDRESS", "0.0.0.0:8080", fileValues),
		TLSCertificate:  value("JUI_TLS_CERTIFICATE_PATH", "", fileValues),
		TLSPrivateKey:   value("JUI_TLS_KEY_PATH", "", fileValues),
		DataDir:         dataDir,
		ConfigDir:       configDir,
		DatabasePath:    filepath.Join(dataDir, "j-ui.db"),
		SecretKeyPath:   filepath.Join(configDir, "secret.key"),
		SingBoxBinary:   value("JUI_SINGBOX_BINARY", "/usr/local/lib/j-ui/sing-box", fileValues),
		SingBoxConfig:   filepath.Join(configDir, "sing-box.json"),
		SessionTTL:      12 * time.Hour,
		MockEngine:      value("JUI_ENGINE_MODE", "", fileValues) == "mock",
		VPNGateMaxExits: boundedInt(value("JUI_VPNGATE_MAX_EXITS", "5", fileValues), 5, 1, 5),
		NodeStartPort:   boundedInt(value("JUI_NODE_START_PORT", "8881", fileValues), 8881, 1, 65535),
	}
}

// ReloadFromFile applies a deployed EnvironmentFile to an already resolved
// configuration without consulting the current process environment. It is
// used after restore, because the running CLI process still has the old
// environment while systemd will start services with the restored file.
func ReloadFromFile(path string, fallback Config) Config {
	fileValues := readEnvironmentFile(path)
	dataDir := fileValue("JUI_DATA_DIR", fallback.DataDir, fileValues)
	configDir := fileValue("JUI_CONFIG_DIR", fallback.ConfigDir, fileValues)
	mode := fileValue("JUI_ENGINE_MODE", "", fileValues)
	mockEngine := fallback.MockEngine
	if _, specified := fileValues["JUI_ENGINE_MODE"]; specified {
		mockEngine = mode == "mock"
	}
	nodeStartPort := fallback.NodeStartPort
	if nodeStartPort < 1 || nodeStartPort > 65535 {
		nodeStartPort = 8881
	}
	return Config{
		ListenAddress:  fileValue("JUI_LISTEN_ADDRESS", fallback.ListenAddress, fileValues),
		TLSCertificate: fileValue("JUI_TLS_CERTIFICATE_PATH", fallback.TLSCertificate, fileValues),
		TLSPrivateKey:  fileValue("JUI_TLS_KEY_PATH", fallback.TLSPrivateKey, fileValues),
		DataDir:        dataDir,
		ConfigDir:      configDir,
		DatabasePath:   filepath.Join(dataDir, "j-ui.db"),
		SecretKeyPath:  filepath.Join(configDir, "secret.key"),
		SingBoxBinary:  fileValue("JUI_SINGBOX_BINARY", fallback.SingBoxBinary, fileValues),
		SingBoxConfig:  filepath.Join(configDir, "sing-box.json"),
		SessionTTL:     fallback.SessionTTL,
		MockEngine:     mockEngine,
		VPNGateMaxExits: boundedInt(
			fileValue("JUI_VPNGATE_MAX_EXITS", "5", fileValues),
			fallback.VPNGateMaxExits, 1, 5,
		),
		NodeStartPort: boundedInt(
			fileValue("JUI_NODE_START_PORT", "8881", fileValues),
			nodeStartPort, 1, 65535,
		),
	}
}

func value(name, fallback string, fileValues map[string]string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	if value := fileValues[name]; value != "" {
		return value
	}
	return fallback
}

func fileValue(name, fallback string, fileValues map[string]string) string {
	if value := fileValues[name]; value != "" {
		return value
	}
	return fallback
}

func readEnvironmentFile(path string) map[string]string {
	values := make(map[string]string)
	file, err := os.Open(path)
	if err != nil {
		return values
	}
	defer file.Close()
	allowed := map[string]bool{
		"JUI_LISTEN_ADDRESS":       true,
		"JUI_TLS_CERTIFICATE_PATH": true,
		"JUI_TLS_KEY_PATH":         true,
		"JUI_DATA_DIR":             true,
		"JUI_CONFIG_DIR":           true,
		"JUI_SINGBOX_BINARY":       true,
		"JUI_ENGINE_MODE":          true,
		"JUI_VPNGATE_MAX_EXITS":    true,
		"JUI_NODE_START_PORT":      true,
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, raw, found := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if !found || !allowed[name] {
			continue
		}
		raw = strings.TrimSpace(raw)
		if len(raw) >= 2 && ((raw[0] == '"' && raw[len(raw)-1] == '"') ||
			(raw[0] == '\'' && raw[len(raw)-1] == '\'')) {
			raw = raw[1 : len(raw)-1]
		}
		values[name] = raw
	}
	return values
}

func boundedInt(raw string, fallback, minimum, maximum int) int {
	value := 0
	for _, character := range strings.TrimSpace(raw) {
		if character < '0' || character > '9' {
			return fallback
		}
		value = value*10 + int(character-'0')
		if value > maximum {
			return fallback
		}
	}
	if value < minimum || value > maximum {
		return fallback
	}
	return value
}
