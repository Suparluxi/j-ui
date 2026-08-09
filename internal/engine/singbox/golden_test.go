package singbox

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Suparluxi/j-ui/internal/model"
)

func TestGenerateProtocolGoldens(t *testing.T) {
	protocols := []string{
		model.ProtocolVLESSReality, model.ProtocolVLESSH2Reality, model.ProtocolVLESSGRPCReality,
		model.ProtocolVLESSWSTLS, model.ProtocolTrojanTLS, model.ProtocolHysteria2,
		model.ProtocolTUIC, model.ProtocolAnyTLS, model.ProtocolAnyTLSReality,
		model.ProtocolSOCKS5,
		model.ProtocolVLESSArgo,
	}
	fixtureIndexes := map[string]int{
		model.ProtocolVLESSReality: 0, model.ProtocolVLESSWSTLS: 1,
		model.ProtocolTrojanTLS: 2, model.ProtocolHysteria2: 3,
		model.ProtocolTUIC: 4, model.ProtocolSOCKS5: 5, model.ProtocolVLESSArgo: 6,
		model.ProtocolVLESSH2Reality: 7, model.ProtocolVLESSGRPCReality: 8,
		model.ProtocolAnyTLS: 9, model.ProtocolAnyTLSReality: 10,
	}
	for _, protocol := range protocols {
		t.Run(protocol, func(t *testing.T) {
			got, err := Generate([]NodeWithClients{goldenFixture(protocol, fixtureIndexes[protocol])})
			if err != nil {
				t.Fatal(err)
			}
			goldenPath := filepath.Join("testdata", protocol+".json.golden")
			if os.Getenv("UPDATE_GOLDEN") == "1" {
				if err := os.WriteFile(goldenPath, append(got, '\n'), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			expected, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(expected)) {
				t.Fatalf("generated config changed\n--- expected\n%s\n--- got\n%s", expected, got)
			}
		})
	}
}

func goldenFixture(protocol string, index int) NodeWithClients {
	credential := map[string]any{}
	switch protocol {
	case model.ProtocolVLESSReality:
		credential["uuid"] = "00000000-0000-4000-8000-000000000000"
		credential["flow"] = "xtls-rprx-vision"
	case model.ProtocolVLESSH2Reality, model.ProtocolVLESSGRPCReality,
		model.ProtocolVLESSWSTLS, model.ProtocolVLESSArgo:
		credential["uuid"] = "00000000-0000-4000-8000-000000000000"
	case model.ProtocolTUIC:
		credential["uuid"] = "00000000-0000-4000-8000-000000000000"
		credential["password"] = "fixed-password"
	case model.ProtocolSOCKS5:
		credential["username"] = "fixed-user"
		credential["password"] = "fixed-password"
	default:
		credential["password"] = "fixed-password"
	}
	return NodeWithClients{
		Node: model.Node{
			ID: int64(index + 1), Protocol: protocol, Listen: "127.0.0.1",
			Port: 20000 + index, Enabled: true,
			Settings: map[string]any{
				"server_name": "example.com", "handshake_server": "example.com",
				"handshake_port": 443, "short_id": "0123456789abcdef",
				"certificate_path": "/etc/j-ui/example.crt",
				"key_path":         "/etc/j-ui/example.key", "ws_path": "/ws",
				"transport_path": "/h2", "service_name": "jui-grpc",
			},
			Secret: map[string]any{"private_key": "fixed-private-key"},
		},
		Clients: []model.Client{{Name: "default", Enabled: true, Credential: credential}},
	}
}
