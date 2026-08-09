package singbox

import (
	"encoding/json"
	"testing"

	"github.com/Suparluxi/j-ui/internal/model"
)

func TestGenerateAllProtocols(t *testing.T) {
	protocols := []string{
		model.ProtocolVLESSReality, model.ProtocolVLESSH2Reality,
		model.ProtocolVLESSGRPCReality, model.ProtocolVLESSWSTLS,
		model.ProtocolTrojanTLS, model.ProtocolHysteria2,
		model.ProtocolTUIC, model.ProtocolAnyTLS, model.ProtocolAnyTLSReality,
		model.ProtocolSOCKS5, model.ProtocolVLESSArgo,
	}
	var items []NodeWithClients
	for index, protocol := range protocols {
		items = append(items, NodeWithClients{
			Node: model.Node{
				ID: int64(index + 1), Protocol: protocol, Listen: "0.0.0.0",
				Port: 10000 + index, Enabled: true,
				Settings: map[string]any{
					"server_name": "example.com", "handshake_server": "example.com",
					"handshake_port": 443, "short_id": "0123456789abcdef",
					"certificate_path": "/cert.pem", "key_path": "/key.pem", "ws_path": "/ws",
					"transport_path": "/h2", "service_name": "jui-grpc",
				},
				Secret: map[string]any{"private_key": "private"},
			},
			Clients: []model.Client{{
				Name: "default", Enabled: true,
				Credential: map[string]any{
					"uuid": "uuid", "password": "password", "username": "username",
					"flow": "xtls-rprx-vision",
				},
			}},
		})
	}
	config, err := Generate(items)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(config, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Inbounds) != len(protocols) {
		t.Fatalf("inbounds = %d, want %d", len(document.Inbounds), len(protocols))
	}
	tuic := document.Inbounds[6]
	tlsConfig := tuic["tls"].(map[string]any)
	alpn := tlsConfig["alpn"].([]any)
	if len(alpn) != 1 || alpn[0] != "h3" {
		t.Fatalf("TUIC ALPN = %#v", alpn)
	}
}

func TestGenerateManualOutboundUsesExplicitInboundRoute(t *testing.T) {
	outboundID := int64(9)
	config, err := GenerateWithOutbounds([]NodeWithClients{{
		Node: model.Node{
			ID: 1, Protocol: model.ProtocolSOCKS5, Listen: "127.0.0.1",
			Port: 1080, Enabled: true, OutboundID: &outboundID,
		},
		Clients: []model.Client{{
			Name: "default", Enabled: true,
			Credential: map[string]any{"username": "client", "password": "secret"},
		}},
	}}, []model.Outbound{{
		ID: 9, Name: "residential", Type: model.OutboundSOCKS5,
		Server: "2001:db8::1", Port: 1080, Enabled: true,
		Username: "proxy-user", Password: "proxy-password",
	}})
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(config, &document); err != nil {
		t.Fatal(err)
	}
	outbounds := document["outbounds"].([]any)
	proxy := outbounds[1].(map[string]any)
	if proxy["type"] != "socks" || proxy["tag"] != "outbound-9" ||
		proxy["server"] != "2001:db8::1" || proxy["password"] != "proxy-password" {
		t.Fatalf("unexpected outbound: %#v", proxy)
	}
	route := document["route"].(map[string]any)
	if route["final"] != "native" {
		t.Fatalf("route final = %#v", route["final"])
	}
	rule := route["rules"].([]any)[0].(map[string]any)
	if rule["outbound"] != "outbound-9" {
		t.Fatalf("route rule = %#v", rule)
	}
}

func TestGenerateRejectsDisabledBoundOutbound(t *testing.T) {
	outboundID := int64(1)
	_, err := GenerateWithOutbounds([]NodeWithClients{{
		Node: model.Node{ID: 1, Enabled: true, OutboundID: &outboundID},
	}}, []model.Outbound{{ID: 1, Type: model.OutboundHTTP, Enabled: false}})
	if err == nil {
		t.Fatal("expected disabled outbound to reject generation")
	}
}

func TestGenerateOmitsUnboundOutbounds(t *testing.T) {
	config, err := GenerateWithOutbounds(nil, []model.Outbound{{
		ID: 1, Type: model.OutboundSOCKS5, Server: "127.0.0.1",
		Port: 1080, Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(config, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Outbounds) != 1 || document.Outbounds[0]["tag"] != "native" {
		t.Fatalf("unbound outbound was retained: %#v", document.Outbounds)
	}
}
