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

func TestCustomAIBaselineReplacesBundledSnapshot(t *testing.T) {
	base, err := DefaultAIDomains()
	if err != nil {
		t.Fatal(err)
	}
	base.Rules[0].Domain = []string{"custom.ai.example"}
	base.Rules[0].DomainSuffix = nil
	base.Rules[0].DomainRegex = nil
	config, err := GenerateWithAIRouting([]NodeWithClients{{
		Node:    model.Node{ID: 1, Protocol: model.ProtocolSOCKS5, Listen: "127.0.0.1", Port: 1080, Enabled: true},
		Clients: []model.Client{{Enabled: true, Credential: map[string]any{"username": "user", "password": "password"}}},
	}}, nil, &AIRouting{InboundIDs: []int64{1}, Base: &base, Server: "jp.example.com", Port: 443,
		UUID: "00000000-0000-4000-8000-000000000000", ServerName: "www.example.com",
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ShortID: "abcd"})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Route struct {
			Rules []struct {
				Outbound     string   `json:"outbound"`
				Domain       []string `json:"domain"`
				DomainSuffix []string `json:"domain_suffix"`
			} `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(config, &doc); err != nil {
		t.Fatal(err)
	}
	for _, rule := range doc.Route.Rules {
		if rule.Outbound == "ai-japan" {
			if len(rule.Domain) != 1 || rule.Domain[0] != "custom.ai.example" || len(rule.DomainSuffix) != 0 {
				t.Fatalf("unexpected effective baseline: %+v", rule)
			}
			return
		}
	}
	t.Fatal("AI rule not generated")
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

func TestGenerateAIRoutingCoversEligibleInbounds(t *testing.T) {
	boundID := int64(9)
	items := []NodeWithClients{
		{Node: model.Node{ID: 1, Protocol: model.ProtocolSOCKS5, Listen: "127.0.0.1", Port: 1081, Enabled: true}},
		{Node: model.Node{ID: 2, Protocol: model.ProtocolVLESSReality, Listen: "127.0.0.1", Port: 1082, Enabled: true}},
		{Node: model.Node{ID: 3, Protocol: model.ProtocolSOCKS5, Listen: "127.0.0.1", Port: 1083, Enabled: true, OutboundID: &boundID}},
		{Node: model.Node{ID: 4, Protocol: model.ProtocolSOCKS5, Listen: "127.0.0.1", Port: 1084, Enabled: false}},
	}
	ai := &AIRouting{InboundIDs: []int64{1, 2}, Server: "jp.example.com", Port: 443,
		UUID: "00000000-0000-4000-8000-000000000000", ServerName: "www.example.com",
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ShortID: "abcd",
		Include: []string{"new-ai.example"}, Exclude: []string{"excluded.example"}}
	config, err := GenerateWithAIRouting(items, []model.Outbound{{ID: boundID, Type: model.OutboundSOCKS5, Server: "127.0.0.1", Port: 1080, Enabled: true}}, ai)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Route struct {
			Final string           `json:"final"`
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(config, &document); err != nil {
		t.Fatal(err)
	}
	if document.Route.Final != "native" || len(document.Route.Rules) != 5 {
		t.Fatalf("unexpected AI rules: %#v", document.Route)
	}
	for _, rule := range document.Route.Rules[:4] {
		inbounds := rule["inbound"].([]any)
		if len(inbounds) != 2 || inbounds[0] != "node-1" || inbounds[1] != "node-2" {
			t.Fatalf("unexpected AI rule scope: %#v", rule)
		}
	}
	if document.Route.Rules[0]["action"] != "sniff" || document.Route.Rules[1]["outbound"] != "native" ||
		document.Route.Rules[2]["outbound"] != "ai-japan" || document.Route.Rules[3]["outbound"] != "ai-japan" ||
		document.Route.Rules[4]["outbound"] != "outbound-9" {
		t.Fatalf("incorrect route priority: %#v", document.Route.Rules)
	}
	for _, id := range []int64{3, 4, 99} {
		if _, err := GenerateWithAIRouting(items, nil, &AIRouting{InboundIDs: []int64{id}}); err == nil {
			t.Fatalf("ineligible AI source node %d must fail closed", id)
		}
	}
}
