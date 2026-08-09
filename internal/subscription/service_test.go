package subscription

import (
	"encoding/base64"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Suparluxi/j-ui/internal/model"
)

func TestURIHandlesIPv6AndEscaping(t *testing.T) {
	node := model.Node{
		Name: "测试 #1", Protocol: model.ProtocolVLESSReality, Port: 443,
		Settings: map[string]any{
			"server_name": "example.com", "public_key": "public+key", "short_id": "abcd",
		},
	}
	client := model.Client{Name: "默认", Credential: map[string]any{
		"uuid": "00000000-0000-4000-8000-000000000000", "flow": "xtls-rprx-vision",
	}}
	link, err := URI(node, client, "2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Hostname() != "2001:db8::1" || !strings.Contains(parsed.Fragment, "测试") {
		t.Fatalf("unexpected URI %q", link)
	}
}

func TestVLESSArgoExportsCloudflareEdgeEndpoint(t *testing.T) {
	node := model.Node{
		Name: "Argo", Protocol: model.ProtocolVLESSArgo, Port: 2080,
		Settings: map[string]any{"server_name": "argo.example.com", "ws_path": "/jui-argo"},
	}
	client := model.Client{Name: "default", Credential: map[string]any{
		"uuid": "00000000-0000-4000-8000-000000000000",
	}}
	link, err := URI(node, client, "argo.example.com")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Port() != "443" || parsed.Query().Get("security") != "tls" ||
		parsed.Query().Get("type") != "ws" || parsed.Query().Get("path") != "/jui-argo" {
		t.Fatalf("unexpected Argo URI %q", link)
	}
}

func TestURIExportsNewCustomProtocols(t *testing.T) {
	client := model.Client{Name: "default", Credential: map[string]any{
		"uuid":     "00000000-0000-4000-8000-000000000000",
		"username": "user", "password": "password",
	}}
	tests := []struct {
		protocol string
		scheme   string
		key      string
		value    string
	}{
		{model.ProtocolVLESSH2Reality, "vless", "type", "http"},
		{model.ProtocolVLESSGRPCReality, "vless", "type", "grpc"},
		{model.ProtocolAnyTLS, "anytls", "sni", "example.com"},
		{model.ProtocolAnyTLSReality, "anytls", "security", "reality"},
	}
	for _, test := range tests {
		node := model.Node{Name: test.protocol, Protocol: test.protocol, Port: 443, Settings: map[string]any{
			"server_name": "example.com", "public_key": "public", "short_id": "abcd",
			"transport_path": "/h2", "service_name": "jui-grpc",
		}}
		link, err := URI(node, client, "example.com")
		if err != nil {
			t.Fatalf("%s URI: %v", test.protocol, err)
		}
		parsed, err := url.Parse(link)
		if err != nil || parsed.Scheme != test.scheme || (test.key != "" && parsed.Query().Get(test.key) != test.value) {
			t.Fatalf("unexpected %s URI %q", test.protocol, link)
		}
	}
}

func TestURIProfilesFilterClientIncompatibleProtocols(t *testing.T) {
	client := model.Client{Name: "default", Credential: map[string]any{
		"uuid":     "00000000-0000-4000-8000-000000000000",
		"username": "user", "password": "password", "flow": "xtls-rprx-vision",
	}}
	items := []item{
		{
			host: "example.com",
			node: model.Node{Name: "Reality", Protocol: model.ProtocolVLESSReality, Port: 443, Settings: map[string]any{
				"server_name": "example.com", "public_key": "public", "short_id": "abcd",
			}},
			client: client,
		},
		{
			host: "example.com",
			node: model.Node{Name: "H2", Protocol: model.ProtocolVLESSH2Reality, Port: 8443, Settings: map[string]any{
				"server_name": "example.com", "public_key": "public", "short_id": "abcd", "transport_path": "/h2",
			}},
			client: client,
		},
		{
			host: "example.com",
			node: model.Node{Name: "AnyTLS+Reality", Protocol: model.ProtocolAnyTLSReality, Port: 9443, Settings: map[string]any{
				"server_name": "example.com", "public_key": "public", "short_id": "abcd",
			}},
			client: client,
		},
	}
	decode := func(profile string) string {
		body, err := base64.StdEncoding.DecodeString(string(renderURIList(items, profile)))
		if err != nil {
			t.Fatalf("decode %s profile: %v", profile, err)
		}
		return string(body)
	}
	if value := decode("v2rayn"); !strings.Contains(value, "#Reality") || !strings.Contains(value, "#H2") || !strings.Contains(value, "type=raw") || !strings.Contains(value, "headerType=http") || !strings.Contains(value, "anytls://") {
		t.Fatalf("unexpected v2rayN profile: %s", value)
	}
	if value := decode("shadowrocket"); !strings.Contains(value, "vless://") || strings.Contains(value, "anytls://") {
		t.Fatalf("unexpected Shadowrocket profile: %s", value)
	}
	if value := decode("base64"); !strings.Contains(value, "vless://") || !strings.Contains(value, "anytls://") {
		t.Fatalf("unexpected ordinary profile: %s", value)
	}
}

func TestDefaultClientNameIsNotAppended(t *testing.T) {
	node := model.Node{Name: "J-UI丨TUIC_9902", Protocol: model.ProtocolTUIC, Port: 9902,
		Settings: map[string]any{"server_name": "example.com"}}
	client := model.Client{Name: "default", Credential: map[string]any{
		"uuid": "00000000-0000-4000-8000-000000000000", "password": "secret",
	}}
	link, err := URI(node, client, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(link, "default") || !strings.HasSuffix(link, "#J-UI%E4%B8%A8TUIC_9902") {
		t.Fatalf("unexpected default client display name: %s", link)
	}
	body, err := Clash([]item{{node: node, client: client, host: "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	value := string(body)
	if strings.Contains(value, "default") || !strings.Contains(value, "J-UI丨TUIC_9902") ||
		!strings.Contains(value, "udp-relay-mode: native") || !strings.Contains(value, "- h3") {
		t.Fatalf("unexpected Mihomo output:\n%s", body)
	}
}

func TestClashSkipsAnyTLSRealityUnsupportedByMihomo(t *testing.T) {
	body, err := Clash([]item{{
		host:   "example.com",
		node:   model.Node{Name: "unsupported", Protocol: model.ProtocolAnyTLSReality, Port: 443},
		client: model.Client{Name: "default", Credential: map[string]any{"password": "secret"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "name: unsupported") {
		t.Fatalf("AnyTLS+Reality leaked into Mihomo subscription:\n%s", body)
	}
}

func TestClashWithMihomo(t *testing.T) {
	binary := os.Getenv("MIHOMO_TEST_BINARY")
	if binary == "" {
		t.Skip("MIHOMO_TEST_BINARY is not set")
	}
	protocols := []string{
		model.ProtocolVLESSReality, model.ProtocolVLESSH2Reality,
		model.ProtocolVLESSGRPCReality, model.ProtocolVLESSWSTLS,
		model.ProtocolTrojanTLS, model.ProtocolHysteria2,
		model.ProtocolTUIC, model.ProtocolAnyTLS, model.ProtocolAnyTLSReality,
		model.ProtocolSOCKS5, model.ProtocolVLESSArgo,
	}
	var items []item
	for index, protocol := range protocols {
		items = append(items, item{
			host: "example.com",
			node: model.Node{
				ID: int64(index + 1), Name: "node " + protocol, Protocol: protocol, Port: 20000 + index,
				Settings: map[string]any{
					"server_name": "example.com", "public_key": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
					"short_id": "0123456789abcdef", "ws_path": "/ws",
					"transport_path": "/h2", "service_name": "jui-grpc",
				},
			},
			client: model.Client{
				ID: int64(index + 1), Name: "default",
				Credential: map[string]any{
					"uuid":     "00000000-0000-4000-8000-000000000000",
					"password": "password", "username": "username",
					"flow": "xtls-rprx-vision",
				},
			},
		})
	}
	duplicate := items[0]
	duplicate.node.ID = 100
	duplicate.client.ID = 100
	items = append(items, duplicate)
	body, err := Clash(items)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(binary, "-t", "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("mihomo validation failed: %v\n%s\nConfig:\n%s", err, output, body)
	}
}

func TestSingBoxSubscriptionWithSingBox(t *testing.T) {
	binary := os.Getenv("SINGBOX_TEST_BINARY")
	if binary == "" {
		t.Skip("SINGBOX_TEST_BINARY is not set")
	}
	protocols := []string{
		model.ProtocolVLESSReality, model.ProtocolVLESSH2Reality,
		model.ProtocolVLESSGRPCReality, model.ProtocolVLESSWSTLS,
		model.ProtocolTrojanTLS, model.ProtocolHysteria2,
		model.ProtocolTUIC, model.ProtocolAnyTLS, model.ProtocolAnyTLSReality,
		model.ProtocolSOCKS5, model.ProtocolVLESSArgo,
	}
	items := make([]item, 0, len(protocols))
	for index, protocol := range protocols {
		items = append(items, item{
			host: "example.com",
			node: model.Node{
				ID: int64(index + 1), Name: "node " + protocol,
				Protocol: protocol, Port: 20000 + index,
				Settings: map[string]any{
					"server_name":    "example.com",
					"public_key":     "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
					"short_id":       "0123456789abcdef",
					"ws_path":        "/ws",
					"transport_path": "/h2",
					"service_name":   "jui-grpc",
				},
			},
			client: model.Client{
				ID: int64(index + 1), Name: "default",
				Credential: map[string]any{
					"uuid":     "00000000-0000-4000-8000-000000000000",
					"password": "password", "username": "username",
					"flow": "xtls-rprx-vision",
				},
			},
		})
	}
	body, err := SingBox(items)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(binary, "check", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("sing-box subscription validation failed: %v\n%s\nConfig:\n%s", err, output, body)
	}
}

func TestClashDisambiguatesDuplicateNames(t *testing.T) {
	items := []item{
		{
			host: "example.com",
			node: model.Node{ID: 1, Name: "same", Protocol: model.ProtocolSOCKS5, Port: 1080},
			client: model.Client{ID: 1, Name: "client", Credential: map[string]any{
				"username": "one", "password": "one",
			}},
		},
		{
			host: "example.com",
			node: model.Node{ID: 2, Name: "same", Protocol: model.ProtocolSOCKS5, Port: 1081},
			client: model.Client{ID: 2, Name: "client", Credential: map[string]any{
				"username": "two", "password": "two",
			}},
		},
	}
	body, err := Clash(items)
	if err != nil {
		t.Fatal(err)
	}
	value := string(body)
	if !strings.Contains(value, "same · client · n1-c1") ||
		!strings.Contains(value, "same · client · n2-c2") {
		t.Fatalf("duplicate names were not disambiguated:\n%s", body)
	}
}

func TestClashIsValidYAML(t *testing.T) {
	body, err := Clash([]item{{
		host: "example.com",
		node: model.Node{Name: "node: one", Protocol: model.ProtocolSOCKS5, Port: 1080},
		client: model.Client{Name: "default", Credential: map[string]any{
			"username": "user", "password": "p:a#s",
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "proxy-groups:") || !strings.Contains(string(body), "p:a#s") {
		t.Fatalf("unexpected YAML:\n%s", body)
	}
}
