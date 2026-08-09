package subscription

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/Suparluxi/j-ui/internal/database"
	"github.com/Suparluxi/j-ui/internal/model"
	"github.com/Suparluxi/j-ui/internal/problem"
	"github.com/Suparluxi/j-ui/internal/secure"
	"gopkg.in/yaml.v3"
)

type Service struct {
	store  *database.Store
	sealer *secure.Sealer
}

type Preview struct {
	Format  string `json:"format"`
	Valid   bool   `json:"valid"`
	Items   int    `json:"items"`
	Content string `json:"content"`
}

func NewService(store *database.Store, sealer *secure.Sealer) *Service {
	return &Service{store: store, sealer: sealer}
}

func (s *Service) CurrentToken(ctx context.Context) (string, error) {
	return s.store.SubscriptionToken(ctx)
}

func (s *Service) ResetToken(ctx context.Context) (string, error) {
	token, err := secure.RandomToken(32)
	if err != nil {
		return "", err
	}
	encrypted, err := s.sealer.Seal([]byte(token))
	if err != nil {
		return "", err
	}
	if err := s.store.ResetSubscriptionToken(ctx, secure.HashToken(token), encrypted); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Service) NodeURI(ctx context.Context, nodeID int64) (string, error) {
	node, err := s.store.Node(ctx, nodeID)
	if err != nil {
		return "", err
	}
	publicHost, err := s.store.Setting(ctx, "public_host")
	if err != nil {
		return "", err
	}
	host := node.PublicHostOverride
	if host == "" {
		host = publicHost
	}
	clients, err := s.store.Clients(ctx, nodeID)
	if err != nil {
		return "", err
	}
	for _, client := range clients {
		if client.Enabled {
			return URI(node, client, host)
		}
	}
	return "", problem.New(problem.Conflict, "no_enabled_client", "node has no enabled client", nil)
}

func (s *Service) ClientURI(ctx context.Context, nodeID, clientID int64) (string, error) {
	node, err := s.store.Node(ctx, nodeID)
	if err != nil {
		return "", err
	}
	publicHost, err := s.store.Setting(ctx, "public_host")
	if err != nil {
		return "", err
	}
	host := node.PublicHostOverride
	if host == "" {
		host = publicHost
	}
	clients, err := s.store.Clients(ctx, nodeID)
	if err != nil {
		return "", err
	}
	for _, client := range clients {
		if client.ID == clientID {
			return URI(node, client, host)
		}
	}
	return "", problem.New(problem.NotFound, "not_found", "client not found", sql.ErrNoRows)
}

func (s *Service) Render(ctx context.Context, token, format string) ([]byte, string, error) {
	user, err := s.store.UserByTokenHash(ctx, secure.HashToken(token))
	if err != nil {
		return nil, "", err
	}
	publicHost, err := s.store.Setting(ctx, "public_host")
	if err != nil || publicHost == "" {
		return nil, "", problem.New(problem.Conflict, "public_host_required", "public host is not configured", err)
	}
	items, err := s.items(ctx, user.ID, publicHost)
	if err != nil {
		return nil, "", err
	}
	switch format {
	case "", "base64", "v2rayn", "shadowrocket":
		return renderURIList(items, format), "text/plain; charset=utf-8", nil
	case "clash":
		body, err := Clash(items)
		return body, "application/yaml; charset=utf-8", err
	case "singbox":
		body, err := SingBox(items)
		return body, "application/json; charset=utf-8", err
	default:
		return nil, "", problem.New(problem.Validation, "unsupported_format", "unsupported subscription format", nil)
	}
}

func (s *Service) Preview(ctx context.Context, format string) (Preview, error) {
	if format == "" {
		format = "base64"
	}
	token, err := s.CurrentToken(ctx)
	if err != nil {
		return Preview{}, err
	}
	body, _, err := s.Render(ctx, token, format)
	if err != nil {
		return Preview{}, err
	}
	preview := Preview{Format: format, Valid: true}
	switch format {
	case "base64", "v2rayn", "shadowrocket":
		decoded, err := base64.StdEncoding.DecodeString(string(body))
		if err != nil {
			return Preview{}, fmt.Errorf("validate base64 subscription: %w", err)
		}
		preview.Content = string(decoded)
		for _, line := range strings.Split(preview.Content, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			parsed, err := url.Parse(line)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" {
				return Preview{}, fmt.Errorf("validate node URI %d: invalid URI", preview.Items+1)
			}
			preview.Items++
		}
	case "clash":
		var document struct {
			Proxies []map[string]any `yaml:"proxies"`
		}
		if err := yaml.Unmarshal(body, &document); err != nil {
			return Preview{}, fmt.Errorf("validate Mihomo YAML: %w", err)
		}
		preview.Items = len(document.Proxies)
		preview.Content = string(body)
	case "singbox":
		var document struct {
			Outbounds []struct {
				Tag string `json:"tag"`
			} `json:"outbounds"`
		}
		if err := json.Unmarshal(body, &document); err != nil {
			return Preview{}, fmt.Errorf("validate sing-box JSON: %w", err)
		}
		for _, outbound := range document.Outbounds {
			if strings.HasPrefix(outbound.Tag, "node-") {
				preview.Items++
			}
		}
		preview.Content = string(body)
	default:
		return Preview{}, problem.New(problem.Validation, "unsupported_format", "unsupported subscription format", nil)
	}
	return preview, nil
}

func renderURIList(items []item, profile string) []byte {
	links := make([]string, 0, len(items))
	for _, item := range items {
		if !supportsURIProfile(profile, item.node.Protocol) {
			continue
		}
		link, err := URIForProfile(item.node, item.client, item.host, profile)
		if err == nil {
			links = append(links, link)
		} else {
			log.Printf("subscription skipped profile=%s node=%d protocol=%s: %v", profile, item.node.ID, item.node.Protocol, err)
		}
	}
	return []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n"))))
}

func supportsURIProfile(profile, protocol string) bool {
	return profile != "shadowrocket" || protocol != model.ProtocolAnyTLSReality
}

// URIForProfile preserves the standard link for most clients and maps H2 to
// v2rayN's raw+headerType=http representation. Its sing-box core converts
// that representation back into an HTTP transport instead of discarding it.
func URIForProfile(node model.Node, client model.Client, host, profile string) (string, error) {
	link, err := URI(node, client, host)
	if err != nil || profile != "v2rayn" || node.Protocol != model.ProtocolVLESSH2Reality {
		return link, err
	}
	parsed, err := url.Parse(link)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("type", "raw")
	query.Set("headerType", "http")
	query.Set("host", setting(node, "server_name"))
	query.Set("path", setting(node, "transport_path"))
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

type item struct {
	node   model.Node
	client model.Client
	host   string
}

func (s *Service) items(ctx context.Context, userID int64, publicHost string) ([]item, error) {
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	var items []item
	for _, node := range nodes {
		if !node.Enabled {
			continue
		}
		host := node.PublicHostOverride
		if host == "" {
			host = publicHost
		}
		clients, err := s.store.Clients(ctx, node.ID)
		if err != nil {
			return nil, err
		}
		for _, client := range clients {
			if client.Enabled && client.UserID == userID {
				items = append(items, item{node: node, client: client, host: host})
			}
		}
	}
	return items, nil
}

func URI(node model.Node, client model.Client, host string) (string, error) {
	if host == "" {
		return "", errors.New("host is required")
	}
	name := url.PathEscape(displayName(node, client))
	endpoint := net.JoinHostPort(host, strconv.Itoa(exportPort(node)))
	query := url.Values{}
	switch node.Protocol {
	case model.ProtocolVLESSReality, model.ProtocolVLESSH2Reality, model.ProtocolVLESSGRPCReality:
		query.Set("encryption", "none")
		query.Set("security", "reality")
		query.Set("sni", setting(node, "server_name"))
		query.Set("fp", "chrome")
		query.Set("pbk", setting(node, "public_key"))
		query.Set("sid", setting(node, "short_id"))
		switch node.Protocol {
		case model.ProtocolVLESSH2Reality:
			query.Set("type", "http")
			query.Set("path", setting(node, "transport_path"))
		case model.ProtocolVLESSGRPCReality:
			query.Set("type", "grpc")
			query.Set("serviceName", setting(node, "service_name"))
		default:
			query.Set("type", "tcp")
			query.Set("flow", credential(client, "flow"))
		}
		return "vless://" + credential(client, "uuid") + "@" + endpoint + "?" + query.Encode() + "#" + name, nil
	case model.ProtocolVLESSWSTLS, model.ProtocolVLESSArgo:
		query.Set("encryption", "none")
		query.Set("security", "tls")
		query.Set("sni", setting(node, "server_name"))
		query.Set("host", setting(node, "server_name"))
		query.Set("type", "ws")
		query.Set("path", setting(node, "ws_path"))
		return "vless://" + credential(client, "uuid") + "@" + endpoint + "?" + query.Encode() + "#" + name, nil
	case model.ProtocolTrojanTLS:
		query.Set("security", "tls")
		query.Set("sni", setting(node, "server_name"))
		return "trojan://" + url.PathEscape(credential(client, "password")) + "@" + endpoint + "?" + query.Encode() + "#" + name, nil
	case model.ProtocolHysteria2:
		query.Set("sni", setting(node, "server_name"))
		return "hysteria2://" + url.PathEscape(credential(client, "password")) + "@" + endpoint + "?" + query.Encode() + "#" + name, nil
	case model.ProtocolTUIC:
		query.Set("sni", setting(node, "server_name"))
		query.Set("alpn", "h3")
		query.Set("congestion_control", "cubic")
		query.Set("udp_relay_mode", "native")
		userInfo := url.PathEscape(credential(client, "uuid")) + ":" + url.PathEscape(credential(client, "password"))
		return "tuic://" + userInfo + "@" + endpoint + "?" + query.Encode() + "#" + name, nil
	case model.ProtocolAnyTLS, model.ProtocolAnyTLSReality:
		query.Set("sni", setting(node, "server_name"))
		if node.Protocol == model.ProtocolAnyTLSReality {
			query.Set("security", "reality")
			query.Set("fp", "chrome")
			query.Set("pbk", setting(node, "public_key"))
			query.Set("sid", setting(node, "short_id"))
		}
		return "anytls://" + url.PathEscape(credential(client, "password")) + "@" + endpoint + "?" + query.Encode() + "#" + name, nil
	case model.ProtocolSOCKS5:
		userInfo := url.PathEscape(credential(client, "username")) + ":" + url.PathEscape(credential(client, "password"))
		return "socks://" + userInfo + "@" + endpoint + "#" + name, nil
	default:
		return "", fmt.Errorf("unsupported protocol %q", node.Protocol)
	}
}

func Clash(items []item) ([]byte, error) {
	proxies := make([]map[string]any, 0, len(items))
	names := make([]string, 0, len(items))
	nameCounts := make(map[string]int)
	for _, item := range items {
		if supportsClash(item.node.Protocol) {
			nameCounts[displayName(item.node, item.client)]++
		}
	}
	for index, item := range items {
		if !supportsClash(item.node.Protocol) {
			log.Printf("Mihomo subscription skipped node=%d protocol=%s: unsupported by Mihomo", item.node.ID, item.node.Protocol)
			continue
		}
		name := displayName(item.node, item.client)
		if nameCounts[name] > 1 {
			if item.node.ID != 0 && item.client.ID != 0 {
				name += fmt.Sprintf(" · n%d-c%d", item.node.ID, item.client.ID)
			} else {
				name += fmt.Sprintf(" · #%d", index+1)
			}
		}
		proxy, err := clashProxy(item.node, item.client, item.host, name)
		if err != nil {
			log.Printf("Mihomo subscription skipped node=%d protocol=%s: %v", item.node.ID, item.node.Protocol, err)
			continue
		}
		proxies = append(proxies, proxy)
		names = append(names, proxy["name"].(string))
	}
	autoNames := names
	if len(autoNames) == 0 {
		autoNames = []string{"DIRECT"}
	}
	document := map[string]any{
		"mixed-port": 7890,
		"mode":       "rule",
		"proxies":    proxies,
		"proxy-groups": []map[string]any{
			{"name": "PROXY", "type": "select", "proxies": append([]string{"AUTO"}, names...)},
			{"name": "AUTO", "type": "url-test", "url": "https://www.gstatic.com/generate_204", "interval": 300, "proxies": autoNames},
		},
		"rules": []string{"MATCH,PROXY"},
	}
	return yaml.Marshal(document)
}

func supportsClash(protocol string) bool {
	return protocol != model.ProtocolAnyTLSReality
}

func SingBox(items []item) ([]byte, error) {
	outbounds := make([]any, 0, len(items)+2)
	proxyTags := make([]string, 0, len(items))
	for index, item := range items {
		tag := fmt.Sprintf("node-%d-%d", item.node.ID, item.client.ID)
		if item.node.ID == 0 || item.client.ID == 0 {
			tag = fmt.Sprintf("node-%d", index+1)
		}
		outbound, err := singBoxOutbound(item.node, item.client, item.host, tag)
		if err != nil {
			log.Printf("sing-box subscription skipped node=%d protocol=%s: %v", item.node.ID, item.node.Protocol, err)
			continue
		}
		outbounds = append(outbounds, outbound)
		proxyTags = append(proxyTags, tag)
	}
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})
	final := "direct"
	if len(proxyTags) != 0 {
		final = "proxy"
		outbounds = append(outbounds, map[string]any{
			"type": "selector", "tag": "proxy", "outbounds": proxyTags,
			"default": proxyTags[0],
		})
	}
	document := map[string]any{
		"log": map[string]any{"level": "info", "timestamp": true},
		"inbounds": []any{map[string]any{
			"type": "mixed", "tag": "mixed-in",
			"listen": "127.0.0.1", "listen_port": 2080,
		}},
		"outbounds": outbounds,
		"route":     map[string]any{"final": final},
	}
	return json.MarshalIndent(document, "", "  ")
}

func singBoxOutbound(node model.Node, client model.Client, host, tag string) (map[string]any, error) {
	if host == "" {
		return nil, errors.New("host is required")
	}
	base := map[string]any{
		"type":        singBoxOutboundType(node.Protocol),
		"tag":         tag,
		"server":      host,
		"server_port": exportPort(node),
	}
	tls := func() map[string]any {
		return map[string]any{
			"enabled":     true,
			"server_name": setting(node, "server_name"),
		}
	}
	switch node.Protocol {
	case model.ProtocolVLESSReality, model.ProtocolVLESSH2Reality, model.ProtocolVLESSGRPCReality:
		base["uuid"] = credential(client, "uuid")
		if node.Protocol == model.ProtocolVLESSReality {
			base["flow"] = credential(client, "flow")
		}
		tlsConfig := tls()
		tlsConfig["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
		tlsConfig["reality"] = map[string]any{
			"enabled": true, "public_key": setting(node, "public_key"),
			"short_id": setting(node, "short_id"),
		}
		base["tls"] = tlsConfig
		if node.Protocol == model.ProtocolVLESSH2Reality {
			base["transport"] = map[string]any{"type": "http", "path": setting(node, "transport_path")}
		}
		if node.Protocol == model.ProtocolVLESSGRPCReality {
			base["transport"] = map[string]any{"type": "grpc", "service_name": setting(node, "service_name")}
		}
	case model.ProtocolVLESSWSTLS, model.ProtocolVLESSArgo:
		base["uuid"] = credential(client, "uuid")
		base["tls"] = tls()
		base["transport"] = map[string]any{
			"type": "ws", "path": setting(node, "ws_path"),
			"headers": map[string]any{"Host": setting(node, "server_name")},
		}
	case model.ProtocolTrojanTLS:
		base["password"] = credential(client, "password")
		base["tls"] = tls()
	case model.ProtocolHysteria2:
		base["password"] = credential(client, "password")
		base["tls"] = tls()
	case model.ProtocolTUIC:
		base["uuid"] = credential(client, "uuid")
		base["password"] = credential(client, "password")
		base["congestion_control"] = "cubic"
		tlsConfig := tls()
		tlsConfig["alpn"] = []string{"h3"}
		base["tls"] = tlsConfig
	case model.ProtocolAnyTLS, model.ProtocolAnyTLSReality:
		base["password"] = credential(client, "password")
		tlsConfig := tls()
		if node.Protocol == model.ProtocolAnyTLSReality {
			tlsConfig["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
			tlsConfig["reality"] = map[string]any{
				"enabled": true, "public_key": setting(node, "public_key"),
				"short_id": setting(node, "short_id"),
			}
		}
		base["tls"] = tlsConfig
	case model.ProtocolSOCKS5:
		base["version"] = "5"
		base["username"] = credential(client, "username")
		base["password"] = credential(client, "password")
	default:
		return nil, fmt.Errorf("unsupported protocol %q", node.Protocol)
	}
	return base, nil
}

func singBoxOutboundType(protocol string) string {
	switch protocol {
	case model.ProtocolVLESSReality, model.ProtocolVLESSH2Reality,
		model.ProtocolVLESSGRPCReality, model.ProtocolVLESSWSTLS, model.ProtocolVLESSArgo:
		return "vless"
	case model.ProtocolAnyTLSReality:
		return "anytls"
	case model.ProtocolTrojanTLS:
		return "trojan"
	case model.ProtocolSOCKS5:
		return "socks"
	default:
		return protocol
	}
}

func clashProxy(node model.Node, client model.Client, host, name string) (map[string]any, error) {
	base := map[string]any{"name": name, "server": host, "port": exportPort(node)}
	switch node.Protocol {
	case model.ProtocolVLESSReality, model.ProtocolVLESSH2Reality, model.ProtocolVLESSGRPCReality:
		base["type"] = "vless"
		base["uuid"] = credential(client, "uuid")
		base["network"] = "tcp"
		base["tls"] = true
		base["servername"] = setting(node, "server_name")
		if node.Protocol == model.ProtocolVLESSReality {
			base["flow"] = credential(client, "flow")
		} else if node.Protocol == model.ProtocolVLESSH2Reality {
			base["network"] = "h2"
			base["h2-opts"] = map[string]any{"path": setting(node, "transport_path")}
		} else {
			base["network"] = "grpc"
			base["grpc-opts"] = map[string]any{"grpc-service-name": setting(node, "service_name")}
		}
		base["client-fingerprint"] = "chrome"
		base["reality-opts"] = map[string]any{
			"public-key": setting(node, "public_key"),
			"short-id":   setting(node, "short_id"),
		}
	case model.ProtocolVLESSWSTLS, model.ProtocolVLESSArgo:
		base["type"] = "vless"
		base["uuid"] = credential(client, "uuid")
		base["network"] = "ws"
		base["tls"] = true
		base["servername"] = setting(node, "server_name")
		base["ws-opts"] = map[string]any{
			"path":    setting(node, "ws_path"),
			"headers": map[string]any{"Host": setting(node, "server_name")},
		}
	case model.ProtocolTrojanTLS:
		base["type"] = "trojan"
		base["password"] = credential(client, "password")
		base["sni"] = setting(node, "server_name")
	case model.ProtocolHysteria2:
		base["type"] = "hysteria2"
		base["password"] = credential(client, "password")
		base["sni"] = setting(node, "server_name")
	case model.ProtocolTUIC:
		base["type"] = "tuic"
		base["uuid"] = credential(client, "uuid")
		base["password"] = credential(client, "password")
		base["sni"] = setting(node, "server_name")
		base["alpn"] = []string{"h3"}
		base["congestion-controller"] = "cubic"
		base["udp-relay-mode"] = "native"
	case model.ProtocolAnyTLS:
		base["type"] = "anytls"
		base["password"] = credential(client, "password")
		base["sni"] = setting(node, "server_name")
	case model.ProtocolAnyTLSReality:
		return nil, errors.New("AnyTLS with Reality is not supported by Mihomo")
	case model.ProtocolSOCKS5:
		base["type"] = "socks5"
		base["username"] = credential(client, "username")
		base["password"] = credential(client, "password")
	default:
		return nil, errors.New("unsupported protocol")
	}
	return base, nil
}

func displayName(node model.Node, client model.Client) string {
	clientName := strings.TrimSpace(client.Name)
	if clientName == "" || strings.EqualFold(clientName, "default") {
		return node.Name
	}
	return node.Name + " · " + clientName
}

func exportPort(node model.Node) int {
	if node.Protocol == model.ProtocolVLESSArgo {
		return 443
	}
	return node.Port
}

func setting(node model.Node, key string) string {
	value, _ := node.Settings[key].(string)
	return value
}

func credential(client model.Client, key string) string {
	value, _ := client.Credential[key].(string)
	return value
}
