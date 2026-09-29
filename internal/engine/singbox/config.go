package singbox

import (
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/Suparluxi/j-ui/internal/model"
)

type NodeWithClients struct {
	Node    model.Node
	Clients []model.Client
}

//go:embed ai-rule-set.json
var aiRuleSet []byte

type AIDomains struct {
	Version int            `json:"version"`
	Rules   []AIDomainRule `json:"rules"`
}

type AIDomainRule struct {
	Domain       []string `json:"domain"`
	DomainSuffix []string `json:"domain_suffix"`
	DomainRegex  []string `json:"domain_regex"`
}

func DefaultAIDomains() (AIDomains, error) {
	var domains AIDomains
	err := json.Unmarshal(aiRuleSet, &domains)
	return domains, err
}

type AIRouting struct {
	InboundIDs []int64
	Base       *AIDomains
	Server     string
	Port       int
	UUID       string
	ServerName string
	PublicKey  string
	ShortID    string
	Flow       string
	Include    []string
	Exclude    []string
}

func Generate(items []NodeWithClients) ([]byte, error) {
	return generate(items, nil, false, nil)
}

func GenerateWithOutbounds(items []NodeWithClients, configured []model.Outbound) ([]byte, error) {
	return generate(items, configured, true, nil)
}

func GenerateWithAIRouting(items []NodeWithClients, configured []model.Outbound, ai *AIRouting) ([]byte, error) {
	return generate(items, configured, true, ai)
}

func generate(items []NodeWithClients, configured []model.Outbound, routing bool, ai *AIRouting) ([]byte, error) {
	inbounds := make([]any, 0, len(items))
	var outbounds []any
	if routing {
		outbounds = []any{map[string]any{"type": "direct", "tag": "native"}}
	}
	available := make(map[int64]model.Outbound, len(configured))
	required := make(map[int64]bool)
	for _, item := range items {
		if item.Node.Enabled && item.Node.OutboundID != nil {
			required[*item.Node.OutboundID] = true
		}
	}
	for _, outbound := range configured {
		available[outbound.ID] = outbound
		if !outbound.Enabled || !required[outbound.ID] {
			continue
		}
		entry := map[string]any{
			"type":        outboundType(outbound.Type),
			"tag":         fmt.Sprintf("outbound-%d", outbound.ID),
			"server":      outbound.Server,
			"server_port": outbound.Port,
		}
		if outbound.Username != "" {
			entry["username"] = outbound.Username
		}
		if outbound.Password != "" {
			entry["password"] = outbound.Password
		}
		if outbound.Type == model.OutboundSOCKS5 {
			entry["version"] = "5"
		}
		outbounds = append(outbounds, entry)
	}
	rules := make([]any, 0)
	if ai != nil {
		eligible := make(map[int64]bool, len(items))
		for _, item := range items {
			if item.Node.Enabled && item.Node.OutboundID == nil {
				eligible[item.Node.ID] = true
			}
		}
		inboundTags := make([]string, 0, len(ai.InboundIDs))
		seen := make(map[int64]bool, len(ai.InboundIDs))
		for _, id := range ai.InboundIDs {
			if !eligible[id] || seen[id] {
				return nil, fmt.Errorf("AI routing requires distinct enabled native inbounds; invalid node %d", id)
			}
			seen[id] = true
			inboundTags = append(inboundTags, fmt.Sprintf("node-%d", id))
		}
		outbounds = append(outbounds, map[string]any{
			"type": "vless", "tag": "ai-japan", "server": ai.Server, "server_port": ai.Port,
			"uuid": ai.UUID, "flow": ai.Flow,
			"tls": map[string]any{
				"enabled": true, "server_name": ai.ServerName,
				"utls":    map[string]any{"enabled": true, "fingerprint": "chrome"},
				"reality": map[string]any{"enabled": true, "public_key": ai.PublicKey, "short_id": ai.ShortID},
			},
		})
		if len(inboundTags) > 0 {
			rules = append(rules, map[string]any{"inbound": inboundTags, "action": "sniff", "sniffer": []string{"http", "tls", "quic"}})
		}
		if len(inboundTags) > 0 && len(ai.Exclude) > 0 {
			rules = append(rules, map[string]any{"inbound": inboundTags, "domain_suffix": ai.Exclude,
				"action": "route", "outbound": "native"})
		}
		if len(inboundTags) > 0 && len(ai.Include) > 0 {
			rules = append(rules, map[string]any{"inbound": inboundTags, "domain_suffix": ai.Include,
				"action": "route", "outbound": "ai-japan"})
		}
		base, err := DefaultAIDomains()
		if ai.Base != nil {
			base, err = *ai.Base, nil
		}
		if err != nil || len(base.Rules) != 1 {
			return nil, fmt.Errorf("load AI domain snapshot: %v", err)
		}
		list := base.Rules[0]
		if len(inboundTags) > 0 {
			rules = append(rules, map[string]any{"inbound": inboundTags,
				"domain": list.Domain, "domain_suffix": list.DomainSuffix, "domain_regex": list.DomainRegex,
				"action": "route", "outbound": "ai-japan"})
		}
	}
	for _, item := range items {
		if !item.Node.Enabled {
			continue
		}
		if item.Node.OutboundID != nil {
			outbound, ok := available[*item.Node.OutboundID]
			if !ok {
				return nil, fmt.Errorf("node %d: outbound %d does not exist", item.Node.ID, *item.Node.OutboundID)
			}
			if !outbound.Enabled {
				return nil, fmt.Errorf("node %d: outbound %d is disabled", item.Node.ID, outbound.ID)
			}
			rules = append(rules, map[string]any{
				"inbound":  []string{fmt.Sprintf("node-%d", item.Node.ID)},
				"action":   "route",
				"outbound": fmt.Sprintf("outbound-%d", outbound.ID),
			})
		}
		inbound, err := inbound(item.Node, item.Clients)
		if err != nil {
			return nil, fmt.Errorf("node %d: %w", item.Node.ID, err)
		}
		inbounds = append(inbounds, inbound)
	}
	config := map[string]any{
		"log": map[string]any{
			"level":     "info",
			"timestamp": true,
		},
		"inbounds": inbounds,
	}
	if routing {
		config["outbounds"] = outbounds
		config["route"] = map[string]any{
			"rules": rules,
			"final": "native",
		}
	}
	return json.MarshalIndent(config, "", "  ")
}

func outboundType(value string) string {
	if value == model.OutboundSOCKS5 {
		return "socks"
	}
	return value
}

func inbound(node model.Node, clients []model.Client) (map[string]any, error) {
	base := map[string]any{
		"type":        singBoxType(node.Protocol),
		"tag":         fmt.Sprintf("node-%d", node.ID),
		"listen":      node.Listen,
		"listen_port": node.Port,
	}
	active := activeClients(clients)
	switch node.Protocol {
	case model.ProtocolVLESSReality, model.ProtocolVLESSH2Reality, model.ProtocolVLESSGRPCReality:
		base["users"] = vlessUsers(active)
		base["tls"] = realityTLS(node)
		if node.Protocol == model.ProtocolVLESSH2Reality {
			base["transport"] = map[string]any{"type": "http", "path": stringSetting(node, "transport_path")}
		}
		if node.Protocol == model.ProtocolVLESSGRPCReality {
			base["transport"] = map[string]any{"type": "grpc", "service_name": stringSetting(node, "service_name")}
		}
	case model.ProtocolVLESSWSTLS:
		base["users"] = vlessUsers(active)
		base["tls"] = fileTLS(node)
		base["transport"] = map[string]any{
			"type": "ws",
			"path": stringSetting(node, "ws_path"),
		}
	case model.ProtocolVLESSArgo:
		base["users"] = vlessUsers(active)
		base["transport"] = map[string]any{
			"type": "ws",
			"path": stringSetting(node, "ws_path"),
		}
	case model.ProtocolTrojanTLS:
		base["users"] = passwordUsers(active)
		base["tls"] = fileTLS(node)
	case model.ProtocolHysteria2:
		base["users"] = passwordUsers(active)
		base["tls"] = fileTLS(node)
	case model.ProtocolTUIC:
		base["users"] = tuicUsers(active)
		base["congestion_control"] = "cubic"
		base["zero_rtt_handshake"] = false
		tlsConfig := fileTLS(node)
		tlsConfig["alpn"] = []string{"h3"}
		base["tls"] = tlsConfig
	case model.ProtocolAnyTLS:
		base["users"] = passwordUsers(active)
		base["tls"] = fileTLS(node)
	case model.ProtocolAnyTLSReality:
		base["users"] = passwordUsers(active)
		base["tls"] = realityTLS(node)
	case model.ProtocolSOCKS5:
		base["users"] = socksUsers(active)
	default:
		return nil, fmt.Errorf("unsupported protocol %q", node.Protocol)
	}
	return base, nil
}

func singBoxType(protocol string) string {
	switch protocol {
	case model.ProtocolVLESSReality, model.ProtocolVLESSH2Reality, model.ProtocolVLESSGRPCReality,
		model.ProtocolVLESSWSTLS, model.ProtocolVLESSArgo:
		return "vless"
	case model.ProtocolTrojanTLS:
		return "trojan"
	case model.ProtocolAnyTLSReality:
		return "anytls"
	case model.ProtocolSOCKS5:
		return "socks"
	default:
		return protocol
	}
}

func realityTLS(node model.Node) map[string]any {
	return map[string]any{
		"enabled":     true,
		"server_name": stringSetting(node, "server_name"),
		"reality": map[string]any{
			"enabled": true,
			"handshake": map[string]any{
				"server":      stringSetting(node, "handshake_server"),
				"server_port": intSetting(node, "handshake_port", 443),
			},
			"private_key": stringSecret(node, "private_key"),
			"short_id":    []string{stringSetting(node, "short_id")},
		},
	}
}

func activeClients(clients []model.Client) []model.Client {
	active := make([]model.Client, 0, len(clients))
	for _, client := range clients {
		if client.Enabled {
			active = append(active, client)
		}
	}
	return active
}

func vlessUsers(clients []model.Client) []any {
	users := make([]any, 0, len(clients))
	for _, client := range clients {
		user := map[string]any{"name": client.Name, "uuid": client.Credential["uuid"]}
		if flow, ok := client.Credential["flow"]; ok && flow != "" {
			user["flow"] = flow
		}
		users = append(users, user)
	}
	return users
}

func passwordUsers(clients []model.Client) []any {
	users := make([]any, 0, len(clients))
	for _, client := range clients {
		users = append(users, map[string]any{
			"name":     client.Name,
			"password": client.Credential["password"],
		})
	}
	return users
}

func tuicUsers(clients []model.Client) []any {
	users := make([]any, 0, len(clients))
	for _, client := range clients {
		users = append(users, map[string]any{
			"name":     client.Name,
			"uuid":     client.Credential["uuid"],
			"password": client.Credential["password"],
		})
	}
	return users
}

func socksUsers(clients []model.Client) []any {
	users := make([]any, 0, len(clients))
	for _, client := range clients {
		users = append(users, map[string]any{
			"username": client.Credential["username"],
			"password": client.Credential["password"],
		})
	}
	return users
}

func fileTLS(node model.Node) map[string]any {
	return map[string]any{
		"enabled":          true,
		"server_name":      stringSetting(node, "server_name"),
		"certificate_path": stringSetting(node, "certificate_path"),
		"key_path":         stringSetting(node, "key_path"),
	}
}

func stringSetting(node model.Node, key string) string {
	value, _ := node.Settings[key].(string)
	return value
}

func intSetting(node model.Node, key string, fallback int) int {
	value, ok := node.Settings[key].(float64)
	if ok {
		return int(value)
	}
	if value, ok := node.Settings[key].(int); ok {
		return value
	}
	return fallback
}

func stringSecret(node model.Node, key string) string {
	value, _ := node.Secret[key].(string)
	return value
}
