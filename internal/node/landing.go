package node

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Suparluxi/j-ui/internal/engine/singbox"
)

const landingSetting = "ai_landing_v1"

//go:embed landing-setup.sh
var landingSetupScript string

func LandingSetupScript() string { return landingSetupScript }

type landingConfig struct {
	Enabled       bool               `json:"enabled"`
	InboundID     int64              `json:"inboundId,omitempty"` // Legacy single-inbound scope until explicitly saved.
	URI           string             `json:"uri"`
	Include       []string           `json:"include"`
	Exclude       []string           `json:"exclude"`
	RuleSource    string             `json:"ruleSource,omitempty"`
	RuleBase      *singbox.AIDomains `json:"ruleBase,omitempty"`
	RuleHash      string             `json:"ruleHash,omitempty"`
	RuleUpdatedAt string             `json:"ruleUpdatedAt,omitempty"`
}

type LandingInput struct {
	Enabled   bool   `json:"enabled"`
	InboundID int64  `json:"inboundId"`
	Details   string `json:"details"`
}

type LandingView struct {
	Enabled    bool  `json:"enabled"`
	InboundID  int64 `json:"inboundId"`
	Configured bool  `json:"configured"`
}

type LandingRulesInput struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

type LandingRulesView struct {
	Source    string            `json:"source"`
	SourceURL string            `json:"sourceUrl"`
	UpdatedAt string            `json:"updatedAt,omitempty"`
	Base      singbox.AIDomains `json:"base"`
	Include   []string          `json:"include"`
	Exclude   []string          `json:"exclude"`
}

type LandingRuleSourceInput struct {
	SourceURL string `json:"sourceUrl"`
}

func (s *Service) loadLanding(ctx context.Context) (landingConfig, bool, error) {
	value, err := s.store.SecretSetting(ctx, landingSetting)
	if errors.Is(err, sql.ErrNoRows) {
		return landingConfig{}, false, nil
	}
	if err != nil {
		return landingConfig{}, false, err
	}
	var result landingConfig
	if err := json.Unmarshal(value, &result); err != nil {
		return landingConfig{}, false, err
	}
	return result, true, nil
}

func (s *Service) saveLanding(ctx context.Context, value landingConfig) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.store.SetSecretSetting(ctx, landingSetting, encoded)
}

func (s *Service) restoreLanding(ctx context.Context, previous landingConfig, exists bool) error {
	if !exists {
		return s.store.DeleteSetting(ctx, landingSetting)
	}
	return s.saveLanding(ctx, previous)
}

func (s *Service) Landing(ctx context.Context) (LandingView, error) {
	value, _, err := s.loadLanding(ctx)
	if err != nil {
		return LandingView{}, err
	}
	view := LandingView{Enabled: value.Enabled, InboundID: value.InboundID, Configured: value.URI != ""}
	return view, nil
}

func (s *Service) SetLanding(ctx context.Context, input LandingInput) (LandingView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, exists, err := s.loadLanding(ctx)
	if err != nil {
		return LandingView{}, err
	}
	current := previous
	if input.InboundID != 0 {
		return LandingView{}, validationError(errors.New("reload the landing page to apply routing to all regular inbounds"))
	}
	current.Enabled, current.InboundID = input.Enabled, 0
	if strings.TrimSpace(input.Details) != "" {
		uri, err := landingDetailsURI(input.Details)
		if err != nil {
			return LandingView{}, validationError(err)
		}
		current.URI = uri
	}
	if current.Enabled {
		if current.URI == "" {
			return LandingView{}, validationError(errors.New("enabled landing requires six connection details"))
		}
	}
	mutationCtx, cancel := s.detachedContext(ctx)
	defer cancel()
	if err := s.saveLanding(mutationCtx, current); err != nil {
		return LandingView{}, err
	}
	if err := s.reconcile(mutationCtx); err != nil {
		return LandingView{}, s.compensate(mutationCtx, err,
			compensationStep{"restore previous landing", func(ctx context.Context) error {
				return s.restoreLanding(ctx, previous, exists)
			}},
			compensationStep{"restore previous sing-box configuration", func(ctx context.Context) error {
				return s.reconcile(ctx)
			}},
		)
	}
	return s.Landing(mutationCtx)
}

func (s *Service) LandingRules(ctx context.Context) (LandingRulesView, error) {
	value, _, err := s.loadLanding(ctx)
	if err != nil {
		return LandingRulesView{}, err
	}
	base, err := singbox.DefaultAIDomains()
	if err != nil {
		return LandingRulesView{}, err
	}
	source := "v2fly/domain-list-community category-ai-!cn @ bcea25493ed28c387660fe49ce1ceb242d2efca0 (bundled)"
	if value.RuleBase != nil {
		base, source = *value.RuleBase, value.RuleHash
	}
	return LandingRulesView{Source: source, SourceURL: value.RuleSource, UpdatedAt: value.RuleUpdatedAt, Base: base,
		Include: append([]string{}, value.Include...), Exclude: append([]string{}, value.Exclude...)}, nil
}

func (s *Service) UpdateLandingRuleSource(ctx context.Context, input LandingRuleSourceInput) (LandingRulesView, error) {
	source := strings.TrimSpace(input.SourceURL)
	var base *singbox.AIDomains
	var hash, updated string
	if source != "" {
		fetched, digest, err := fetchAIRules(ctx, source)
		if err != nil {
			return LandingRulesView{}, validationError(err)
		}
		base, hash, updated = &fetched, digest, time.Now().UTC().Format(time.RFC3339)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, exists, err := s.loadLanding(ctx)
	if err != nil {
		return LandingRulesView{}, err
	}
	current := previous
	current.RuleSource, current.RuleBase, current.RuleHash, current.RuleUpdatedAt = source, base, hash, updated
	mutationCtx, cancel := s.detachedContext(ctx)
	defer cancel()
	if err := s.saveLanding(mutationCtx, current); err != nil {
		return LandingRulesView{}, err
	}
	if err := s.reconcile(mutationCtx); err != nil {
		return LandingRulesView{}, s.compensate(mutationCtx, err,
			compensationStep{"restore previous AI rule source", func(ctx context.Context) error {
				return s.restoreLanding(ctx, previous, exists)
			}},
			compensationStep{"restore previous sing-box configuration", func(ctx context.Context) error {
				return s.reconcile(ctx)
			}},
		)
	}
	return s.LandingRules(mutationCtx)
}

func (s *Service) SetLandingRules(ctx context.Context, input LandingRulesInput) (LandingRulesView, error) {
	include, err := normalizeLandingDomains(input.Include)
	if err != nil {
		return LandingRulesView{}, validationError(err)
	}
	exclude, err := normalizeLandingDomains(input.Exclude)
	if err != nil {
		return LandingRulesView{}, validationError(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, exists, err := s.loadLanding(ctx)
	if err != nil {
		return LandingRulesView{}, err
	}
	current := previous
	current.Include, current.Exclude = include, exclude
	mutationCtx, cancel := s.detachedContext(ctx)
	defer cancel()
	if err := s.saveLanding(mutationCtx, current); err != nil {
		return LandingRulesView{}, err
	}
	if err := s.reconcile(mutationCtx); err != nil {
		return LandingRulesView{}, s.compensate(mutationCtx, err,
			compensationStep{"restore previous AI rules", func(ctx context.Context) error {
				return s.restoreLanding(ctx, previous, exists)
			}},
			compensationStep{"restore previous sing-box configuration", func(ctx context.Context) error {
				return s.reconcile(ctx)
			}},
		)
	}
	return s.LandingRules(mutationCtx)
}

func normalizeLandingDomains(values []string) ([]string, error) {
	if len(values) > 256 {
		return nil, errors.New("at most 256 custom domains are allowed")
	}
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.ToLower(strings.TrimSpace(raw))
		if len(value) > 253 || !strings.Contains(value, ".") || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
			return nil, fmt.Errorf("invalid domain suffix %q", raw)
		}
		for _, label := range strings.Split(value, ".") {
			if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' || strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
				return nil, fmt.Errorf("invalid domain suffix %q", raw)
			}
		}
		if !seen[value] {
			result = append(result, value)
			seen[value] = true
		}
	}
	sort.Strings(result)
	return result, nil
}

func parseLandingURI(raw string) (*singbox.AIRouting, error) {
	uri, err := url.Parse(raw)
	if err != nil || uri.Scheme != "vless" || uri.User == nil || uri.User.Username() == "" {
		return nil, errors.New("landing node must be a VLESS Reality URI")
	}
	uuid := uri.User.Username()
	if _, hasPassword := uri.User.Password(); hasPassword || !credentialUUIDPattern.MatchString(uuid) {
		return nil, errors.New("invalid VLESS UUID")
	}
	server, err := validateEndpointHost(uri.Hostname())
	if err != nil || server == "" {
		return nil, errors.New("invalid landing server")
	}
	port, err := strconv.Atoi(uri.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid landing port")
	}
	query := uri.Query()
	if query.Get("security") != "reality" || (query.Get("type") != "" && query.Get("type") != "tcp") ||
		(query.Get("encryption") != "" && query.Get("encryption") != "none") ||
		(query.Get("fp") != "" && query.Get("fp") != "chrome") {
		return nil, errors.New("only VLESS Reality over TCP with chrome fingerprint is supported")
	}
	flow := query.Get("flow")
	if flow != "" && flow != "xtls-rprx-vision" {
		return nil, errors.New("unsupported VLESS flow")
	}
	serverName, err := validateEndpointHost(query.Get("sni"))
	if err != nil || serverName == "" {
		return nil, errors.New("Reality server name is required")
	}
	publicKey := query.Get("pbk")
	key, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil || len(key) != 32 {
		return nil, errors.New("invalid Reality public key")
	}
	shortID := query.Get("sid")
	if len(shortID) > 16 || len(shortID)%2 != 0 {
		return nil, errors.New("invalid Reality short ID")
	}
	if _, err := hex.DecodeString(shortID); err != nil {
		return nil, errors.New("invalid Reality short ID")
	}
	return &singbox.AIRouting{Server: server, Port: port, UUID: uuid,
		ServerName: serverName, PublicKey: publicKey, ShortID: shortID, Flow: flow}, nil
}

func landingDetailsURI(raw string) (string, error) {
	fields := map[string]string{}
	allowed := map[string]bool{"ADDR": true, "PORT": true, "UUID": true, "PUB": true, "SID": true, "SNI": true}
	legacy := map[string]string{"JP_ADDR": "ADDR", "JP_PORT": "PORT", "JP_UUID": "UUID", "JP_PUB": "PUB", "JP_SID": "SID", "JP_SNI": "SNI"}
	format := ""
	if len(raw) > 2048 {
		return "", errors.New("landing connection details are too long")
	}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		normalized, isLegacy := legacy[key]
		if !isLegacy {
			normalized = key
		}
		currentFormat := "modern"
		if isLegacy {
			currentFormat = "legacy"
		}
		if !ok || !allowed[normalized] || fields[normalized] != "" || strings.TrimSpace(value) != value || value == "" || (format != "" && format != currentFormat) {
			return "", errors.New("landing connection details must contain six unique fields: ADDR, PORT, UUID, PUB, SID and SNI")
		}
		format = currentFormat
		fields[normalized] = value
	}
	if len(fields) != len(allowed) {
		return "", errors.New("landing connection details must contain ADDR, PORT, UUID, PUB, SID and SNI")
	}
	port, err := strconv.Atoi(fields["PORT"])
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("invalid landing port")
	}
	query := url.Values{"security": {"reality"}, "type": {"tcp"}, "encryption": {"none"},
		"sni": {fields["SNI"]}, "pbk": {fields["PUB"]}, "sid": {fields["SID"]},
		"flow": {"xtls-rprx-vision"}, "fp": {"chrome"}}
	uri := "vless://" + fields["UUID"] + "@" + fields["ADDR"] + ":" + strconv.Itoa(port) + "?" + query.Encode()
	if _, err := parseLandingURI(uri); err != nil {
		return "", err
	}
	return uri, nil
}
