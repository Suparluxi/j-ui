package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Suparluxi/j-ui/internal/engine/singbox"
)

const SuggestedAIRulesURL = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ai-!cn.json"

func validateAIRulesURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "raw.githubusercontent.com" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || len(raw) > 512 {
		return errors.New("rule source must be an HTTPS GitHub Raw JSON URL")
	}
	segments := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	escaped := strings.ToLower(u.EscapedPath())
	if strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%2e") || strings.Contains(escaped, "%5c") {
		return errors.New("invalid rule source path")
	}
	if len(segments) < 4 || !strings.HasSuffix(segments[len(segments)-1], ".json") {
		return errors.New("rule source must point to a GitHub Raw JSON file")
	}
	for _, part := range segments {
		if part == "" || part == "." || part == ".." || strings.Contains(part, "\\") {
			return errors.New("invalid rule source path")
		}
	}
	return nil
}

func parseAIRules(data []byte) (singbox.AIDomains, error) {
	var result singbox.AIDomains
	if len(data) == 0 || len(data) > 1024*1024 {
		return result, errors.New("rule set must be between 1 byte and 1 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var payload struct {
		Version int `json:"version"`
		Rules   []struct {
			Domain       []string        `json:"domain"`
			DomainSuffix []string        `json:"domain_suffix"`
			DomainRegex  json.RawMessage `json:"domain_regex"`
		} `json:"rules"`
	}
	if err := decoder.Decode(&payload); err != nil {
		return result, fmt.Errorf("invalid sing-box rule set: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return result, errors.New("rule set contains trailing data")
	}
	if (payload.Version != 1 && payload.Version != 2) || len(payload.Rules) != 1 {
		return result, errors.New("rule set requires version 1 or 2 and exactly one domain rule")
	}
	result.Version = payload.Version
	result.Rules = []singbox.AIDomainRule{{
		Domain: payload.Rules[0].Domain, DomainSuffix: payload.Rules[0].DomainSuffix,
	}}
	regex := payload.Rules[0].DomainRegex
	if len(regex) > 0 && string(regex) != "null" {
		if regex[0] == '"' {
			var one string
			if err := json.Unmarshal(regex, &one); err != nil {
				return result, err
			}
			result.Rules[0].DomainRegex = []string{one}
		} else if err := json.Unmarshal(regex, &result.Rules[0].DomainRegex); err != nil {
			return result, errors.New("invalid domain_regex value")
		}
	}
	rule := result.Rules[0]
	count := len(rule.Domain) + len(rule.DomainSuffix) + len(rule.DomainRegex)
	if count == 0 || count > 20000 {
		return result, errors.New("rule set must contain 1 to 20000 domains")
	}
	for _, domain := range append(append([]string{}, rule.Domain...), rule.DomainSuffix...) {
		if len(domain) > 253 || domain == "" || domain != strings.ToLower(domain) ||
			strings.ContainsAny(domain, "/\\* ") || !validRuleDomain(domain) {
			return result, errors.New("rule set contains an invalid domain")
		}
	}
	for _, pattern := range rule.DomainRegex {
		if len(pattern) > 512 {
			return result, errors.New("rule set contains an oversized regular expression")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return result, errors.New("rule set contains an invalid regular expression")
		}
	}
	return result, nil
}

func validRuleDomain(domain string) bool {
	if !strings.Contains(domain, ".") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' ||
			strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			return false
		}
	}
	return true
}

func fetchAIRules(ctx context.Context, source string) (singbox.AIDomains, string, error) {
	if err := validateAIRulesURL(source); err != nil {
		return singbox.AIDomains{}, "", err
	}
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return singbox.AIDomains{}, "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return singbox.AIDomains{}, "", fmt.Errorf("rule source download failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return singbox.AIDomains{}, "", fmt.Errorf("rule source returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil {
		return singbox.AIDomains{}, "", err
	}
	base, err := parseAIRules(data)
	if err != nil {
		return singbox.AIDomains{}, "", err
	}
	hash := sha256.Sum256(data)
	return base, hex.EncodeToString(hash[:]), nil
}
