package node

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestAIRuleSourceURLRejectsSSRF(t *testing.T) {
	if err := validateAIRulesURL(SuggestedAIRulesURL); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{
		"http://raw.githubusercontent.com/a/b/main/rules.json",
		"https://127.0.0.1/rules.json",
		"https://raw.githubusercontent.com.evil.test/a/b/main/rules.json",
		"https://raw.githubusercontent.com:443/a/b/main/rules.json",
		"https://raw.githubusercontent.com/a/b/main/../rules.json",
		"https://raw.githubusercontent.com/a/b/main/rules.json?redirect=1",
		"https://raw.githubusercontent.com/a/b/main/rules.srs",
	} {
		if err := validateAIRulesURL(source); err == nil {
			t.Errorf("accepted %s", source)
		}
	}
}

func TestSuggestedAIRulesFetchLive(t *testing.T) {
	if os.Getenv("JUI_TEST_LIVE_RULE_SOURCE") != "1" {
		t.Skip("set JUI_TEST_LIVE_RULE_SOURCE=1 for an external network check")
	}
	base, hash, err := fetchAIRules(context.Background(), SuggestedAIRulesURL)
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) != 64 || len(base.Rules) != 1 || len(base.Rules[0].DomainSuffix) == 0 {
		t.Fatalf("unexpected downloaded baseline: hash %q, rules %d", hash, len(base.Rules))
	}
}

func TestParseAIRulesAcceptsDomainRuleAndRejectsInvalidData(t *testing.T) {
	valid := `{"version":2,"rules":[{"domain":["ai.example.com"],"domain_suffix":["example.ai"],"domain_regex":["^ai[0-9]+\\.example$"]}]}`
	base, err := parseAIRules([]byte(valid))
	if err != nil || base.Version != 2 || base.Rules[0].DomainSuffix[0] != "example.ai" {
		t.Fatalf("parsed %+v, %v", base, err)
	}
	scalar := `{"version":2,"rules":[{"domain_suffix":["example.ai"],"domain_regex":"^ai[0-9]+\\.example$"}]}`
	base, err = parseAIRules([]byte(scalar))
	if err != nil || len(base.Rules[0].DomainRegex) != 1 || base.Rules[0].DomainRegex[0] != "^ai[0-9]+\\.example$" {
		t.Fatalf("scalar regex = %+v, %v", base, err)
	}
	for _, document := range []string{
		`{"version":2,"rules":[{}]}`,
		`{"version":2,"rules":[{"domain_suffix":["x.example"]},{"domain_suffix":["y.example"]}]}`,
		`{"version":2,"rules":[{"domain_regex":["("]}]}`,
		`{"version":2,"rules":[{"domain_suffix":["/etc/passwd"]}]}`,
		`{"version":2,"rules":[{"domain_suffix":["x.example"],"outbound":"direct"}]}`,
		valid + ` {}`,
		strings.Repeat(" ", 1024*1024+1),
	} {
		if _, err := parseAIRules([]byte(document)); err == nil {
			t.Errorf("accepted invalid rule set: %.100s", document)
		}
	}
}
