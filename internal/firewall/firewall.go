package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Suparluxi/j-ui/internal/engine"
)

type Manager interface {
	Backend(context.Context) (string, error)
	Ensure(context.Context, string, int) (Result, error)
	Close(context.Context, string, int, string) error
}

type Ownership string

const (
	Owned    Ownership = "owned"
	Borrowed Ownership = "borrowed"
)

const (
	BackendUnknown   = "unknown"
	BackendFirewalld = "firewalld"
	BackendUFW       = "ufw"
	BackendNFTables  = "nftables"
)

type Result struct {
	Ownership Ownership
	Backend   string
}

type ManagementState struct {
	Protocol  string    `json:"protocol"`
	Port      int       `json:"port"`
	Ownership Ownership `json:"ownership"`
	Backend   string    `json:"backend"`
}

type nftRuleset struct {
	Objects []struct {
		Chain *struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
			Hook   string `json:"hook"`
			Policy string `json:"policy"`
		} `json:"chain,omitempty"`
		Rule *struct {
			Family  string `json:"family"`
			Table   string `json:"table"`
			Chain   string `json:"chain"`
			Handle  int    `json:"handle"`
			Comment string `json:"comment"`
		} `json:"rule,omitempty"`
	} `json:"nftables"`
}

type nftChainRef struct {
	Family string
	Table  string
	Chain  string
}

// EnsureManagement opens the panel port and records whether J-UI owns the
// rule. Borrowed rules are never removed during uninstall.
func EnsureManagement(ctx context.Context, manager Manager, statePath string, port int) (Result, error) {
	result, err := manager.Ensure(ctx, "tcp", port)
	if err != nil {
		return Result{}, err
	}
	state := ManagementState{Protocol: "tcp", Port: port, Ownership: result.Ownership, Backend: result.Backend}
	if previous, loadErr := LoadManagementState(statePath); loadErr == nil &&
		previous.Port == port && previous.Ownership == Owned {
		state.Ownership = Owned
	}
	if err := writeManagementState(statePath, state); err != nil {
		if result.Ownership == Owned {
			_ = manager.Close(ctx, "tcp", port, result.Backend)
		}
		return Result{}, err
	}
	return result, nil
}

func CloseManagement(ctx context.Context, manager Manager, statePath string) error {
	state, err := LoadManagementState(statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if state.Ownership == Owned {
		if err := manager.Close(ctx, state.Protocol, state.Port, state.Backend); err != nil {
			return err
		}
	}
	return os.Remove(statePath)
}

func LoadManagementState(path string) (ManagementState, error) {
	var state ManagementState
	content, err := os.ReadFile(path)
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(content, &state); err != nil {
		return state, fmt.Errorf("decode management firewall state: %w", err)
	}
	if state.Protocol != "tcp" || state.Port < 1 || state.Port > 65535 ||
		(state.Ownership != Owned && state.Ownership != Borrowed) {
		return state, errors.New("invalid management firewall state")
	}
	return state, nil
}

func writeManagementState(path string, state ManagementState) error {
	content, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".management-firewall-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

type System struct {
	Runner engine.Runner
	Lookup func(string) (string, error)
}

func (s System) Ensure(ctx context.Context, protocol string, port int) (Result, error) {
	if err := validateRule(protocol, port); err != nil {
		return Result{}, err
	}
	if s.Runner == nil {
		s.Runner = engine.ExecRunner{}
	}
	backend, err := s.Backend(ctx)
	if err != nil {
		return Result{}, err
	}
	switch backend {
	case BackendFirewalld:
		return s.firewalldEnsure(ctx, protocol, port)
	case BackendUFW:
		return s.ufwEnsure(ctx, protocol, port)
	default:
		return s.nftEnsure(ctx, protocol, port)
	}
}

func (s System) Backend(ctx context.Context) (string, error) {
	if s.Runner == nil {
		s.Runner = engine.ExecRunner{}
	}
	if s.firewalld(ctx) {
		return BackendFirewalld, nil
	}
	if s.ufw(ctx) {
		return BackendUFW, nil
	}
	if _, err := s.lookup("nft"); err != nil {
		return "", errors.New("no active firewalld, UFW, or nftables command is available")
	}
	return BackendNFTables, nil
}

func (s System) Close(ctx context.Context, protocol string, port int, backend string) error {
	if err := validateRule(protocol, port); err != nil {
		return err
	}
	if s.Runner == nil {
		s.Runner = engine.ExecRunner{}
	}
	switch backend {
	case BackendFirewalld:
		if _, err := s.lookup("firewall-cmd"); err != nil {
			return errors.New("cannot remove owned firewalld rule while firewall-cmd is unavailable")
		}
		return s.firewalldClose(ctx, protocol, port)
	case BackendUFW:
		if _, err := s.lookup("ufw"); err != nil {
			return errors.New("cannot remove owned UFW rule while ufw is unavailable")
		}
		return s.ufwClose(ctx, protocol, port)
	case BackendNFTables:
		return s.nftClose(ctx, protocol, port)
	case "", BackendUnknown:
		if s.firewalld(ctx) {
			return s.firewalldClose(ctx, protocol, port)
		}
		if s.ufw(ctx) {
			return s.ufwClose(ctx, protocol, port)
		}
		return s.nftClose(ctx, protocol, port)
	default:
		return fmt.Errorf("unsupported recorded firewall backend %q", backend)
	}
}

func (s System) firewalldEnsure(ctx context.Context, protocol string, port int) (Result, error) {
	changed := false
	output, err := s.Runner.Run(ctx, "firewall-cmd", "--permanent", "--get-policies")
	if err != nil {
		return Result{}, fmt.Errorf("inspect firewalld policies: %w: %s", err, output)
	}
	if !containsField(string(output), "jui") {
		if output, err = s.Runner.Run(ctx, "firewall-cmd", "--permanent", "--new-policy=jui"); err != nil {
			return Result{}, fmt.Errorf("create J-UI firewalld policy: %w: %s", err, output)
		}
		changed = true
	}
	for _, zone := range []struct {
		query string
		add   string
	}{
		{"--query-ingress-zone=ANY", "--add-ingress-zone=ANY"},
		{"--query-egress-zone=HOST", "--add-egress-zone=HOST"},
	} {
		if _, err = s.Runner.Run(ctx, "firewall-cmd", "--permanent", "--policy=jui", zone.query); err == nil {
			continue
		}
		if output, err = s.Runner.Run(ctx, "firewall-cmd", "--permanent", "--policy=jui", zone.add); err != nil {
			return Result{}, fmt.Errorf("configure J-UI firewalld policy zone: %w: %s", err, output)
		}
		changed = true
	}
	spec := fmt.Sprintf("%d/%s", port, protocol)
	if _, err = s.Runner.Run(ctx, "firewall-cmd", "--permanent", "--policy=jui", "--query-port="+spec); err != nil {
		if output, err = s.Runner.Run(ctx, "firewall-cmd", "--permanent", "--policy=jui", "--add-port="+spec); err != nil {
			return Result{}, fmt.Errorf("add J-UI firewalld policy port: %w: %s", err, output)
		}
		changed = true
	}
	if changed {
		if output, err := s.Runner.Run(ctx, "firewall-cmd", "--reload"); err != nil {
			return Result{}, fmt.Errorf("reload firewalld: %w: %s", err, output)
		}
	}
	return Result{Ownership: Owned, Backend: BackendFirewalld}, nil
}

func (s System) firewalldClose(ctx context.Context, protocol string, port int) error {
	output, err := s.Runner.Run(ctx, "firewall-cmd", "--permanent", "--get-policies")
	if err != nil {
		return fmt.Errorf("inspect firewalld policies: %w: %s", err, output)
	}
	if !containsField(string(output), "jui") {
		return nil
	}
	spec := fmt.Sprintf("%d/%s", port, protocol)
	if _, err = s.Runner.Run(ctx, "firewall-cmd", "--permanent", "--policy=jui", "--query-port="+spec); err != nil {
		return nil
	}
	if output, err = s.Runner.Run(ctx, "firewall-cmd", "--permanent", "--policy=jui", "--remove-port="+spec); err != nil {
		return fmt.Errorf("remove J-UI firewalld policy port: %w: %s", err, output)
	}
	if output, err = s.Runner.Run(ctx, "firewall-cmd", "--reload"); err != nil {
		return fmt.Errorf("reload firewalld: %w: %s", err, output)
	}
	return nil
}

func containsField(output, wanted string) bool {
	for _, field := range strings.Fields(output) {
		if field == wanted {
			return true
		}
	}
	return false
}

func (s System) ufwEnsure(ctx context.Context, protocol string, port int) (Result, error) {
	marker := ruleMarker(protocol, port)
	output, err := s.Runner.Run(ctx, "ufw", "status")
	if err != nil {
		return Result{}, fmt.Errorf("inspect UFW rules: %w: %s", err, output)
	}
	if ufwOutputHasMarker(string(output), marker) {
		return Result{Ownership: Owned, Backend: BackendUFW}, nil
	}
	matched, safelyBorrowed := ufwBorrowedRule(string(output), protocol, port)
	if safelyBorrowed {
		return Result{Ownership: Borrowed, Backend: BackendUFW}, nil
	}
	if matched {
		return Result{}, fmt.Errorf(
			"existing UFW rules for %d/%s do not provide an unambiguous global allow; refusing to overwrite them",
			port, protocol)
	}
	output, err = s.Runner.Run(ctx, "ufw", "allow", strconv.Itoa(port)+"/"+protocol, "comment", marker)
	if err != nil {
		return Result{}, fmt.Errorf("add owned UFW rule: %w: %s", err, output)
	}
	return Result{Ownership: Owned, Backend: BackendUFW}, nil
}

func ufwBorrowedRule(output, protocol string, port int) (matched, safelyBorrowed bool) {
	spec := strconv.Itoa(port) + "/" + protocol
	allProtocols := strconv.Itoa(port)
	hasIPv4Allow := false
	hasIPv6Allow := false
	for _, line := range strings.Split(output, "\n") {
		ipv6 := strings.Contains(line, "(v6)")
		rawFields := strings.Fields(strings.TrimSpace(line))
		fields := make([]string, 0, len(rawFields))
		for _, field := range rawFields {
			if field != "(v6)" {
				fields = append(fields, field)
			}
		}
		if len(fields) == 0 || (fields[0] != spec && fields[0] != allProtocols) {
			continue
		}
		matched = true
		if len(fields) < 3 || fields[1] != "ALLOW" {
			return true, false
		}
		sourceIndex := 2
		if fields[sourceIndex] == "IN" {
			sourceIndex++
		}
		if sourceIndex >= len(fields) || fields[sourceIndex] != "Anywhere" {
			return true, false
		}
		if ipv6 {
			hasIPv6Allow = true
		} else {
			hasIPv4Allow = true
		}
	}
	return matched, hasIPv4Allow && hasIPv6Allow
}

func (s System) ufwClose(ctx context.Context, protocol string, port int) error {
	marker := ruleMarker(protocol, port)
	output, err := s.Runner.Run(ctx, "ufw", "status", "numbered")
	if err != nil {
		return fmt.Errorf("inspect numbered UFW rules: %w: %s", err, output)
	}
	if strings.Contains(strings.ToLower(string(output)), "status: inactive") {
		return errors.New("cannot safely remove an owned UFW rule while UFW is inactive")
	}
	var numbers []int
	for _, line := range strings.Split(string(output), "\n") {
		if !ufwLineHasMarker(line, marker) {
			continue
		}
		closeBracket := strings.IndexByte(line, ']')
		openBracket := strings.IndexByte(line, '[')
		if openBracket < 0 || closeBracket <= openBracket {
			return fmt.Errorf("parse owned UFW rule number from %q", strings.TrimSpace(line))
		}
		number, parseErr := strconv.Atoi(strings.TrimSpace(line[openBracket+1 : closeBracket]))
		if parseErr != nil {
			return fmt.Errorf("parse owned UFW rule number: %w", parseErr)
		}
		numbers = append(numbers, number)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(numbers)))
	for _, number := range numbers {
		if output, err = s.Runner.Run(ctx, "ufw", "--force", "delete", strconv.Itoa(number)); err != nil {
			return fmt.Errorf("remove owned UFW rule %d: %w: %s", number, err, output)
		}
	}
	return nil
}

func ufwOutputHasMarker(output, marker string) bool {
	for _, line := range strings.Split(output, "\n") {
		if ufwLineHasMarker(line, marker) {
			return true
		}
	}
	return false
}

func ufwLineHasMarker(line, marker string) bool {
	needle := "# " + marker
	index := strings.Index(line, needle)
	if index < 0 {
		return false
	}
	after := line[index+len(needle):]
	return after == "" || after[0] == ' ' || after[0] == '\t'
}

func (s System) firewalld(ctx context.Context) bool {
	if _, err := s.lookup("firewall-cmd"); err != nil {
		return false
	}
	_, err := s.Runner.Run(ctx, "systemctl", "is-active", "--quiet", "firewalld")
	return err == nil
}

func (s System) ufw(ctx context.Context) bool {
	if _, err := s.lookup("ufw"); err != nil {
		return false
	}
	output, err := s.Runner.Run(ctx, "ufw", "status")
	return err == nil && strings.Contains(string(output), "Status: active")
}

func (s System) nftEnsure(ctx context.Context, protocol string, port int) (Result, error) {
	if _, err := s.lookup("nft"); err != nil {
		return Result{}, errors.New("no active firewalld, UFW, or nftables command is available")
	}
	marker := ruleMarker(protocol, port)
	ruleset, err := s.nftRuleset(ctx)
	if err != nil {
		return Result{}, err
	}
	dropChains, existing := nftDropInputChains(ruleset, marker)
	if len(dropChains) > 0 {
		args := make([]string, 0)
		for _, chain := range dropChains {
			if existing[chain] {
				continue
			}
			if len(args) > 0 {
				args = append(args, ";")
			}
			args = append(args, "insert", "rule", chain.Family, chain.Table, chain.Chain,
				protocol, "dport", strconv.Itoa(port), "accept", "comment", marker)
		}
		if len(args) == 0 {
			return Result{Ownership: Owned, Backend: BackendNFTables}, nil
		}
		if output, addErr := s.Runner.Run(ctx, "nft", args...); addErr != nil {
			return Result{}, fmt.Errorf("insert nftables rule into policy-drop input chain: %w: %s", addErr, output)
		}
		return Result{Ownership: Owned, Backend: BackendNFTables}, nil
	}
	if _, err := s.Runner.Run(ctx, "nft", "list", "table", "inet", "jui"); err != nil {
		if output, addErr := s.Runner.Run(ctx, "nft", "add", "table", "inet", "jui"); addErr != nil {
			return Result{}, fmt.Errorf("create nftables table: %w: %s", addErr, output)
		}
	}
	if _, err := s.Runner.Run(ctx, "nft", "list", "chain", "inet", "jui", "input"); err != nil {
		if output, addErr := s.Runner.Run(ctx, "nft", "add", "chain", "inet", "jui", "input",
			"{", "type", "filter", "hook", "input", "priority", "-5", ";", "}"); addErr != nil {
			return Result{}, fmt.Errorf("create nftables chain: %w: %s", addErr, output)
		}
	}
	comment := marker
	output, err := s.Runner.Run(ctx, "nft", "list", "chain", "inet", "jui", "input")
	if err != nil {
		return Result{}, fmt.Errorf("inspect nftables chain: %w: %s", err, output)
	}
	if strings.Contains(string(output), `comment "`+comment+`"`) {
		return Result{Ownership: Owned, Backend: BackendNFTables}, nil
	}
	output, err = s.Runner.Run(ctx, "nft", "add", "rule", "inet", "jui", "input",
		protocol, "dport", strconv.Itoa(port), "accept", "comment", comment)
	if err != nil {
		return Result{}, fmt.Errorf("add nftables rule: %w: %s", err, output)
	}
	return Result{Ownership: Owned, Backend: BackendNFTables}, nil
}

func ruleMarker(protocol string, port int) string {
	return fmt.Sprintf("jui-%s-%d", protocol, port)
}

func (s System) nftClose(ctx context.Context, protocol string, port int) error {
	if _, err := s.lookup("nft"); err != nil {
		return errors.New("no active firewalld, UFW, or nftables command is available")
	}
	ruleset, err := s.nftRuleset(ctx)
	if err != nil {
		return err
	}
	marker := ruleMarker(protocol, port)
	args := make([]string, 0)
	for _, object := range ruleset.Objects {
		if object.Rule == nil || object.Rule.Comment != marker || object.Rule.Handle < 1 {
			continue
		}
		if !validNFTReference(object.Rule.Family, object.Rule.Table, object.Rule.Chain) {
			return errors.New("invalid nftables rule reference")
		}
		if len(args) > 0 {
			args = append(args, ";")
		}
		args = append(args, "delete", "rule", object.Rule.Family, object.Rule.Table,
			object.Rule.Chain, "handle", strconv.Itoa(object.Rule.Handle))
	}
	if len(args) == 0 {
		return nil
	}
	output, err := s.Runner.Run(ctx, "nft", args...)
	if err != nil {
		return fmt.Errorf("delete owned nftables rules: %w: %s", err, output)
	}
	return nil
}

func (s System) nftRuleset(ctx context.Context) (nftRuleset, error) {
	var ruleset nftRuleset
	output, err := s.Runner.Run(ctx, "nft", "-j", "-a", "list", "ruleset")
	if err != nil {
		return ruleset, fmt.Errorf("inspect nftables ruleset: %w: %s", err, output)
	}
	if err := json.Unmarshal(output, &ruleset); err != nil {
		return ruleset, fmt.Errorf("decode nftables ruleset: %w", err)
	}
	return ruleset, nil
}

func nftDropInputChains(ruleset nftRuleset, marker string) ([]nftChainRef, map[nftChainRef]bool) {
	chains := make([]nftChainRef, 0)
	existing := make(map[nftChainRef]bool)
	for _, object := range ruleset.Objects {
		if object.Chain != nil && object.Chain.Hook == "input" && object.Chain.Policy == "drop" &&
			validNFTReference(object.Chain.Family, object.Chain.Table, object.Chain.Name) {
			chains = append(chains, nftChainRef{object.Chain.Family, object.Chain.Table, object.Chain.Name})
		}
		if object.Rule != nil && object.Rule.Comment == marker {
			existing[nftChainRef{object.Rule.Family, object.Rule.Table, object.Rule.Chain}] = true
		}
	}
	sort.Slice(chains, func(i, j int) bool {
		left, right := chains[i], chains[j]
		return left.Family+"/"+left.Table+"/"+left.Chain < right.Family+"/"+right.Table+"/"+right.Chain
	})
	return chains, existing
}

func validNFTReference(family, table, chain string) bool {
	if family != "inet" && family != "ip" && family != "ip6" {
		return false
	}
	return validNFTIdentifier(table) && validNFTIdentifier(chain)
}

func validNFTIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func (s System) lookup(name string) (string, error) {
	if s.Lookup != nil {
		return s.Lookup(name)
	}
	return exec.LookPath(name)
}

func validateRule(protocol string, port int) error {
	if protocol != "tcp" && protocol != "udp" {
		return fmt.Errorf("unsupported firewall protocol %q", protocol)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("firewall port %d is outside 1-65535", port)
	}
	return nil
}

type Mock struct{}

func (Mock) Backend(context.Context) (string, error) { return BackendNFTables, nil }
func (Mock) Ensure(context.Context, string, int) (Result, error) {
	return Result{Ownership: Owned, Backend: BackendNFTables}, nil
}
func (Mock) Close(context.Context, string, int, string) error { return nil }
