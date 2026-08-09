package netns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Suparluxi/j-ui/internal/model"
	"github.com/Suparluxi/j-ui/internal/socksbridge"
)

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type SystemRunner struct{}

func (SystemRunner) Run(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	allowed := map[string]bool{
		"ip": true, "nft": true, "sysctl": true, "systemctl": true, "systemd-run": true,
		"journalctl": true,
	}
	if !allowed[name] {
		return nil, fmt.Errorf("privileged command %q is not allowlisted", name)
	}
	output, err := exec.CommandContext(ctx, name, arguments...).CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s failed: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

type Orchestrator interface {
	Provision(context.Context, model.VPNGateExit, model.VPNGateCandidate, string, string, string) (string, error)
	Stop(context.Context, model.VPNGateExit) error
	Healthy(context.Context, model.VPNGateExit) bool
}

type Manager struct {
	Runner     Runner
	DataDir    string
	Executable string
}

func New(dataDir string) (*Manager, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return &Manager{Runner: SystemRunner{}, DataDir: dataDir, Executable: executable}, nil
}

func (m *Manager) Provision(
	ctx context.Context,
	exit model.VPNGateExit,
	candidate model.VPNGateCandidate,
	sanitizedConfig, username, password string,
) (string, error) {
	spec, err := slotSpec(exit.Slot)
	if err != nil {
		return "", err
	}
	if exit.Namespace != spec.namespace || exit.LocalAddress != spec.peerAddress ||
		exit.LocalPort != 1080 || candidate.IP != exit.CandidateIP {
		return "", errors.New("VPNGate slot metadata is inconsistent")
	}
	if username == "" || password == "" {
		return "", errors.New("VPNGate bridge credentials are required")
	}
	if err := m.Stop(ctx, exit); err != nil {
		return "", fmt.Errorf("clean previous VPNGate slot state: %w", err)
	}
	directory := filepath.Join(m.DataDir, "vpngate", "slot-"+strconv.Itoa(exit.Slot))
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", err
	}
	openVPNPath := filepath.Join(directory, "client.ovpn")
	bridgePath := filepath.Join(directory, "bridge.json")
	if err := atomicWrite(openVPNPath, []byte(sanitizedConfig)); err != nil {
		return "", err
	}
	if err := socksbridge.WriteConfig(bridgePath, socksbridge.Config{
		Listen:   net.JoinHostPort(spec.peerAddress, "1080"),
		Username: username, Password: password, MaxConnections: 128,
	}); err != nil {
		return "", err
	}
	remoteProtocol := "udp"
	if exit.RemoteProtocol == "tcp-client" {
		remoteProtocol = "tcp"
	}
	rollback := func(primary error) (string, error) {
		return "", errors.Join(primary, m.Stop(context.WithoutCancel(ctx), exit))
	}
	commands := [][]string{
		{"sysctl", "-w", "net.ipv4.ip_forward=1"},
		{"ip", "netns", "add", spec.namespace},
		{"ip", "link", "add", spec.hostVeth, "type", "veth", "peer", "name", spec.peerVeth},
		{"ip", "link", "set", spec.peerVeth, "netns", spec.namespace},
		{"ip", "addr", "add", spec.hostCIDR, "dev", spec.hostVeth},
		{"ip", "link", "set", spec.hostVeth, "up"},
		{"ip", "netns", "exec", spec.namespace, "ip", "link", "set", "lo", "up"},
		{"ip", "netns", "exec", spec.namespace, "ip", "addr", "add", spec.peerCIDR, "dev", spec.peerVeth},
		{"ip", "netns", "exec", spec.namespace, "ip", "link", "set", spec.peerVeth, "up"},
		{"ip", "netns", "exec", spec.namespace, "ip", "route", "add", "default", "via", spec.hostAddress, "dev", spec.peerVeth},
	}
	for _, command := range commands {
		if _, err := m.runPrivileged(ctx, command...); err != nil {
			return rollback(err)
		}
	}
	if err := m.installHostFirewall(ctx, spec, candidate.IP, remoteProtocol, exit.RemotePort); err != nil {
		return rollback(err)
	}
	if err := m.installHostForwardCompatibility(ctx, spec, candidate.IP, remoteProtocol, exit.RemotePort); err != nil {
		return rollback(err)
	}
	if err := m.installNamespaceFirewall(ctx, spec, candidate.IP, remoteProtocol, exit.RemotePort); err != nil {
		return rollback(err)
	}
	if err := m.startUnit(ctx, openVPNUnit(exit.Slot), []string{
		"ip", "netns", "exec", spec.namespace, "openvpn",
		"--config", openVPNPath, "--auth-nocache", "--script-security", "1",
	}); err != nil {
		return rollback(err)
	}
	if err := m.waitForTunnel(ctx, spec.namespace, openVPNUnit(exit.Slot)); err != nil {
		return rollback(err)
	}
	if err := m.startUnit(ctx, bridgeUnit(exit.Slot), []string{
		"ip", "netns", "exec", spec.namespace, m.Executable,
		"internal-socks-bridge", bridgePath,
	}); err != nil {
		return rollback(err)
	}
	ip, err := m.probe(ctx, spec.namespace)
	if err != nil {
		return rollback(err)
	}
	return ip, nil
}

func (m *Manager) Stop(ctx context.Context, exit model.VPNGateExit) error {
	spec, err := slotSpec(exit.Slot)
	if err != nil {
		return err
	}
	var failures []error
	if err := m.removeHostForwardCompatibility(ctx, spec); err != nil {
		failures = append(failures, err)
	}
	for _, unit := range []string{bridgeUnit(exit.Slot), openVPNUnit(exit.Slot)} {
		if _, err := m.Runner.Run(ctx, "systemctl", "stop", unit); err != nil &&
			!cleanupTargetMissing(err) {
			failures = append(failures, err)
		}
		_, _ = m.Runner.Run(ctx, "systemctl", "reset-failed", unit)
	}
	for _, command := range [][]string{
		{"ip", "netns", "delete", spec.namespace},
		{"ip", "link", "delete", spec.hostVeth},
		{"nft", "delete", "table", "ip", spec.hostTable},
	} {
		if _, err := m.runPrivileged(ctx, command...); err != nil && !cleanupTargetMissing(err) {
			failures = append(failures, err)
		}
	}
	directory := filepath.Join(m.DataDir, "vpngate", "slot-"+strconv.Itoa(exit.Slot))
	if err := os.RemoveAll(directory); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func cleanupTargetMissing(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, fragment := range []string{
		"not loaded",
		"not found",
		"no such file",
		"cannot find device",
		"does not exist",
	} {
		if strings.Contains(message, fragment) {
			return true
		}
	}
	return false
}

func (m *Manager) Healthy(ctx context.Context, exit model.VPNGateExit) bool {
	if exit.Status != "running" {
		return false
	}
	if _, err := m.Runner.Run(ctx, "systemctl", "is-active", "--quiet", openVPNUnit(exit.Slot)); err != nil {
		return false
	}
	if _, err := m.Runner.Run(ctx, "systemctl", "is-active", "--quiet", bridgeUnit(exit.Slot)); err != nil {
		return false
	}
	if _, err := m.runPrivileged(ctx, "ip", "netns", "exec", exit.Namespace, "ip", "link", "show", "dev", "tun0"); err != nil {
		return false
	}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	observed, err := m.probeEndpoint(probeCtx, exit.Namespace, "https://api64.ipify.org?format=json")
	return err == nil && observed == exit.ObservedIP
}

func (m *Manager) startUnit(ctx context.Context, unit string, command []string) error {
	_, _ = m.Runner.Run(ctx, "systemctl", "stop", unit)
	arguments := []string{
		"--unit=" + unit, "--collect", "--property=Type=simple",
		"--property=Restart=on-failure", "--property=RestartSec=3s",
		"--property=PrivateTmp=yes", "--property=ProtectSystem=strict",
		"--property=ProtectHome=yes", "--property=NoNewPrivileges=yes",
		"--property=CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN",
		"--property=DeviceAllow=/dev/net/tun rw", "--",
	}
	arguments = append(arguments, command...)
	_, err := m.Runner.Run(ctx, "systemd-run", arguments...)
	return err
}

func (m *Manager) waitForTunnel(ctx context.Context, namespace, unit string) error {
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := m.runPrivileged(ctx, "ip", "netns", "exec", namespace, "ip", "link", "show", "dev", "tun0"); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	diagnostics := m.unitDiagnostics(ctx, unit)
	if diagnostics == "" {
		return errors.New("OpenVPN did not create tun0 within 25 seconds")
	}
	return fmt.Errorf("OpenVPN did not create tun0 within 25 seconds: %s", diagnostics)
}

func (m *Manager) unitDiagnostics(ctx context.Context, unit string) string {
	output, err := m.Runner.Run(ctx, "journalctl", "--unit", unit, "--no-pager", "--lines=20")
	if err != nil && len(output) == 0 {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func (m *Manager) probe(ctx context.Context, namespace string) (string, error) {
	endpoints := []string{
		"https://api64.ipify.org?format=json",
		"https://ifconfig.co/json",
	}
	var observed string
	for _, endpoint := range endpoints {
		current, err := m.probeEndpoint(ctx, namespace, endpoint)
		if err != nil {
			return "", err
		}
		if observed != "" && observed != current {
			return "", errors.New("exit identity services returned different IP addresses")
		}
		observed = current
	}
	return observed, nil
}

func (m *Manager) probeEndpoint(ctx context.Context, namespace, endpoint string) (string, error) {
	output, err := m.runPrivileged(
		ctx, "ip", "netns", "exec", namespace, m.Executable, "internal-probe", endpoint,
	)
	if err != nil {
		return "", err
	}
	var response struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal(output, &response); err != nil || net.ParseIP(response.IP) == nil {
		return "", errors.New("exit identity service returned an invalid response")
	}
	return response.IP, nil
}

func (m *Manager) installHostFirewall(
	ctx context.Context, spec specification, remoteIP, protocol string, port int,
) error {
	commands := [][]string{
		{"nft", "add", "table", "ip", spec.hostTable},
		{"nft", "add", "chain", "ip", spec.hostTable, "forward",
			"{", "type", "filter", "hook", "forward", "priority", "-5", ";", "policy", "accept", ";", "}"},
		{"nft", "add", "rule", "ip", spec.hostTable, "forward",
			"iifname", spec.hostVeth, "ip", "daddr", remoteIP, protocol, "dport", strconv.Itoa(port), "accept"},
		{"nft", "add", "rule", "ip", spec.hostTable, "forward",
			"oifname", spec.hostVeth, "ct", "state", "established,related", "accept"},
		{"nft", "add", "rule", "ip", spec.hostTable, "forward",
			"iifname", spec.hostVeth, "reject"},
		{"nft", "add", "chain", "ip", spec.hostTable, "postrouting",
			"{", "type", "nat", "hook", "postrouting", "priority", "srcnat", ";", "policy", "accept", ";", "}"},
		{"nft", "add", "rule", "ip", spec.hostTable, "postrouting",
			"ip", "saddr", spec.subnetCIDR, "ip", "daddr", remoteIP, "masquerade"},
	}
	for _, command := range commands {
		if _, err := m.runPrivileged(ctx, command...); err != nil {
			return err
		}
	}
	return nil
}

type nftRuleset struct {
	NFTables []struct {
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

func (m *Manager) nftRules(ctx context.Context) (nftRuleset, error) {
	output, err := m.Runner.Run(ctx, "nft", "-j", "list", "ruleset")
	if err != nil {
		return nftRuleset{}, err
	}
	if len(strings.TrimSpace(string(output))) == 0 {
		return nftRuleset{}, nil
	}
	var rules nftRuleset
	if err := json.Unmarshal(output, &rules); err != nil {
		return nftRuleset{}, fmt.Errorf("decode nftables ruleset: %w", err)
	}
	return rules, nil
}

func (m *Manager) installHostForwardCompatibility(
	ctx context.Context, spec specification, remoteIP, protocol string, port int,
) error {
	ruleset, err := m.nftRules(ctx)
	if err != nil {
		return err
	}
	for _, entry := range ruleset.NFTables {
		chain := entry.Chain
		if chain == nil || chain.Hook != "forward" || chain.Policy != "drop" ||
			(chain.Family != "ip" && chain.Family != "inet") || chain.Table == spec.hostTable {
			continue
		}
		commands := [][]string{
			{"nft", "insert", "rule", chain.Family, chain.Table, chain.Name,
				"iifname", spec.hostVeth, "ip", "daddr", remoteIP, protocol, "dport", strconv.Itoa(port),
				"accept", "comment", forwardComment(spec, "out")},
			{"nft", "insert", "rule", chain.Family, chain.Table, chain.Name,
				"oifname", spec.hostVeth, "ct", "state", "established,related",
				"accept", "comment", forwardComment(spec, "in")},
		}
		for _, command := range commands {
			if _, err := m.runPrivileged(ctx, command...); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *Manager) removeHostForwardCompatibility(ctx context.Context, spec specification) error {
	ruleset, err := m.nftRules(ctx)
	if err != nil {
		return err
	}
	var failures []error
	for _, entry := range ruleset.NFTables {
		rule := entry.Rule
		if rule == nil || (rule.Comment != forwardComment(spec, "out") && rule.Comment != forwardComment(spec, "in")) {
			continue
		}
		if _, err := m.runPrivileged(ctx, "nft", "delete", "rule", rule.Family, rule.Table, rule.Chain,
			"handle", strconv.Itoa(rule.Handle)); err != nil && !cleanupTargetMissing(err) {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func forwardComment(spec specification, direction string) string {
	return spec.namespace + "-forward-" + direction
}

func (m *Manager) installNamespaceFirewall(
	ctx context.Context, spec specification, remoteIP, protocol string, port int,
) error {
	prefix := []string{"netns", "exec", spec.namespace, "nft"}
	commands := [][]string{
		{"add", "table", "inet", "jui"},
		{"add", "chain", "inet", "jui", "input",
			"{", "type", "filter", "hook", "input", "priority", "-100", ";", "policy", "drop", ";", "}"},
		{"add", "rule", "inet", "jui", "input", "iifname", "lo", "accept"},
		{"add", "rule", "inet", "jui", "input", "ct", "state", "established,related", "accept"},
		{"add", "rule", "inet", "jui", "input", "iifname", spec.peerVeth,
			"ip", "saddr", spec.hostAddress, "tcp", "dport", "1080", "accept"},
		{"add", "chain", "inet", "jui", "output",
			"{", "type", "filter", "hook", "output", "priority", "-100", ";", "policy", "drop", ";", "}"},
		{"add", "rule", "inet", "jui", "output", "oifname", "lo", "accept"},
		{"add", "rule", "inet", "jui", "output", "ct", "state", "established,related", "accept"},
		{"add", "rule", "inet", "jui", "output", "oifname", "tun0", "accept"},
		{"add", "rule", "inet", "jui", "output", "oifname", spec.peerVeth,
			"ip", "daddr", spec.hostAddress, "accept"},
		{"add", "rule", "inet", "jui", "output", "oifname", spec.peerVeth,
			"ip", "daddr", remoteIP, protocol, "dport", strconv.Itoa(port), "accept"},
	}
	for _, command := range commands {
		arguments := append(append([]string{"ip"}, prefix...), command...)
		if _, err := m.runPrivileged(ctx, arguments...); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) runPrivileged(ctx context.Context, command ...string) ([]byte, error) {
	if len(command) == 0 {
		return nil, errors.New("empty privileged command")
	}
	arguments := []string{
		"--wait", "--pipe", "--collect", "--quiet",
		"--property=Type=oneshot",
		"--property=CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN",
		"--property=DeviceAllow=/dev/net/tun rw",
		"--",
	}
	arguments = append(arguments, command...)
	return m.Runner.Run(ctx, "systemd-run", arguments...)
}

type specification struct {
	namespace, hostVeth, peerVeth, hostTable string
	subnetCIDR, hostCIDR, peerCIDR           string
	hostAddress, peerAddress                 string
}

func slotSpec(slot int) (specification, error) {
	if slot < 1 || slot > 5 {
		return specification{}, errors.New("VPNGate slot must be between 1 and 5")
	}
	prefix := "10.254." + strconv.Itoa(slot)
	return specification{
		namespace: "jui-vpn-" + strconv.Itoa(slot),
		hostVeth:  "jvh" + strconv.Itoa(slot), peerVeth: "jvn" + strconv.Itoa(slot),
		hostTable:  "jui_vpn_" + strconv.Itoa(slot),
		subnetCIDR: prefix + ".0/30", hostCIDR: prefix + ".1/30", peerCIDR: prefix + ".2/30",
		hostAddress: prefix + ".1", peerAddress: prefix + ".2",
	}, nil
}

func openVPNUnit(slot int) string {
	return "jui-vpngate-" + strconv.Itoa(slot) + "-openvpn.service"
}

func bridgeUnit(slot int) string {
	return "jui-vpngate-" + strconv.Itoa(slot) + "-bridge.service"
}

func atomicWrite(path string, content []byte) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, content, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(temporary, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

type Mock struct{}

func (Mock) Provision(
	_ context.Context, _ model.VPNGateExit, candidate model.VPNGateCandidate,
	_, _, _ string,
) (string, error) {
	return candidate.IP, nil
}

func (Mock) Stop(context.Context, model.VPNGateExit) error {
	return nil
}

func (Mock) Healthy(context.Context, model.VPNGateExit) bool {
	return true
}
