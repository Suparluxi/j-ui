package netns

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Suparluxi/j-ui/internal/model"
)

type recordingRunner struct {
	commands []string
	failOn   string
	nftJSON  string
}

func (r *recordingRunner) Run(_ context.Context, name string, arguments ...string) ([]byte, error) {
	command := name + " " + strings.Join(arguments, " ")
	r.commands = append(r.commands, command)
	if r.failOn != "" && strings.Contains(command, r.failOn) {
		return nil, errors.New("injected failure")
	}
	if strings.Contains(command, "nft -j list ruleset") {
		return []byte(r.nftJSON), nil
	}
	if strings.Contains(command, "internal-probe") {
		return []byte(`{"ip":"203.0.113.8"}`), nil
	}
	return nil, nil
}

func TestForwardDropPolicyGetsScopedCompatibilityRules(t *testing.T) {
	runner := &recordingRunner{nftJSON: `{"nftables":[
		{"chain":{"family":"inet","table":"filter","name":"forward","hook":"forward","policy":"drop"}},
		{"chain":{"family":"ip","table":"other","name":"pass","hook":"forward","policy":"accept"}}
	]}`}
	manager := &Manager{Runner: runner, DataDir: t.TempDir(), Executable: "/usr/local/bin/j-ui"}
	spec, _ := slotSpec(1)
	if err := manager.installHostForwardCompatibility(
		context.Background(), spec, "198.51.100.8", "udp", 1194,
	); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	for _, expected := range []string{
		"nft insert rule inet filter forward iifname jvh1 ip daddr 198.51.100.8 udp dport 1194 accept comment jui-vpn-1-forward-out",
		"nft insert rule inet filter forward oifname jvh1 ct state established,related accept comment jui-vpn-1-forward-in",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("missing compatibility rule %q:\n%s", expected, joined)
		}
	}
	if strings.Contains(joined, "ip other pass") {
		t.Fatalf("modified accept-policy chain:\n%s", joined)
	}
}

func TestStopRemovesScopedCompatibilityRules(t *testing.T) {
	runner := &recordingRunner{nftJSON: `{"nftables":[
		{"rule":{"family":"inet","table":"filter","chain":"forward","handle":42,"comment":"jui-vpn-1-forward-out"}},
		{"rule":{"family":"inet","table":"filter","chain":"forward","handle":43,"comment":"unrelated"}}
	]}`}
	manager := &Manager{Runner: runner, DataDir: t.TempDir(), Executable: "/usr/local/bin/j-ui"}
	if err := manager.Stop(context.Background(), model.VPNGateExit{Slot: 1}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	if !strings.Contains(joined, "nft delete rule inet filter forward handle 42") ||
		strings.Contains(joined, "handle 43") {
		t.Fatalf("unexpected compatibility cleanup:\n%s", joined)
	}
}

func TestStopReportsUnexpectedCleanupFailure(t *testing.T) {
	runner := &recordingRunner{failOn: "ip netns delete jui-vpn-1"}
	manager := &Manager{
		Runner: runner, DataDir: t.TempDir(), Executable: "/usr/local/bin/j-ui",
	}
	err := manager.Stop(context.Background(), model.VPNGateExit{Slot: 1})
	if err == nil || !strings.Contains(err.Error(), "injected failure") {
		t.Fatalf("cleanup error = %v", err)
	}
}

func TestCleanupTargetMissingIsIdempotent(t *testing.T) {
	for _, message := range []string{
		"Unit is not loaded",
		"Cannot find device",
		"No such file or directory",
		"table does not exist",
	} {
		if !cleanupTargetMissing(errors.New(message)) {
			t.Fatalf("missing target error was not ignored: %s", message)
		}
	}
	if cleanupTargetMissing(errors.New("permission denied")) {
		t.Fatal("unexpected cleanup failure was ignored")
	}
}

func TestSlotSpecUsesStableIsolatedAddresses(t *testing.T) {
	first, err := slotSpec(1)
	if err != nil {
		t.Fatal(err)
	}
	fifth, err := slotSpec(5)
	if err != nil {
		t.Fatal(err)
	}
	if first.namespace != "jui-vpn-1" || first.peerAddress != "10.254.1.2" ||
		fifth.hostTable != "jui_vpn_5" || fifth.peerAddress != "10.254.5.2" {
		t.Fatalf("slot specs = %#v %#v", first, fifth)
	}
	if _, err := slotSpec(6); err == nil {
		t.Fatal("accepted slot above maximum")
	}
}

func TestProvisionFailureRunsCleanup(t *testing.T) {
	runner := &recordingRunner{failOn: "nft add table ip jui_vpn_1"}
	manager := &Manager{
		Runner: runner, DataDir: t.TempDir(), Executable: "/usr/local/bin/j-ui",
	}
	exit := model.VPNGateExit{
		Slot: 1, Namespace: "jui-vpn-1", LocalAddress: "10.254.1.2",
		LocalPort: 1080, CandidateIP: "198.51.100.8", RemoteProtocol: "udp", RemotePort: 1194,
	}
	_, err := manager.Provision(
		context.Background(), exit,
		model.VPNGateCandidate{IP: "198.51.100.8"}, "client\n", "user", "password",
	)
	if err == nil {
		t.Fatal("expected injected provisioning failure")
	}
	joined := strings.Join(runner.commands, "\n")
	for _, expected := range []string{
		"systemctl stop jui-vpngate-1-openvpn.service",
		"systemd-run --wait --pipe --collect --quiet",
		"ip netns delete jui-vpn-1",
		"nft delete table ip jui_vpn_1",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("cleanup lacks %q:\n%s", expected, joined)
		}
	}
}

func TestProvisionRefusesToReuseSlotAfterCleanupFailure(t *testing.T) {
	runner := &recordingRunner{failOn: "ip netns delete jui-vpn-1"}
	manager := &Manager{
		Runner: runner, DataDir: t.TempDir(), Executable: "/usr/local/bin/j-ui",
	}
	exit := model.VPNGateExit{
		Slot: 1, Namespace: "jui-vpn-1", LocalAddress: "10.254.1.2",
		LocalPort: 1080, CandidateIP: "198.51.100.8",
	}
	if _, err := manager.Provision(
		context.Background(), exit,
		model.VPNGateCandidate{IP: "198.51.100.8"}, "client\n", "user", "password",
	); err == nil {
		t.Fatal("provision reused a slot after cleanup failure")
	}
	joined := strings.Join(runner.commands, "\n")
	if strings.Contains(joined, "ip netns add jui-vpn-1") {
		t.Fatalf("provision continued after cleanup failure:\n%s", joined)
	}
}

func TestHealthyRequiresMatchingLiveExitIdentity(t *testing.T) {
	runner := &recordingRunner{}
	manager := &Manager{
		Runner: runner, DataDir: t.TempDir(), Executable: "/usr/local/bin/j-ui",
	}
	exit := model.VPNGateExit{
		Slot: 1, Namespace: "jui-vpn-1", Status: "running",
		ObservedIP: "203.0.113.8",
	}
	if !manager.Healthy(context.Background(), exit) {
		t.Fatal("healthy exit with matching live identity was rejected")
	}
	exit.ObservedIP = "203.0.113.9"
	if manager.Healthy(context.Background(), exit) {
		t.Fatal("exit with changed live identity was considered healthy")
	}
}
