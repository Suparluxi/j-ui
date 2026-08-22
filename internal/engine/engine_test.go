package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type rollbackRunner struct {
	reloadCalls int
}

type countingRunner struct {
	actionCalls int
}

type removeCandidateRunner struct{}

type cancelOnReloadRunner struct {
	cancel context.CancelFunc
}

type deadlineReloadRunner struct {
	reloads int
}

func (r *deadlineReloadRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "systemctl" && len(args) > 0 && args[0] == "reload" {
		r.reloads++
		if r.reloads == 1 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
	}
	return nil, nil
}

func (r cancelOnReloadRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name == "systemctl" && len(args) > 0 && args[0] == "reload" {
		r.cancel()
	}
	return nil, nil
}

func (removeCandidateRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name == "sing-box" && len(args) == 3 && args[0] == "check" {
		return nil, os.Remove(args[2])
	}
	return nil, nil
}

type bulkStatusRunner struct {
	showCalls int
	ssCalls   int
}

type samePortStatusRunner struct{}

type startIfInactiveRunner struct {
	calls  []string
	active bool
}

func (r *startIfInactiveRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name != "systemctl" || len(args) == 0 {
		return nil, nil
	}
	r.calls = append(r.calls, strings.Join(args, " "))
	switch args[0] {
	case "is-active":
		if !r.active {
			return nil, errors.New("inactive")
		}
	case "start":
		r.active = true
	case "reload":
		return nil, errors.New("reload should not be used for an inactive dedicated unit")
	}
	return nil, nil
}

func (samePortStatusRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name == "systemctl" && len(args) > 0 && args[0] == "show" {
		return []byte("42\n"), nil
	}
	if name == "ss" {
		return []byte(
			`tcp LISTEN 0 4096 127.0.0.1:1080 0.0.0.0:* users:(("sing-box",pid=42,fd=7))` + "\n",
		), nil
	}
	return nil, nil
}

type recoverIdenticalRunner struct {
	restartCalls int
}

func (r *recoverIdenticalRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name == "systemctl" && len(args) > 0 {
		switch args[0] {
		case "restart":
			r.restartCalls++
			return nil, nil
		case "is-active":
			if r.restartCalls == 0 {
				return nil, errors.New("inactive")
			}
		}
	}
	return nil, nil
}

func (r *bulkStatusRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name == "systemctl" && len(args) > 0 && args[0] == "show" {
		r.showCalls++
		return []byte("42\n"), nil
	}
	if name == "ss" {
		r.ssCalls++
		var output strings.Builder
		for port := 20000; port < 20100; port++ {
			fmt.Fprintf(&output,
				"tcp LISTEN 0 4096 0.0.0.0:%d 0.0.0.0:* users:((\"sing-box\",pid=42,fd=7))\n",
				port)
		}
		return []byte(output.String()), nil
	}
	return nil, nil
}

func (r *countingRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name == "systemctl" && len(args) != 0 && (args[0] == "restart" || args[0] == "reload") {
		r.actionCalls++
	}
	return nil, nil
}

func TestListenersHealthyChecksTCPAndUDPBindings(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	udpListener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpListener.Close()
	listeners := []Listener{
		{Network: "tcp", Host: "127.0.0.1", Port: tcpListener.Addr().(*net.TCPAddr).Port},
		{Network: "udp", Host: "127.0.0.1", Port: udpListener.LocalAddr().(*net.UDPAddr).Port},
	}
	if err := listenersHealthy(context.Background(), listeners); err != nil {
		t.Fatalf("bound listeners reported unhealthy: %v", err)
	}
	if err := tcpListener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := listenersHealthy(context.Background(), listeners); err == nil {
		t.Fatal("unbound TCP listener reported healthy")
	}
}

func TestExecRunnerForcesCLocale(t *testing.T) {
	t.Setenv("LC_ALL", "zh_CN.UTF-8")
	output, err := (ExecRunner{}).Run(context.Background(), "env")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(output), "LC_ALL=C\n") {
		t.Fatalf("environment does not contain forced C locale:\n%s", output)
	}
}

func (r *rollbackRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name == "systemctl" && len(args) != 0 && args[0] == "reload" {
		r.reloadCalls++
		if r.reloadCalls == 1 {
			return []byte("reload rejected"), errors.New("reload failed")
		}
	}
	return nil, nil
}

func TestApplyRollsBackReloadFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sing-box.json")
	if err := os.WriteFile(path, []byte(`{"inbounds":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	system := &System{Binary: "sing-box", ConfigPath: path, Runner: &rollbackRunner{}}
	err := system.Apply(context.Background(), []byte("candidate"), nil)
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("Apply error = %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != `{"inbounds":[]}` {
		t.Fatalf("config = %q, want previous document", content)
	}
}

func TestApplyRollbackGetsFreshDeadlineAfterReloadTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sing-box.json")
	if err := os.WriteFile(path, []byte(`{"inbounds":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &deadlineReloadRunner{}
	system := &System{
		Binary: "sing-box", ConfigPath: path, Runner: runner,
		CommitTimeout: 20 * time.Millisecond,
	}
	err := system.Apply(context.Background(), []byte("candidate"), nil)
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("Apply error = %v", err)
	}
	content, readErr := os.ReadFile(path)
	if readErr != nil || string(content) != `{"inbounds":[]}` {
		t.Fatalf("config=%q err=%v", content, readErr)
	}
	if runner.reloads != 2 {
		t.Fatalf("reload calls = %d, want timed-out primary plus rollback", runner.reloads)
	}
}

func TestApplyIdenticalConfigDoesNotRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sing-box.json")
	if err := os.WriteFile(path, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &countingRunner{}
	system := &System{Binary: "sing-box", ConfigPath: path, Runner: runner}
	if err := system.Apply(context.Background(), []byte("unchanged"), nil); err != nil {
		t.Fatal(err)
	}
	if runner.actionCalls != 0 {
		t.Fatalf("reload/restart calls = %d, want 0", runner.actionCalls)
	}
}

func TestApplyIdenticalConfigRestartsUnhealthyRuntime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sing-box.json")
	if err := os.WriteFile(path, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &recoverIdenticalRunner{}
	system := &System{Binary: "sing-box", ConfigPath: path, Runner: runner}
	if err := system.Apply(context.Background(), []byte("unchanged"), nil); err != nil {
		t.Fatal(err)
	}
	if runner.restartCalls != 1 {
		t.Fatalf("restart calls = %d, want 1", runner.restartCalls)
	}
}

func TestDedicatedRuntimeStartsBeforeReloadWhenInactive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "residential.json")
	runner := &startIfInactiveRunner{}
	system := &System{
		Binary:          "sing-box",
		ConfigPath:      path,
		ServiceUnit:     "j-ui-residential@7.service",
		StartIfInactive: true,
		Runner:          runner,
		ListenerChecker: func(context.Context, []Listener) error { return nil },
	}
	if err := system.Apply(context.Background(), []byte(`{"inbounds":[]}`), nil); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.calls, "|")
	if !strings.Contains(joined, "start j-ui-residential@7.service") {
		t.Fatalf("dedicated unit was not started: %s", joined)
	}
	if strings.Contains(joined, "reload j-ui-residential@7.service") {
		t.Fatalf("dedicated inactive unit was reloaded: %s", joined)
	}
}

func TestApplyPreservesPreviousOnAtomicReplaceFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sing-box.json")
	if err := os.WriteFile(path, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	system := &System{Binary: "sing-box", ConfigPath: path, Runner: removeCandidateRunner{}}
	if err := system.Apply(context.Background(), []byte("candidate"), nil); err == nil {
		t.Fatal("Apply succeeded after candidate was removed before atomic replace")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "previous" {
		t.Fatalf("config = %q, want previous", content)
	}
}

func TestApplyRollsBackListenerFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sing-box.json")
	if err := os.WriteFile(path, []byte(`{"inbounds":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	system := &System{
		Binary:     "sing-box",
		ConfigPath: path,
		Runner:     &rollbackRunner{reloadCalls: 1},
		ListenerChecker: func(context.Context, []Listener) error {
			return errors.New("listener missing")
		},
	}
	err := system.Apply(context.Background(), []byte("candidate"), []Listener{{Network: "tcp", Host: "127.0.0.1", Port: 443}})
	if err == nil || !strings.Contains(err.Error(), "listener health check failed") {
		t.Fatalf("Apply error = %v", err)
	}
	content, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(content) != `{"inbounds":[]}` {
		t.Fatalf("config = %q, want previous document", content)
	}
}

func TestApplyCompletesAfterCallerCancelsPostReplace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sing-box.json")
	if err := os.WriteFile(path, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	listenerChecked := false
	system := &System{
		Binary: "sing-box", ConfigPath: path,
		Runner: cancelOnReloadRunner{cancel: cancel},
		ListenerChecker: func(checkCtx context.Context, _ []Listener) error {
			listenerChecked = true
			return checkCtx.Err()
		},
	}
	if err := system.Apply(ctx, []byte("candidate"), nil); err != nil {
		t.Fatal(err)
	}
	if !listenerChecked || ctx.Err() == nil {
		t.Fatalf("listenerChecked=%t callerErr=%v", listenerChecked, ctx.Err())
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "candidate" {
		t.Fatalf("config=%q err=%v", content, err)
	}
}

func TestSocketOwnerRequiresExactMainPID(t *testing.T) {
	line := `tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("sing-box",pid=1234,fd=7))`
	if !socketOwnedByPID(line, 1234) {
		t.Fatal("exact MainPID was not recognized")
	}
	if socketOwnedByPID(line, 123) {
		t.Fatal("PID prefix was incorrectly accepted")
	}
}

func TestBulkListenerStatusUsesOneProcessSnapshot(t *testing.T) {
	runner := &bulkStatusRunner{}
	system := &System{Runner: runner}
	listeners := make([]Listener, 100)
	for index := range listeners {
		listeners[index] = Listener{Network: "tcp", Port: 20000 + index}
	}
	statuses, err := system.ListenerStatuses(context.Background(), listeners)
	if err != nil {
		t.Fatal(err)
	}
	for index, status := range statuses {
		if !status {
			t.Fatalf("listener %d reported unhealthy", index)
		}
	}
	if runner.showCalls != 1 || runner.ssCalls != 1 {
		t.Fatalf("command calls show=%d ss=%d, want one each", runner.showCalls, runner.ssCalls)
	}
}

func TestListenerStatusDistinguishesSamePortOnDifferentHosts(t *testing.T) {
	system := &System{Runner: samePortStatusRunner{}}
	statuses, err := system.ListenerStatuses(context.Background(), []Listener{
		{Network: "tcp", Host: "127.0.0.1", Port: 1080},
		{Network: "tcp", Host: "127.0.0.2", Port: 1080},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 2 || !statuses[0] || statuses[1] {
		t.Fatalf("listener statuses = %#v", statuses)
	}
}

func TestWildcardSocketMatchesOnlyItsAddressFamily(t *testing.T) {
	if !socketHostMatches("0.0.0.0:443", "127.0.0.2") {
		t.Fatal("IPv4 wildcard did not match an IPv4 listener")
	}
	if socketHostMatches("0.0.0.0:443", "::1") {
		t.Fatal("IPv4 wildcard matched an IPv6 listener")
	}
	if !socketHostMatches("[::]:443", "2001:db8::1") {
		t.Fatal("IPv6 wildcard did not match an IPv6 listener")
	}
	if socketHostMatches("*:443", "127.0.0.1") ||
		socketHostMatches("*:443", "0.0.0.0") ||
		!socketHostMatches("*:443", "::1") {
		t.Fatal("ss star wildcard was not treated as IPv6")
	}
}

func TestRollbackReportsMissingPreviousListener(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sing-box.json")
	previous := `{"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":1080}]}`
	if err := os.WriteFile(path, []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}
	system := &System{
		Binary: "sing-box", ConfigPath: path, Runner: &rollbackRunner{},
		RollbackListenerChecker: func(_ context.Context, listeners []Listener) error {
			if len(listeners) != 1 || listeners[0].Host != "127.0.0.1" {
				t.Fatalf("rollback listeners = %#v", listeners)
			}
			return errors.New("old listener missing")
		},
	}
	err := system.Apply(context.Background(), []byte("candidate"), nil)
	if err == nil || !strings.Contains(err.Error(), "rollback failed") ||
		!strings.Contains(err.Error(), "old listener missing") {
		t.Fatalf("Apply error = %v", err)
	}
}
