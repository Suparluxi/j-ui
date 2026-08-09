package node_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Suparluxi/j-ui/internal/application"
	"github.com/Suparluxi/j-ui/internal/config"
	"github.com/Suparluxi/j-ui/internal/database"
	"github.com/Suparluxi/j-ui/internal/engine"
	"github.com/Suparluxi/j-ui/internal/firewall"
	nodeservice "github.com/Suparluxi/j-ui/internal/node"
	_ "modernc.org/sqlite"
)

type partialFirewall struct{}

type cancelOnceEngine struct {
	cancel context.CancelFunc
	calls  int
}

type failOnceEngine struct{ calls int }

func (e *failOnceEngine) Apply(context.Context, []byte, []engine.Listener) error {
	e.calls++
	if e.calls == 1 {
		return errors.New("injected port reallocation failure")
	}
	return nil
}
func (*failOnceEngine) Healthy(context.Context) bool                              { return true }
func (*failOnceEngine) ListenersHealthy(context.Context, []engine.Listener) error { return nil }
func (*failOnceEngine) Version(context.Context) string                            { return "test" }

func (e *cancelOnceEngine) Apply(context.Context, []byte, []engine.Listener) error {
	e.calls++
	if e.calls == 1 {
		e.cancel()
		return errors.New("injected apply failure after caller disconnect")
	}
	return nil
}
func (*cancelOnceEngine) Healthy(context.Context) bool { return true }
func (*cancelOnceEngine) ListenersHealthy(context.Context, []engine.Listener) error {
	return nil
}
func (*cancelOnceEngine) Version(context.Context) string { return "test" }

func (partialFirewall) Backend(context.Context) (string, error) {
	return firewall.BackendNFTables, nil
}

func (partialFirewall) Ensure(_ context.Context, protocol string, _ int) (firewall.Result, error) {
	if protocol == "tcp" {
		return firewall.Result{}, errors.New("injected TCP ensure failure")
	}
	return firewall.Result{Ownership: firewall.Owned, Backend: firewall.BackendNFTables}, nil
}

type recordingFirewall struct {
	ensured []string
	closed  []string
	actions []string
	backend string
}

func (f *recordingFirewall) Ensure(_ context.Context, protocol string, port int) (firewall.Result, error) {
	f.ensured = append(f.ensured, fmt.Sprintf("%s/%d", protocol, port))
	backend, _ := f.Backend(context.Background())
	f.actions = append(f.actions, "ensure@"+backend)
	return firewall.Result{Ownership: firewall.Owned, Backend: backend}, nil
}
func (f *recordingFirewall) Backend(context.Context) (string, error) {
	if f.backend != "" {
		return f.backend, nil
	}
	return firewall.BackendNFTables, nil
}
func (f *recordingFirewall) Close(_ context.Context, protocol string, port int, backend string) error {
	f.closed = append(f.closed, fmt.Sprintf("%s/%d@%s", protocol, port, backend))
	f.actions = append(f.actions, "close@"+backend)
	return nil
}

func (partialFirewall) Close(_ context.Context, protocol string, _ int, _ string) error {
	if protocol == "tcp" {
		return errors.New("injected TCP compensation failure")
	}
	return nil
}

func TestCreateCompensatesDatabaseConfigVersionFailure(t *testing.T) {
	root := t.TempDir()
	databasePath := filepath.Join(root, "data", "j-ui.db")
	app, err := application.New(context.Background(), config.Config{
		DataDir:       filepath.Join(root, "data"),
		ConfigDir:     filepath.Join(root, "config"),
		DatabasePath:  databasePath,
		SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"),
		MockEngine:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	injector, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer injector.Close()
	if _, err := injector.Exec(`
		CREATE TRIGGER reject_config_version
		BEFORE INSERT ON config_versions
		BEGIN SELECT RAISE(ABORT, 'injected config version failure'); END
	`); err != nil {
		t.Fatal(err)
	}

	_, err = app.Nodes.Create(context.Background(), nodeservice.CreateInput{
		Name: "rollback", Protocol: "vless_reality", Listen: "127.0.0.1",
		Port: availableTCPPort(t), Enabled: false, ClientName: "default",
	})
	if err == nil {
		t.Fatal("Create succeeded despite injected config version failure")
	}
	nodes, listErr := app.Store.ListNodes(context.Background())
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(nodes) != 0 {
		t.Fatalf("nodes after compensation = %#v", nodes)
	}
}

func TestCreateCompensationSurvivesCallerCancellationAfterMutation(t *testing.T) {
	root := t.TempDir()
	app, err := application.New(context.Background(), config.Config{
		DataDir:       filepath.Join(root, "data"),
		ConfigDir:     filepath.Join(root, "config"),
		DatabasePath:  filepath.Join(root, "data", "j-ui.db"),
		SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"),
		MockEngine:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ctx, cancel := context.WithCancel(context.Background())
	proxy := &cancelOnceEngine{cancel: cancel}
	service := nodeservice.NewService(app.Store, proxy, firewall.Mock{})
	_, err = service.Create(ctx, nodeservice.CreateInput{
		Name: "disconnect", Protocol: "vless_reality", Listen: "127.0.0.1",
		Port: availableTCPPort(t), Enabled: true, ClientName: "default",
	})
	if err == nil || ctx.Err() == nil {
		t.Fatalf("Create error=%v callerErr=%v", err, ctx.Err())
	}
	nodes, listErr := app.Store.ListNodes(context.Background())
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(nodes) != 0 {
		t.Fatalf("nodes after detached compensation = %#v", nodes)
	}
	rules, rulesErr := app.Store.ManagedFirewallRules(context.Background())
	if rulesErr != nil {
		t.Fatal(rulesErr)
	}
	if len(rules) != 0 {
		t.Fatalf("firewall intents after detached compensation = %#v", rules)
	}
}

func TestLoopbackNodeDoesNotOpenFirewall(t *testing.T) {
	root := t.TempDir()
	app, err := application.New(context.Background(), config.Config{
		DataDir:       filepath.Join(root, "data"),
		ConfigDir:     filepath.Join(root, "config"),
		DatabasePath:  filepath.Join(root, "data", "j-ui.db"),
		SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"),
		MockEngine:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	manager := &recordingFirewall{}
	service := nodeservice.NewService(app.Store, &engine.Mock{}, manager)
	if _, err := service.Create(context.Background(), nodeservice.CreateInput{
		Name: "local", Protocol: "vless_reality", Listen: "127.0.0.1",
		Port: availableTCPPort(t), Enabled: true, ClientName: "default",
	}); err != nil {
		t.Fatal(err)
	}
	if len(manager.ensured) != 0 {
		t.Fatalf("loopback listener opened firewall rules: %#v", manager.ensured)
	}
}

func TestCreateReportsIncompleteFirewallCompensation(t *testing.T) {
	root := t.TempDir()
	app, err := application.New(context.Background(), config.Config{
		DataDir:       filepath.Join(root, "data"),
		ConfigDir:     filepath.Join(root, "config"),
		DatabasePath:  filepath.Join(root, "data", "j-ui.db"),
		SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"),
		MockEngine:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	service := nodeservice.NewService(app.Store, &engine.Mock{}, partialFirewall{})

	_, err = service.Create(context.Background(), nodeservice.CreateInput{
		Name: "rollback", Protocol: "vless_reality", Listen: "0.0.0.0",
		Port: availableTCPAndUDPPort(t), Enabled: true, ClientName: "default",
	})
	if err == nil || !strings.Contains(err.Error(), "remove stale firewall rule tcp/") {
		t.Fatalf("Create error = %v; want joined compensation failure", err)
	}
	nodes, listErr := app.Store.ListNodes(context.Background())
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(nodes) != 0 {
		t.Fatalf("nodes after compensation = %#v", nodes)
	}
	events, eventErr := app.Store.RecentEvents(context.Background(), 10)
	if eventErr != nil {
		t.Fatal(eventErr)
	}
	found := false
	for _, event := range events {
		if event.Code == "rollback_incomplete" {
			found = true
		}
	}
	if !found {
		t.Fatalf("rollback_incomplete event missing: %#v", events)
	}
}

func TestReconcileRemovesPersistedStaleFirewallRules(t *testing.T) {
	root := t.TempDir()
	app, err := application.New(context.Background(), config.Config{
		DataDir:       filepath.Join(root, "data"),
		ConfigDir:     filepath.Join(root, "config"),
		DatabasePath:  filepath.Join(root, "data", "j-ui.db"),
		SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"),
		MockEngine:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if err := app.Store.TrackFirewallRule(context.Background(), "tcp", 23456); err != nil {
		t.Fatal(err)
	}
	manager := &recordingFirewall{}
	service := nodeservice.NewService(app.Store, &engine.Mock{}, manager)
	if err := service.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(manager.closed) != 1 || manager.closed[0] != "tcp/23456@unknown" {
		t.Fatalf("closed rules = %#v", manager.closed)
	}
	rules, err := app.Store.ManagedFirewallRules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("tracked rules after reconcile = %#v", rules)
	}
}

func TestTrackFailureDoesNotCreateUnownedFirewallRule(t *testing.T) {
	root := t.TempDir()
	databasePath := filepath.Join(root, "data", "j-ui.db")
	app, err := application.New(context.Background(), config.Config{
		DataDir:       filepath.Join(root, "data"),
		ConfigDir:     filepath.Join(root, "config"),
		DatabasePath:  databasePath,
		SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"),
		MockEngine:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	injector, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer injector.Close()
	if _, err := injector.Exec(`
		CREATE TRIGGER reject_firewall_tracking
		BEFORE INSERT ON managed_firewall_rules
		BEGIN SELECT RAISE(ABORT, 'injected firewall tracking failure'); END
	`); err != nil {
		t.Fatal(err)
	}
	manager := &recordingFirewall{}
	service := nodeservice.NewService(app.Store, &engine.Mock{}, manager)
	_, err = service.Create(context.Background(), nodeservice.CreateInput{
		Name: "track-first", Protocol: "vless_reality", Listen: "0.0.0.0",
		Port: availableTCPPort(t), Enabled: true, ClientName: "default",
	})
	if err == nil || !strings.Contains(err.Error(), "track firewall rule") {
		t.Fatalf("Create error = %v", err)
	}
	if len(manager.ensured) != 0 {
		t.Fatalf("unowned OS rules were created: %#v", manager.ensured)
	}
}

func TestClientMutationDoesNotReapplyVerifiedFirewallRule(t *testing.T) {
	root := t.TempDir()
	app, err := application.New(context.Background(), config.Config{
		DataDir:       filepath.Join(root, "data"),
		ConfigDir:     filepath.Join(root, "config"),
		DatabasePath:  filepath.Join(root, "data", "j-ui.db"),
		SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"),
		MockEngine:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	manager := &recordingFirewall{}
	service := nodeservice.NewService(app.Store, &engine.Mock{}, manager)
	node, err := service.Create(context.Background(), nodeservice.CreateInput{
		Name: "client-only", Protocol: "vless_reality", Listen: "0.0.0.0",
		Port: availableTCPPort(t), Enabled: true, ClientName: "default",
	})
	if err != nil {
		t.Fatal(err)
	}
	initialEnsures := len(manager.ensured)
	if initialEnsures != 1 {
		t.Fatalf("initial ensured rules = %#v", manager.ensured)
	}
	if _, err := service.AddClient(context.Background(), node.ID, "second"); err != nil {
		t.Fatal(err)
	}
	if len(manager.ensured) != initialEnsures {
		t.Fatalf("client-only mutation reapplied rules: %#v", manager.ensured)
	}
}

func TestSharedFirewallRuleClosesOnlyAfterLastNodeIsDeleted(t *testing.T) {
	root := t.TempDir()
	app, err := application.New(context.Background(), config.Config{
		DataDir:       filepath.Join(root, "data"),
		ConfigDir:     filepath.Join(root, "config"),
		DatabasePath:  filepath.Join(root, "data", "j-ui.db"),
		SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"),
		MockEngine:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	manager := &recordingFirewall{}
	service := nodeservice.NewService(app.Store, &engine.Mock{}, manager)
	port := availableTCPPort(t)
	first, err := service.Create(context.Background(), nodeservice.CreateInput{
		Name: "first", Protocol: "vless_reality", Listen: "0.0.0.0",
		Port: port, Enabled: true, ClientName: "default",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Create(context.Background(), nodeservice.CreateInput{
		Name: "second", Protocol: "vless_reality", Listen: "::",
		Port: port, Enabled: true, ClientName: "default",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Delete(context.Background(), first.ID); err != nil {
		t.Fatal(err)
	}
	if len(manager.closed) != 0 {
		t.Fatalf("shared rule closed too early: %#v", manager.closed)
	}
	if err := service.Delete(context.Background(), second.ID); err != nil {
		t.Fatal(err)
	}
	if len(manager.closed) != 1 {
		t.Fatalf("closed rules = %#v", manager.closed)
	}
}

func TestRestartAfterFirewallBackendSwitchRemovesOldOwnedRuleFirst(t *testing.T) {
	root := t.TempDir()
	app, err := application.New(context.Background(), config.Config{
		DataDir:       filepath.Join(root, "data"),
		ConfigDir:     filepath.Join(root, "config"),
		DatabasePath:  filepath.Join(root, "data", "j-ui.db"),
		SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"),
		MockEngine:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	manager := &recordingFirewall{backend: firewall.BackendUFW}
	service := nodeservice.NewService(app.Store, &engine.Mock{}, manager)
	if _, err := service.Create(context.Background(), nodeservice.CreateInput{
		Name: "switch", Protocol: "vless_reality", Listen: "0.0.0.0",
		Port: availableTCPPort(t), Enabled: true, ClientName: "default",
	}); err != nil {
		t.Fatal(err)
	}
	manager.backend = firewall.BackendFirewalld
	manager.actions = nil
	manager.closed = nil
	manager.ensured = nil
	restartedService := nodeservice.NewService(app.Store, &engine.Mock{}, manager)
	if err := restartedService.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(manager.actions) < 2 ||
		manager.actions[0] != "close@"+firewall.BackendUFW ||
		manager.actions[1] != "ensure@"+firewall.BackendFirewalld {
		t.Fatalf("backend migration actions = %#v", manager.actions)
	}
	rules, err := app.Store.ManagedFirewallRules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Backend != firewall.BackendFirewalld ||
		rules[0].Ownership != database.FirewallOwned {
		t.Fatalf("tracked rules after migration = %#v", rules)
	}
}

func TestSetStartPortReassignsNodesAndAllocatesTheNextPort(t *testing.T) {
	root := t.TempDir()
	app, err := application.New(context.Background(), config.Config{
		DataDir: filepath.Join(root, "data"), ConfigDir: filepath.Join(root, "config"),
		DatabasePath:  filepath.Join(root, "data", "j-ui.db"),
		SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"),
		MockEngine:    true, NodeStartPort: 8881,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	firstPort := availableTCPPort(t)
	first, err := app.Nodes.Create(context.Background(), nodeservice.CreateInput{
		Name: fmt.Sprintf("test丨XTLS+Reality_%d", firstPort), Protocol: "vless_reality",
		Listen: "127.0.0.1", Port: firstPort, Enabled: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := app.Nodes.Create(context.Background(), nodeservice.CreateInput{
		Name: "custom Hysteria", Protocol: "hysteria2", Listen: "127.0.0.1",
		Port: availableTCPAndUDPPort(t), Enabled: false,
		Settings: map[string]any{"server_name": "127.0.0.1", "certificate_mode": "auto"},
	})
	if err != nil {
		t.Fatal(err)
	}
	startPort := availableConsecutivePorts(t, 3)
	settings, err := app.Nodes.SetStartPort(context.Background(), startPort)
	if err != nil {
		t.Fatal(err)
	}
	if settings.StartPort != startPort || settings.NextPort != startPort+2 {
		t.Fatalf("port settings = %#v", settings)
	}
	first, err = app.Store.Node(context.Background(), first.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, err = app.Store.Node(context.Background(), second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if first.Port != startPort || first.Name != fmt.Sprintf("test丨XTLS+Reality_%d", startPort) {
		t.Fatalf("first node = %#v", first)
	}
	if second.Port != startPort+1 || second.Name != "custom Hysteria" {
		t.Fatalf("second node = %#v", second)
	}
	created, err := app.Nodes.Create(context.Background(), nodeservice.CreateInput{
		Name: "test丨XTLS+Reality_0", Protocol: "vless_reality", Listen: "127.0.0.1",
		Port: 0, Enabled: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Port != startPort+2 || created.Name != fmt.Sprintf("test丨XTLS+Reality_%d", startPort+2) {
		t.Fatalf("automatically allocated node = %#v", created)
	}
}

func TestSetStartPortRestoresDatabaseAndSettingWhenDeployFails(t *testing.T) {
	root := t.TempDir()
	app, err := application.New(context.Background(), config.Config{
		DataDir: filepath.Join(root, "data"), ConfigDir: filepath.Join(root, "config"),
		DatabasePath:  filepath.Join(root, "data", "j-ui.db"),
		SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"),
		MockEngine:    true, NodeStartPort: 8881,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	oldPort := availableTCPPort(t)
	node, err := app.Nodes.Create(context.Background(), nodeservice.CreateInput{
		Name: fmt.Sprintf("rollback_%d", oldPort), Protocol: "vless_reality",
		Listen: "127.0.0.1", Port: oldPort, Enabled: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	service := nodeservice.NewService(app.Store, &failOnceEngine{}, firewall.Mock{})
	if _, err := service.SetStartPort(context.Background(), availableConsecutivePorts(t, 2)); err == nil {
		t.Fatal("port reallocation succeeded despite injected deploy failure")
	}
	restored, err := app.Store.Node(context.Background(), node.ID)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := service.PortSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if restored.Port != oldPort || restored.Name != fmt.Sprintf("rollback_%d", oldPort) || settings.StartPort != 8881 {
		t.Fatalf("rollback node=%#v settings=%#v", restored, settings)
	}
}

func availableTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func availableTCPAndUDPPort(t *testing.T) int {
	t.Helper()
	for attempt := 0; attempt < 20; attempt++ {
		port := availableTCPPort(t)
		packet, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)))
		if err != nil {
			continue
		}
		_ = packet.Close()
		return port
	}
	t.Fatal("could not find a port available for TCP and UDP")
	return 0
}

func availableConsecutivePorts(t *testing.T, count int) int {
	t.Helper()
	for base := 20000; base+count < 65000; base += count + 7 {
		available := true
		for port := base; port < base+count; port++ {
			tcp, tcpErr := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)))
			udp, udpErr := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)))
			if tcp != nil {
				_ = tcp.Close()
			}
			if udp != nil {
				_ = udp.Close()
			}
			if tcpErr != nil || udpErr != nil {
				available = false
				break
			}
		}
		if available {
			return base
		}
	}
	t.Fatal("could not find consecutive TCP and UDP ports")
	return 0
}
