package node_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Suparluxi/j-ui/internal/application"
	"github.com/Suparluxi/j-ui/internal/config"
	"github.com/Suparluxi/j-ui/internal/engine"
	"github.com/Suparluxi/j-ui/internal/firewall"
	"github.com/Suparluxi/j-ui/internal/model"
	nodeservice "github.com/Suparluxi/j-ui/internal/node"
)

const testLandingDetails = "JP_ADDR=jp.example.com\nJP_PORT=443\nJP_UUID=00000000-0000-4000-8000-000000000000\n" +
	"JP_PUB=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nJP_SID=abcd\nJP_SNI=www.example.com"

func TestLandingFollowsRegularNodeChangesAndPreservesDedicatedExits(t *testing.T) {
	root := t.TempDir()
	app, err := application.New(context.Background(), config.Config{
		DataDir: filepath.Join(root, "data"), ConfigDir: filepath.Join(root, "config"),
		DatabasePath: filepath.Join(root, "data", "j-ui.db"), SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"), MockEngine: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	proxy := &engine.Mock{}
	service := nodeservice.NewService(app.Store, proxy, firewall.Mock{})
	runtime := &recordingTemporaryRuntime{}
	service.ConfigureTemporaryRuntime(runtime)
	create := func(name, protocol string, outboundID *int64) int64 {
		t.Helper()
		node, err := service.Create(context.Background(), nodeservice.CreateInput{
			Name: name, Protocol: protocol, Listen: "127.0.0.1", Port: availableTCPPort(t),
			Enabled: true, ClientName: "default", OutboundID: outboundID,
		})
		if err != nil {
			t.Fatal(err)
		}
		return node.ID
	}
	first := create("reality", model.ProtocolVLESSReality, nil)
	if _, err := service.SetLanding(context.Background(), nodeservice.LandingInput{Enabled: true, Details: testLandingDetails}); err != nil {
		t.Fatal(err)
	}
	assertLandingScope(t, proxy.Configuration, first)
	second := create("anytls", model.ProtocolAnyTLSReality, nil)
	assertLandingScope(t, proxy.Configuration, first, second)
	outbound, err := app.Store.CreateOutbound(context.Background(), model.Outbound{
		Name: "dedicated", Type: model.OutboundSOCKS5, Server: "127.0.0.1", Port: 1080, Enabled: true, ManagedKind: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	bound := create("dedicated", model.ProtocolVLESSReality, &outbound.ID)
	assertLandingScope(t, proxy.Configuration, first, second)
	temporary, err := service.CloneTemporary(context.Background(), first, "temporary", outbound.ID, nil, "manual", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(runtime.last) != 1 || runtime.last[0].Node.ID != temporary.ID {
		t.Fatalf("temporary node missing from separate runtime: %#v", runtime.last)
	}
	assertLandingScope(t, proxy.Configuration, first, second)
	if _, err := service.SetEnabled(context.Background(), second, false); err != nil {
		t.Fatal(err)
	}
	assertLandingScope(t, proxy.Configuration, first)
	if _, err := service.SetEnabled(context.Background(), bound, false); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetEnabled(context.Background(), first, false); err != nil {
		t.Fatal(err)
	}
	assertLandingScope(t, proxy.Configuration)
	if _, err := service.SetEnabled(context.Background(), second, true); err != nil {
		t.Fatal(err)
	}
	assertLandingScope(t, proxy.Configuration, second)
}

func TestLegacyLandingScopeExpandsOnlyAfterSave(t *testing.T) {
	root := t.TempDir()
	app, err := application.New(context.Background(), config.Config{
		DataDir: filepath.Join(root, "data"), ConfigDir: filepath.Join(root, "config"),
		DatabasePath: filepath.Join(root, "data", "j-ui.db"), SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"), MockEngine: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	proxy := &engine.Mock{}
	service := nodeservice.NewService(app.Store, proxy, firewall.Mock{})
	create := func(name string) int64 {
		t.Helper()
		node, err := service.Create(context.Background(), nodeservice.CreateInput{
			Name: name, Protocol: model.ProtocolVLESSReality, Listen: "127.0.0.1",
			Port: availableTCPPort(t), Enabled: true, ClientName: "default",
		})
		if err != nil {
			t.Fatal(err)
		}
		return node.ID
	}
	first, second := create("first"), create("second")
	uri := "vless://00000000-0000-4000-8000-000000000000@jp.example.com:443?security=reality&type=tcp&sni=www.example.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd"
	legacy, err := json.Marshal(map[string]any{"enabled": true, "inboundId": first, "uri": uri})
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Store.SetSecretSetting(context.Background(), "ai_landing_v1", legacy); err != nil {
		t.Fatal(err)
	}
	if err := service.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertLandingScope(t, proxy.Configuration, first)
	view, err := service.Landing(context.Background())
	if err != nil || view.InboundID != first {
		t.Fatalf("legacy scope view = %+v, %v", view, err)
	}
	if _, err := service.SetLanding(context.Background(), nodeservice.LandingInput{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	assertLandingScope(t, proxy.Configuration, first, second)
	view, err = service.Landing(context.Background())
	if err != nil || view.InboundID != 0 {
		t.Fatalf("scope after explicit save = %+v, %v", view, err)
	}
}

func assertLandingScope(t *testing.T, config []byte, ids ...int64) {
	t.Helper()
	var document struct {
		Route struct {
			Rules []struct {
				Action   string   `json:"action"`
				Inbound  []string `json:"inbound"`
				Outbound string   `json:"outbound"`
			} `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(config, &document); err != nil {
		t.Fatal(err)
	}
	want := make([]string, 0, len(ids))
	for _, id := range ids {
		want = append(want, "node-"+strconv.FormatInt(id, 10))
	}
	count := 0
	for _, rule := range document.Route.Rules {
		if rule.Action != "sniff" && rule.Outbound != "ai-japan" && rule.Outbound != "native" {
			continue
		}
		if len(rule.Inbound) != len(want) {
			t.Fatalf("AI rule scope = %v, want %v", rule.Inbound, want)
		}
		for index := range want {
			if rule.Inbound[index] != want[index] {
				t.Fatalf("AI rule scope = %v, want %v", rule.Inbound, want)
			}
		}
		count++
	}
	wantCount := 2
	if len(want) == 0 {
		wantCount = 0
	}
	if count != wantCount {
		t.Fatalf("AI rule count = %d, want %d", count, wantCount)
	}
}

func TestLandingSetupConfigChecksWithSingBox(t *testing.T) {
	binary := os.Getenv("SINGBOX_TEST_BINARY")
	if binary == "" {
		t.Skip("SINGBOX_TEST_BINARY is not set")
	}
	script := nodeservice.LandingSetupScript()
	start := strings.Index(script, "  cat > \"$config_dir/config.json\" <<EOF\n")
	if start < 0 {
		t.Fatal("landing config template not found")
	}
	template := strings.SplitN(script[start:], "\nEOF", 2)[0]
	template = template[strings.Index(template, "\n")+1:]
	keyOutput, err := exec.Command(binary, "generate", "reality-keypair").Output()
	if err != nil {
		t.Fatal(err)
	}
	private := ""
	for _, line := range strings.Split(string(keyOutput), "\n") {
		if strings.HasPrefix(line, "PrivateKey: ") {
			private = strings.TrimPrefix(line, "PrivateKey: ")
		}
	}
	if private == "" {
		t.Fatal("sing-box did not generate a private key")
	}
	config := strings.NewReplacer("$listen_port", "14443", "$uuid", "11111111-1111-4111-8111-111111111111",
		"$sni", "www.microsoft.com", "$private", private, "$sid", "1234abcd").Replace(template)
	path := filepath.Join(t.TempDir(), "landing.json")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(binary, "check", "-c", path).CombinedOutput()
	if err != nil {
		t.Fatalf("landing config check: %v\n%s", err, output)
	}
}

func TestLandingApplyFailureRestoresPreviousState(t *testing.T) {
	root := t.TempDir()
	app, err := application.New(context.Background(), config.Config{
		ListenAddress: "127.0.0.1:8080", DataDir: filepath.Join(root, "data"),
		ConfigDir: filepath.Join(root, "config"), DatabasePath: filepath.Join(root, "data", "j-ui.db"),
		SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"), SessionTTL: time.Hour, MockEngine: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	_, err = app.Nodes.Create(context.Background(), nodeservice.CreateInput{
		Name: "Hong Kong", Protocol: model.ProtocolVLESSReality, Listen: "127.0.0.1",
		Port: 19986, Enabled: true, Settings: map[string]any{
			"handshake_server": "www.example.com", "handshake_port": 443, "server_name": "www.example.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine := &failOnceEngine{}
	service := nodeservice.NewService(app.Store, engine, &recordingFirewall{})
	if _, err := service.SetLanding(context.Background(), nodeservice.LandingInput{
		Enabled: true, Details: testLandingDetails,
	}); err == nil {
		t.Fatal("expected failed apply")
	}
	if engine.calls != 2 {
		t.Fatalf("apply calls = %d, want failure and rollback", engine.calls)
	}
	view, err := service.Landing(context.Background())
	if err != nil || view.Enabled || view.Configured {
		t.Fatalf("landing after rollback = %+v, %v", view, err)
	}
	if _, err := app.Store.Setting(context.Background(), "ai_landing_v1"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("failed apply persisted settings: %v", err)
	}
}
