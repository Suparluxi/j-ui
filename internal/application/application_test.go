package application

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Suparluxi/j-ui/internal/config"
)

func TestCloudflareRouteCheckRejectsOccupiedOriginPort(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	err = verifyCloudflarePublicRoute(context.Background(), "argo.example.com", port)
	if err == nil || !strings.Contains(err.Error(), "请先停用") {
		t.Fatalf("occupied origin error = %v", err)
	}
}

func TestOpenExistingDoesNotBootstrapEmptyInstance(t *testing.T) {
	root := t.TempDir()
	cfg := config.Config{
		DataDir:       filepath.Join(root, "data"),
		ConfigDir:     filepath.Join(root, "config"),
		DatabasePath:  filepath.Join(root, "data", "j-ui.db"),
		SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"),
		MockEngine:    true,
	}
	app, err := OpenExisting(context.Background(), cfg)
	if app != nil || err == nil {
		t.Fatalf("OpenExisting = %#v, %v; want initialization error", app, err)
	}
	for _, path := range []string{cfg.DatabasePath, cfg.SecretKeyPath} {
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("%s was created by OpenExisting: %v", path, statErr)
		}
	}
}

func TestCloudflaredConfigDataIncludesDomain(t *testing.T) {
	config := []byte(`
tunnel: 3f865809-7c85-4f80-8d77-2f544393a81e
credentials-file: /etc/cloudflared/tunnel.json
ingress:
  - hostname: argo.example.com
    service: http://127.0.0.1:2080
  - hostname: "*.ws.example.com"
    service: http://127.0.0.1:2081
  - service: http_status:404
`)
	for domain, expectedPort := range map[string]int{"argo.example.com": 2080, "one.ws.example.com": 2081} {
		if port, ok := cloudflaredConfigDataOriginPort(config, domain); !ok || port != expectedPort {
			t.Fatalf("expected %s to match cloudflared ingress", domain)
		}
	}
	for _, domain := range []string{"example.com", "ws.example.com", "evil.example.net"} {
		if _, ok := cloudflaredConfigDataOriginPort(config, domain); ok {
			t.Fatalf("did not expect %s to match cloudflared ingress", domain)
		}
	}
	invalidOrigin := []byte(`
tunnel: 3f865809-7c85-4f80-8d77-2f544393a81e
ingress:
  - hostname: argo.example.com
    service: http_status:404
`)
	if _, ok := cloudflaredConfigDataOriginPort(invalidOrigin, "argo.example.com"); ok {
		t.Fatal("non-local cloudflared ingress service was accepted")
	}
	if _, ok := cloudflaredConfigDataOriginPort([]byte("ingress: []\n"), "argo.example.com"); ok {
		t.Fatal("configuration without a tunnel was accepted")
	}
}

func TestCloudflaredProfileIncludesDomain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "argo-profile.json")
	data, err := json.Marshal(map[string]any{"domain": "argo.example.com", "originPort": 2080})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if port, ok := cloudflaredProfileOriginPort(path, "ARGO.EXAMPLE.COM"); !ok || port != 2080 {
		t.Fatalf("profile origin = %d, %v", port, ok)
	}
	for _, domain := range []string{"other.example.com", ""} {
		if _, ok := cloudflaredProfileOriginPort(path, domain); ok {
			t.Fatalf("profile unexpectedly matched %q", domain)
		}
	}
}

func TestPubliclyRoutableIP(t *testing.T) {
	for _, address := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !publiclyRoutableIP(address) {
			t.Fatalf("public address %s was rejected", address)
		}
	}
	for _, address := range []string{
		"127.0.0.1", "10.0.0.1", "100.64.0.1", "192.0.2.1", "198.18.0.1",
		"198.51.100.1", "203.0.113.1", "::1", "fd00::1", "2001:db8::1",
	} {
		if publiclyRoutableIP(address) {
			t.Fatalf("reserved address %s was accepted", address)
		}
	}
}
