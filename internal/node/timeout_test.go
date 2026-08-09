package node

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Suparluxi/j-ui/internal/database"
	"github.com/Suparluxi/j-ui/internal/engine"
	"github.com/Suparluxi/j-ui/internal/firewall"
	"github.com/Suparluxi/j-ui/internal/secure"
)

type deadlineOnceEngine struct {
	calls int
}

func (e *deadlineOnceEngine) Apply(ctx context.Context, _ []byte, _ []engine.Listener) error {
	e.calls++
	if e.calls == 1 {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func (*deadlineOnceEngine) Healthy(context.Context) bool { return true }
func (*deadlineOnceEngine) ListenersHealthy(context.Context, []engine.Listener) error {
	return nil
}
func (*deadlineOnceEngine) Version(context.Context) string { return "test" }

func TestCompensationGetsFreshDeadlineAfterPrimaryTimeout(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	sealer, err := secure.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := database.Open(filepath.Join(root, "data", "j-ui.db"), sealer)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	tokenEncrypted, err := sealer.Seal([]byte("subscription-token"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Bootstrap(context.Background(), database.Bootstrap{
		AdminPasswordHash: "unused",
		AdminPath:         "manage-00112233445566778899aabb",
		TokenHash:         secure.HashToken("subscription-token"),
		TokenEncrypted:    tokenEncrypted,
	}); err != nil {
		t.Fatal(err)
	}
	proxy := &deadlineOnceEngine{}
	service := NewService(store, proxy, firewall.Mock{})
	service.operationTimeout = 20 * time.Millisecond
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = service.Create(context.Background(), CreateInput{
		Name: "timeout", Protocol: "vless_reality", Listen: "127.0.0.1",
		Port: port, Enabled: true, ClientName: "default",
	})
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Create error = %v", err)
	}
	nodes, listErr := store.ListNodes(context.Background())
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(nodes) != 0 {
		t.Fatalf("candidate nodes after timeout compensation = %#v", nodes)
	}
	rules, rulesErr := store.ManagedFirewallRules(context.Background())
	if rulesErr != nil {
		t.Fatal(rulesErr)
	}
	if len(rules) != 0 {
		t.Fatalf("firewall rules after timeout compensation = %#v", rules)
	}
}
