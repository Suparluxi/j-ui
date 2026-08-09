package monitor_test

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/Suparluxi/j-ui/internal/database"
	"github.com/Suparluxi/j-ui/internal/engine"
	"github.com/Suparluxi/j-ui/internal/model"
	"github.com/Suparluxi/j-ui/internal/monitor"
	"github.com/Suparluxi/j-ui/internal/secure"
)

type bulkEngine struct {
	bulkCalls   atomic.Int32
	legacyCalls atomic.Int32
}

func (*bulkEngine) Apply(context.Context, []byte, []engine.Listener) error { return nil }
func (*bulkEngine) Healthy(context.Context) bool                           { return true }
func (*bulkEngine) Version(context.Context) string                         { return "test" }
func (e *bulkEngine) ListenersHealthy(context.Context, []engine.Listener) error {
	e.legacyCalls.Add(1)
	return nil
}
func (e *bulkEngine) ListenerStatuses(_ context.Context, listeners []engine.Listener) ([]bool, error) {
	e.bulkCalls.Add(1)
	statuses := make([]bool, len(listeners))
	for index := range statuses {
		statuses[index] = true
	}
	return statuses, nil
}

func TestSnapshotsBatchHundredNodesAndShareShortCache(t *testing.T) {
	sealer, err := secure.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := database.Open(filepath.Join(t.TempDir(), "j-ui.db"), sealer)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	tokenEncrypted, err := sealer.Seal([]byte("test-token"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Bootstrap(context.Background(), database.Bootstrap{
		AdminPasswordHash: "test", AdminPath: "manage-test",
		TokenHash: secure.HashToken("test-token"), TokenEncrypted: tokenEncrypted,
	}); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 100; index++ {
		_, err := store.CreateNode(context.Background(), model.Node{
			Name: "node", Protocol: model.ProtocolVLESSReality, Listen: "127.0.0.1",
			Port: 20000 + index, Enabled: true, Settings: map[string]any{}, Secret: map[string]any{},
		}, model.Client{Name: "default", Credential: map[string]any{}})
		if err != nil {
			t.Fatal(err)
		}
	}
	proxy := &bulkEngine{}
	service := monitor.NewService(store, proxy)
	if _, err := service.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if proxy.bulkCalls.Load() != 1 || proxy.legacyCalls.Load() != 0 {
		t.Fatalf("health calls bulk=%d legacy=%d", proxy.bulkCalls.Load(), proxy.legacyCalls.Load())
	}
}
