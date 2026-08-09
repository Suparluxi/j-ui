package vpngate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/Suparluxi/j-ui/internal/database"
	"github.com/Suparluxi/j-ui/internal/model"
	"github.com/Suparluxi/j-ui/internal/secure"
)

type fakeFetcher struct {
	candidates []model.VPNGateCandidate
	err        error
}

func (f fakeFetcher) Fetch(context.Context) ([]model.VPNGateCandidate, error) {
	return f.candidates, f.err
}

type fakeOrchestrator struct {
	attempts []string
	fail     map[string]bool
	stopped  int
	stopErr  error
	healthy  bool
	observed string
}

type fakeIPInspector struct{}

func (fakeIPInspector) Inspect(_ context.Context, candidate model.VPNGateCandidate) (IPInspection, error) {
	inspection := inspectionForCandidate(candidate)
	inspection.Lookup = IPLookup{IP: candidate.IP, CountryCode: candidate.CountryShort}
	inspection.Provider = "test"
	return inspection, nil
}

type gatedHealthOrchestrator struct {
	started chan int64
	release chan struct{}
}

func TestCreateDefaultsToAutomaticCandidateSwap(t *testing.T) {
	input, err := validateCreateInput(CreateInput{Name: "default policy", Country: "JP", DurationMinutes: 30})
	if err != nil {
		t.Fatal(err)
	}
	if input.FailurePolicy != "auto_swap" {
		t.Fatalf("default failure policy = %q, want auto_swap", input.FailurePolicy)
	}
}

func (g *gatedHealthOrchestrator) Provision(
	context.Context, model.VPNGateExit, model.VPNGateCandidate, string, string, string,
) (string, error) {
	return "203.0.113.50", nil
}

func (g *gatedHealthOrchestrator) Stop(context.Context, model.VPNGateExit) error {
	return nil
}

func (g *gatedHealthOrchestrator) Healthy(ctx context.Context, exit model.VPNGateExit) bool {
	g.started <- exit.ID
	select {
	case <-g.release:
		return true
	case <-ctx.Done():
		return false
	}
}

func (f *fakeOrchestrator) Provision(
	_ context.Context, _ model.VPNGateExit, candidate model.VPNGateCandidate,
	_, _, _ string,
) (string, error) {
	f.attempts = append(f.attempts, candidate.HostName)
	if f.fail[candidate.HostName] {
		return "", errors.New("dial failed")
	}
	if f.observed != "" {
		return f.observed, nil
	}
	return "203.0.113.50", nil
}

func (f *fakeOrchestrator) Stop(context.Context, model.VPNGateExit) error {
	f.stopped++
	return f.stopErr
}

func TestInspectReturnsProviderDataWithoutStartingTunnel(t *testing.T) {
	store := testStore(t)
	candidate := candidate("inspect", "198.51.100.40", 100, time.Now().UTC())
	if err := store.ReplaceVPNGateCandidates(context.Background(), []model.VPNGateCandidate{candidate}); err != nil {
		t.Fatal(err)
	}
	orchestrator := &fakeOrchestrator{observed: candidate.IP}
	service := NewService(store, orchestrator, fakeFetcher{}, 5)
	service.ipInspector = fakeIPInspector{}
	inspection, err := service.Inspect(context.Background(), candidate.HostName)
	if err != nil {
		t.Fatal(err)
	}
	if orchestrator.stopped != 0 || len(orchestrator.attempts) != 0 ||
		inspection.Provider == "" || inspection.Lookup.IP != candidate.IP {
		t.Fatalf("stopped=%d inspection=%#v", orchestrator.stopped, inspection)
	}
}

func TestSwapDoesNotStartCandidateWhenCleanupFails(t *testing.T) {
	store := testStore(t)
	now := time.Now().UTC()
	candidates := []model.VPNGateCandidate{
		candidate("first", "198.51.100.1", 20, now),
		candidate("second", "198.51.100.2", 10, now),
	}
	orchestrator := &fakeOrchestrator{}
	service := NewService(store, orchestrator, fakeFetcher{candidates: candidates}, 5)
	exit, err := service.Create(context.Background(), CreateInput{
		Name: "cleanup guard", Country: "JP", DurationMinutes: 30,
		FailurePolicy: "block",
	})
	if err != nil {
		t.Fatal(err)
	}
	orchestrator.attempts = nil
	orchestrator.stopErr = errors.New("cleanup denied")
	updated, err := service.Swap(context.Background(), exit.ID)
	if err == nil {
		t.Fatal("swap succeeded despite cleanup failure")
	}
	if len(orchestrator.attempts) != 0 {
		t.Fatalf("candidate started after cleanup failure: %#v", orchestrator.attempts)
	}
	if updated.Status != "faulted" || updated.ObservedIP != "" {
		t.Fatalf("exit after cleanup failure = %#v", updated)
	}
	outbound, readErr := store.Outbound(context.Background(), exit.OutboundID)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if outbound.Status != "unhealthy" || outbound.ObservedIP != "" {
		t.Fatalf("outbound after cleanup failure = %#v", outbound)
	}
}

func (f *fakeOrchestrator) Healthy(context.Context, model.VPNGateExit) bool {
	return f.healthy
}

func TestReconcileRestoresInterruptedExitInPlace(t *testing.T) {
	store := testStore(t)
	now := time.Now().UTC()
	candidates := []model.VPNGateCandidate{
		candidate("first", "198.51.100.1", 20, now),
	}
	orchestrator := &fakeOrchestrator{}
	service := NewService(store, orchestrator, fakeFetcher{candidates: candidates}, 5)
	exit, err := service.Create(context.Background(), CreateInput{
		Name: "restore", Country: "JP", DurationMinutes: 30,
		FailurePolicy: "block",
	})
	if err != nil {
		t.Fatal(err)
	}
	exit.Status = "provisioning"
	exit.ObservedIP = ""
	if err := store.UpdateVPNGateExit(context.Background(), exit); err != nil {
		t.Fatal(err)
	}
	orchestrator.attempts = nil
	if err := service.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	restored, err := store.VPNGateExit(context.Background(), exit.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Status != "running" || restored.CandidateHostName != "first" ||
		restored.ObservedIP != "203.0.113.50" {
		t.Fatalf("restored exit = %#v", restored)
	}
	if len(orchestrator.attempts) != 1 || orchestrator.attempts[0] != "first" {
		t.Fatalf("restore attempts = %#v", orchestrator.attempts)
	}
}

func TestReconcileAutoSwapDoesNotDeadlock(t *testing.T) {
	store := testStore(t)
	now := time.Now().UTC()
	candidates := []model.VPNGateCandidate{
		candidate("first", "198.51.100.1", 20, now),
		candidate("second", "198.51.100.2", 10, now),
	}
	orchestrator := &fakeOrchestrator{healthy: true}
	service := NewService(store, orchestrator, fakeFetcher{candidates: candidates}, 5)
	exit, err := service.Create(context.Background(), CreateInput{
		Name: "auto restore", Country: "JP", DurationMinutes: 30,
		FailurePolicy: "auto_swap",
	})
	if err != nil {
		t.Fatal(err)
	}
	orchestrator.healthy = false
	orchestrator.fail = map[string]bool{"first": true}
	orchestrator.attempts = nil
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if len(orchestrator.attempts) != 0 {
		t.Fatalf("single failed health check restarted tunnel: %#v", orchestrator.attempts)
	}
	if err := service.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	restored, err := store.VPNGateExit(context.Background(), exit.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Status != "running" || restored.CandidateHostName != "second" {
		t.Fatalf("auto-swapped exit = %#v", restored)
	}
	if len(orchestrator.attempts) != 2 ||
		orchestrator.attempts[0] != "first" || orchestrator.attempts[1] != "second" {
		t.Fatalf("reconcile attempts = %#v", orchestrator.attempts)
	}
}

func TestReconcileChecksFiveExitsConcurrentlyWithoutBlockingMutations(t *testing.T) {
	store := testStore(t)
	var first model.VPNGateExit
	for slot := 1; slot <= 5; slot++ {
		now := time.Now().UTC()
		exit, err := store.CreateVPNGateExit(context.Background(), model.Outbound{
			Name: "exit", Type: model.OutboundSOCKS5, Server: "10.254.0.2",
			Port: 1080, Enabled: true, Username: "user", Password: "password",
			ManagedKind: "vpngate", Country: "JP",
		}, model.VPNGateExit{
			Slot: slot, Name: "exit", Country: "JP",
			Namespace:    "jui-vpn-" + fmt.Sprint(slot),
			LocalAddress: "10.254.0.2", LocalPort: 1080,
			Status: "running", ObservedIP: "203.0.113.50",
			FailurePolicy: "block", Permanent: true,
			CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			t.Fatal(err)
		}
		if slot == 1 {
			first = exit
		}
	}
	orchestrator := &gatedHealthOrchestrator{
		started: make(chan int64, 5),
		release: make(chan struct{}),
	}
	service := NewService(store, orchestrator, fakeFetcher{}, 5)
	reconcileDone := make(chan error, 1)
	go func() { reconcileDone <- service.Reconcile(context.Background()) }()
	for count := 0; count < 5; count++ {
		select {
		case <-orchestrator.started:
		case <-time.After(300 * time.Millisecond):
			close(orchestrator.release)
			t.Fatal("five health probes did not start concurrently")
		}
	}
	mutationDone := make(chan error, 1)
	go func() {
		_, err := service.Extend(context.Background(), first.ID, ExtendInput{Permanent: true})
		mutationDone <- err
	}()
	select {
	case err := <-mutationDone:
		if err != nil {
			close(orchestrator.release)
			t.Fatal(err)
		}
	case <-time.After(300 * time.Millisecond):
		close(orchestrator.release)
		t.Fatal("health probes blocked a VPNGate mutation")
	}
	close(orchestrator.release)
	if err := <-reconcileDone; err != nil {
		t.Fatal(err)
	}
}

func TestHealthResultRejectsSameSecondTunnelReplacement(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	exit := model.VPNGateExit{
		UpdatedAt: now, CandidateHostName: "old", CandidateIP: "198.51.100.1",
		ObservedIP: "203.0.113.1", RemoteProtocol: "udp", RemotePort: 1194,
		Namespace: "jui-vpn-1",
	}
	result := exitHealthResult{
		updatedAt: now, candidateHostName: exit.CandidateHostName,
		candidateIP: exit.CandidateIP, observedIP: exit.ObservedIP,
		remoteProtocol: exit.RemoteProtocol, remotePort: exit.RemotePort,
		namespace: exit.Namespace, healthy: false,
	}
	exit.CandidateHostName = "replacement"
	exit.CandidateIP = "198.51.100.2"
	if result.matches(exit) {
		t.Fatal("stale health result matched a replacement tunnel from the same second")
	}
}

func TestCreateTriesNextCandidateAndKeepsStableSlot(t *testing.T) {
	store := testStore(t)
	now := time.Now().UTC()
	candidates := []model.VPNGateCandidate{
		candidate("first", "198.51.100.1", 20, now),
		candidate("second", "198.51.100.2", 10, now),
	}
	orchestrator := &fakeOrchestrator{fail: map[string]bool{"first": true}}
	service := NewService(store, orchestrator, fakeFetcher{candidates: candidates}, 5)
	exit, err := service.Create(context.Background(), CreateInput{
		Name: "Japan temporary", Country: "JP", DurationMinutes: 30,
		FailurePolicy: "block",
	})
	if err != nil {
		t.Fatal(err)
	}
	if exit.Slot != 1 || exit.Namespace != "jui-vpn-1" ||
		exit.LocalAddress != "10.254.1.2" || exit.CandidateHostName != "second" ||
		exit.ObservedIP != "203.0.113.50" || exit.Status != "running" {
		t.Fatalf("exit = %#v", exit)
	}
	if len(orchestrator.attempts) != 2 {
		t.Fatalf("attempts = %#v", orchestrator.attempts)
	}
	outbound, err := store.Outbound(context.Background(), exit.OutboundID)
	if err != nil {
		t.Fatal(err)
	}
	if outbound.ManagedKind != "vpngate" || outbound.Server != "10.254.1.2" ||
		outbound.Status != "healthy" || outbound.ObservedIP != "203.0.113.50" {
		t.Fatalf("outbound = %#v", outbound)
	}
}

func TestCreateTriesSelectedCandidateBeforeAutomaticFallback(t *testing.T) {
	store := testStore(t)
	now := time.Now().UTC()
	candidates := []model.VPNGateCandidate{
		candidate("preferred-by-score", "198.51.100.1", 20, now),
		candidate("selected", "198.51.100.2", 10, now),
	}
	orchestrator := &fakeOrchestrator{fail: map[string]bool{"selected": true}}
	service := NewService(store, orchestrator, fakeFetcher{candidates: candidates}, 5)
	exit, err := service.Create(context.Background(), CreateInput{
		Name: "selected fallback", Country: "JP", CandidateHostName: "selected",
		DurationMinutes: 30, FailurePolicy: "auto_swap",
	})
	if err != nil {
		t.Fatal(err)
	}
	if exit.CandidateHostName != "preferred-by-score" {
		t.Fatalf("fallback candidate = %q", exit.CandidateHostName)
	}
	if len(orchestrator.attempts) != 2 || orchestrator.attempts[0] != "selected" ||
		orchestrator.attempts[1] != "preferred-by-score" {
		t.Fatalf("attempt order = %#v", orchestrator.attempts)
	}
}

func TestCreateStopsTunnelWhenAtomicHealthCommitFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j-ui.db")
	sealer, err := secure.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := database.Open(path, sealer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	injector, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = injector.Close() })
	if _, err := injector.Exec(`
		CREATE TRIGGER reject_healthy_outbound
		BEFORE UPDATE OF status ON outbounds
		WHEN NEW.status = 'healthy'
		BEGIN
			SELECT RAISE(FAIL, 'injected health commit failure');
		END
	`); err != nil {
		t.Fatal(err)
	}
	orchestrator := &fakeOrchestrator{}
	service := NewService(store, orchestrator, fakeFetcher{candidates: []model.VPNGateCandidate{
		candidate("first", "198.51.100.1", 20, time.Now().UTC()),
	}}, 5)
	if _, err := service.Create(context.Background(), CreateInput{
		Name: "commit failure", Country: "JP", DurationMinutes: 30,
		FailurePolicy: "block",
	}); err == nil {
		t.Fatal("create succeeded despite injected atomic health commit failure")
	}
	if orchestrator.stopped != 1 {
		t.Fatalf("new tunnel stop count = %d, want 1", orchestrator.stopped)
	}
	exits, err := store.ListVPNGateExits(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(exits) != 1 || exits[0].Status != "faulted" || exits[0].ObservedIP != "" {
		t.Fatalf("compensated exits = %#v", exits)
	}
}

func TestConfiguredExitMaximumIsEnforced(t *testing.T) {
	store := testStore(t)
	candidates := []model.VPNGateCandidate{
		candidate("first", "198.51.100.1", 20, time.Now().UTC()),
		candidate("second", "198.51.100.2", 10, time.Now().UTC()),
	}
	service := NewService(store, &fakeOrchestrator{}, fakeFetcher{candidates: candidates}, 1)
	if _, err := service.Create(context.Background(), CreateInput{
		Name: "first", Country: "JP", DurationMinutes: 30, FailurePolicy: "block",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Create(context.Background(), CreateInput{
		Name: "second", Country: "JP", DurationMinutes: 30, FailurePolicy: "block",
	}); err == nil {
		t.Fatal("created more VPNGate exits than configured")
	}
}

func TestRefreshFailurePreservesCachedCatalog(t *testing.T) {
	store := testStore(t)
	cached := candidate("cached", "198.51.100.3", 1, time.Now().Add(-time.Hour))
	if err := store.ReplaceVPNGateCandidates(context.Background(), []model.VPNGateCandidate{cached}); err != nil {
		t.Fatal(err)
	}
	service := NewService(store, &fakeOrchestrator{}, fakeFetcher{err: errors.New("offline")}, 5)
	candidates, err := service.Refresh(context.Background())
	if err == nil || len(candidates) != 1 || candidates[0].HostName != "cached" {
		t.Fatalf("cached refresh = %#v err=%v", candidates, err)
	}
}

func candidate(host, ip string, score int64, fetchedAt time.Time) model.VPNGateCandidate {
	return model.VPNGateCandidate{
		HostName: host, IP: ip, Score: score, Ping: 20, Speed: 10_000_000,
		CountryLong: "Japan", CountryShort: "JP", NumSessions: 2, Uptime: 1000,
		OpenVPNConfig: safeOpenVPN, HasOpenVPN: true, FetchedAt: fetchedAt,
	}
}

func testStore(t *testing.T) *database.Store {
	t.Helper()
	sealer, err := secure.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := database.Open(filepath.Join(t.TempDir(), "j-ui.db"), sealer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}
