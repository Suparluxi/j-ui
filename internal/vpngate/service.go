package vpngate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Suparluxi/j-ui/internal/database"
	"github.com/Suparluxi/j-ui/internal/model"
	"github.com/Suparluxi/j-ui/internal/netns"
	"github.com/Suparluxi/j-ui/internal/problem"
	"github.com/Suparluxi/j-ui/internal/secure"
)

type CatalogFetcher interface {
	Fetch(context.Context) ([]model.VPNGateCandidate, error)
}

type CreateInput struct {
	Name              string `json:"name"`
	Country           string `json:"country"`
	CandidateHostName string `json:"candidateHostName"`
	DurationMinutes   int    `json:"durationMinutes"`
	Permanent         bool   `json:"permanent"`
	FailurePolicy     string `json:"failurePolicy"`
	// Deprecated: retained for API compatibility; candidate filtering is no longer applied.
	MaxPing      int `json:"maxPing,omitempty"`
	MinSpeedMbps int `json:"minSpeedMbps,omitempty"`
	MaxSessions  int `json:"maxSessions,omitempty"`
}

type ExtendInput struct {
	DurationMinutes int  `json:"durationMinutes"`
	Permanent       bool `json:"permanent"`
}

type Service struct {
	store          *database.Store
	orchestrator   netns.Orchestrator
	fetcher        CatalogFetcher
	timeout        time.Duration
	maxExits       int
	mu             sync.Mutex
	reconcileMu    sync.Mutex
	healthFailures map[int64]int
	stop           chan struct{}
	done           chan struct{}
	ipInspector    candidateIPInspector
}

type candidateIPInspector interface {
	Inspect(context.Context, model.VPNGateCandidate) (IPInspection, error)
}

type exitHealthResult struct {
	updatedAt         time.Time
	candidateHostName string
	candidateIP       string
	observedIP        string
	remoteProtocol    string
	remotePort        int
	namespace         string
	healthy           bool
}

func (r exitHealthResult) matches(exit model.VPNGateExit) bool {
	return r.updatedAt.Equal(exit.UpdatedAt) &&
		r.candidateHostName == exit.CandidateHostName &&
		r.candidateIP == exit.CandidateIP &&
		r.observedIP == exit.ObservedIP &&
		r.remoteProtocol == exit.RemoteProtocol &&
		r.remotePort == exit.RemotePort &&
		r.namespace == exit.Namespace
}

func NewService(
	store *database.Store,
	orchestrator netns.Orchestrator,
	fetcher CatalogFetcher,
	maxExits int,
) *Service {
	if maxExits < 1 || maxExits > 5 {
		maxExits = 5
	}
	return &Service{
		store: store, orchestrator: orchestrator, fetcher: fetcher,
		timeout: 3 * time.Minute, maxExits: maxExits,
		healthFailures: make(map[int64]int),
		stop:           make(chan struct{}), done: make(chan struct{}), ipInspector: NewIPInspector(),
	}
}

func (s *Service) Start() {
	go s.watch()
}

func (s *Service) Close() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	<-s.done
}

func (s *Service) Refresh(ctx context.Context) ([]model.VPNGateCandidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidates, err := s.fetcher.Fetch(ctx)
	if err != nil {
		cached, cacheErr := s.store.ListVPNGateCandidates(ctx)
		if cacheErr == nil && len(cached) != 0 {
			return cached, problem.New(
				problem.Unavailable, "vpngate_refresh_failed",
				"VPNGate 列表刷新失败，已保留上次缓存", err,
			)
		}
		return nil, problem.New(
			problem.Unavailable, "vpngate_unavailable", "VPNGate 列表暂时不可用", err,
		)
	}
	if err := s.store.ReplaceVPNGateCandidates(ctx, candidates); err != nil {
		return nil, err
	}
	s.recordEvent(ctx, "info", "vpngate_catalog_refreshed",
		fmt.Sprintf("VPNGate 候选列表已刷新，共 %d 条", len(candidates)))
	return candidates, nil
}

func (s *Service) Candidates(ctx context.Context, filter Filter) ([]model.VPNGateCandidate, error) {
	candidates, err := s.store.ListVPNGateCandidates(ctx)
	if err != nil {
		return nil, err
	}
	return FilterAndRank(candidates, filter, nil), nil
}

func (s *Service) Inspect(ctx context.Context, hostName string) (IPInspection, error) {
	candidate, err := s.store.VPNGateCandidate(ctx, strings.TrimSpace(hostName))
	if err != nil {
		return IPInspection{}, err
	}
	operationCtx, cancel := s.operationContext(ctx)
	defer cancel()
	if s.ipInspector == nil {
		return IPInspection{}, errors.New("IP 信息检测服务未初始化")
	}
	inspection, err := s.ipInspector.Inspect(operationCtx, candidate)
	if err != nil {
		return IPInspection{}, err
	}
	base := inspectionForCandidate(candidate)
	inspection.CandidateHostName = base.CandidateHostName
	inspection.CandidateIP = base.CandidateIP
	inspection.VPNGate = base.VPNGate
	return inspection, nil
}

func (s *Service) Regions(ctx context.Context, filter Filter) ([]map[string]any, error) {
	candidates, err := s.store.ListVPNGateCandidates(ctx)
	if err != nil {
		return nil, err
	}
	filter.Country = ""
	available := FilterAndRank(candidates, filter, nil)
	availableByCountry := make(map[string]int)
	for _, candidate := range available {
		availableByCountry[candidate.CountryShort]++
	}
	type region struct {
		name  string
		count int
	}
	regions := make(map[string]region)
	for _, candidate := range candidates {
		value := regions[candidate.CountryShort]
		value.name = candidate.CountryLong
		value.count++
		regions[candidate.CountryShort] = value
	}
	result := make([]map[string]any, 0, len(regions))
	for code, value := range regions {
		region := map[string]any{
			"code": code, "name": value.name, "count": value.count,
			"availableCount": availableByCountry[code],
		}
		if name := countryNameZh(code); name != "" {
			region["nameZh"] = name
		}
		result = append(result, region)
	}
	for i := 1; i < len(result); i++ {
		for j := i; j > 0 && result[j]["code"].(string) < result[j-1]["code"].(string); j-- {
			result[j], result[j-1] = result[j-1], result[j]
		}
	}
	return result, nil
}

func (s *Service) Exits(ctx context.Context) ([]model.VPNGateExit, error) {
	return s.store.ListVPNGateExits(ctx)
}

func (s *Service) Create(ctx context.Context, input CreateInput) (model.VPNGateExit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	input, err := validateCreateInput(input)
	if err != nil {
		return model.VPNGateExit{}, validationError(err)
	}
	exits, err := s.store.ListVPNGateExits(ctx)
	if err != nil {
		return model.VPNGateExit{}, err
	}
	slot := availableSlot(exits, s.maxExits)
	if slot == 0 {
		return model.VPNGateExit{}, conflictError(
			fmt.Errorf("最多同时创建 %d 条 VPNGate 出口", s.maxExits),
		)
	}
	candidates, err := s.cachedCandidates(ctx)
	if err != nil {
		return model.VPNGateExit{}, err
	}
	excluded := activeCandidates(exits, 0)
	ranked := FilterAndRank(candidates, Filter{Country: input.Country}, excluded)
	if input.CandidateHostName != "" {
		selectedIndex := -1
		for index, candidate := range ranked {
			if candidate.HostName == input.CandidateHostName {
				selectedIndex = index
				break
			}
		}
		if selectedIndex < 0 {
			ranked = nil
		} else if input.FailurePolicy == "auto_swap" {
			selected := ranked[selectedIndex]
			remaining := append([]model.VPNGateCandidate{}, ranked[:selectedIndex]...)
			remaining = append(remaining, ranked[selectedIndex+1:]...)
			ranked = append([]model.VPNGateCandidate{selected}, remaining...)
		} else {
			ranked = []model.VPNGateCandidate{ranked[selectedIndex]}
		}
	}
	if len(ranked) == 0 {
		return model.VPNGateExit{}, conflictError(errors.New("当前没有符合筛选条件的 VPNGate 候选，所选 IP 可能已被占用或失效"))
	}
	if len(ranked) > 6 {
		ranked = ranked[:6]
	}
	username, err := secure.RandomToken(12)
	if err != nil {
		return model.VPNGateExit{}, err
	}
	password, err := secure.RandomToken(24)
	if err != nil {
		return model.VPNGateExit{}, err
	}
	now := time.Now().UTC()
	exit := model.VPNGateExit{
		Slot: slot, Name: input.Name, Country: input.Country,
		Namespace:    "jui-vpn-" + fmt.Sprint(slot),
		LocalAddress: "10.254." + fmt.Sprint(slot) + ".2", LocalPort: 1080,
		Status: "provisioning", FailurePolicy: input.FailurePolicy,
		Permanent: input.Permanent, CreatedAt: now, UpdatedAt: now,
	}
	if !input.Permanent {
		expiry := now.Add(time.Duration(input.DurationMinutes) * time.Minute)
		exit.ExpiresAt = &expiry
	}
	exit.CandidateHostName = ranked[0].HostName
	exit.CandidateIP = ranked[0].IP
	outbound := model.Outbound{
		Name: input.Name, Type: model.OutboundSOCKS5, Server: exit.LocalAddress,
		Port: exit.LocalPort, Enabled: true, Username: username, Password: password,
		ManagedKind: "vpngate", Status: "unchecked", Country: input.Country,
	}
	mutationCtx, cancel := s.operationContext(ctx)
	defer cancel()
	exit, err = s.store.CreateVPNGateExit(mutationCtx, outbound, exit)
	if err != nil {
		return model.VPNGateExit{}, err
	}
	exit, observed, provisionErr := s.tryCandidates(
		mutationCtx, exit, ranked, username, password,
	)
	if provisionErr != nil {
		exit.Status = "faulted"
		exit.LastError = provisionErr.Error()
		exit.ObservedIP = ""
		fallbackCtx := context.WithoutCancel(mutationCtx)
		_ = s.store.UpdateVPNGateExit(fallbackCtx, exit)
		_ = s.updateOutboundHealth(fallbackCtx, exit, false)
		s.recordEvent(fallbackCtx, "error", "vpngate_connect_failed",
			fmt.Sprintf("VPNGate 出口 %s 创建失败，流量已阻断", exit.Name))
		return exit, problem.New(
			problem.Unavailable, "vpngate_connect_failed",
			"VPNGate 候选均连接失败，流量保持阻断", provisionErr,
		)
	}
	exit.Status = "running"
	exit.ObservedIP = observed
	checkedAt := time.Now().UTC()
	exit.LastCheckedAt = &checkedAt
	exit.LastError = ""
	if err := s.persistRunning(mutationCtx, exit); err != nil {
		return model.VPNGateExit{}, err
	}
	created, err := s.store.VPNGateExit(mutationCtx, exit.ID)
	if err == nil {
		s.recordEvent(mutationCtx, "info", "vpngate_exit_created",
			fmt.Sprintf("VPNGate 出口 %s 已连接并完成出口 IP 验证", created.Name))
	}
	return created, err
}

func (s *Service) Swap(ctx context.Context, id int64) (model.VPNGateExit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.swapLocked(ctx, id)
}

func (s *Service) swapLocked(ctx context.Context, id int64) (model.VPNGateExit, error) {
	exit, err := s.store.VPNGateExit(ctx, id)
	if err != nil {
		return exit, err
	}
	outbound, err := s.store.Outbound(ctx, exit.OutboundID)
	if err != nil {
		return exit, err
	}
	exits, err := s.store.ListVPNGateExits(ctx)
	if err != nil {
		return exit, err
	}
	candidates, err := s.cachedCandidates(ctx)
	if err != nil {
		return exit, err
	}
	excluded := activeCandidates(exits, exit.ID)
	excluded[exit.CandidateHostName] = true
	ranked := FilterAndRank(candidates, Filter{Country: exit.Country}, excluded)
	if len(ranked) > 6 {
		ranked = ranked[:6]
	}
	if len(ranked) == 0 {
		return exit, conflictError(errors.New("同地区没有可替换的 VPNGate 候选"))
	}
	mutationCtx, cancel := s.operationContext(ctx)
	defer cancel()
	if err := s.orchestrator.Stop(mutationCtx, exit); err != nil {
		exit.Status = "faulted"
		exit.ObservedIP = ""
		exit.LastError = "旧出口清理失败，未启动新候选：" + err.Error()
		fallbackCtx := context.WithoutCancel(mutationCtx)
		_ = s.store.UpdateVPNGateExit(fallbackCtx, exit)
		_ = s.updateOutboundHealth(fallbackCtx, exit, false)
		s.recordEvent(fallbackCtx, "error", "vpngate_cleanup_failed",
			fmt.Sprintf("VPNGate 出口 %s 清理失败，未启动新候选", exit.Name))
		return exit, problem.New(
			problem.Unavailable, "vpngate_cleanup_failed",
			"旧 VPNGate 出口清理失败，流量保持阻断", err,
		)
	}
	exit.Status = "swapping"
	exit.ObservedIP = ""
	exit.LastError = ""
	if err := s.store.UpdateVPNGateExit(mutationCtx, exit); err != nil {
		return exit, err
	}
	exit, observed, provisionErr := s.tryCandidates(
		mutationCtx, exit, ranked, outbound.Username, outbound.Password,
	)
	if provisionErr != nil {
		exit.Status = "faulted"
		exit.LastError = provisionErr.Error()
		exit.ObservedIP = ""
		_ = s.store.UpdateVPNGateExit(context.WithoutCancel(mutationCtx), exit)
		_ = s.updateOutboundHealth(context.WithoutCancel(mutationCtx), exit, false)
		s.recordEvent(context.WithoutCancel(mutationCtx), "error", "vpngate_swap_failed",
			fmt.Sprintf("VPNGate 出口 %s 更换失败，流量已阻断", exit.Name))
		return exit, problem.New(
			problem.Unavailable, "vpngate_swap_failed",
			"VPNGate 更换失败，流量保持阻断", provisionErr,
		)
	}
	exit.Status = "running"
	exit.ObservedIP = observed
	checkedAt := time.Now().UTC()
	exit.LastCheckedAt = &checkedAt
	exit.LastError = ""
	if err := s.persistRunning(mutationCtx, exit); err != nil {
		return exit, err
	}
	updated, err := s.store.VPNGateExit(mutationCtx, id)
	if err == nil {
		s.recordEvent(mutationCtx, "info", "vpngate_exit_swapped",
			fmt.Sprintf("VPNGate 出口 %s 已更换并重新验证出口 IP", updated.Name))
	}
	return updated, err
}

func (s *Service) Extend(ctx context.Context, id int64, input ExtendInput) (model.VPNGateExit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	exit, err := s.store.VPNGateExit(ctx, id)
	if err != nil {
		return exit, err
	}
	if !input.Permanent && (input.DurationMinutes < 5 || input.DurationMinutes > 24*60) {
		return exit, validationError(errors.New("延长时间必须在 5 分钟到 24 小时之间"))
	}
	exit.Permanent = input.Permanent
	exit.ExpiresAt = nil
	if !input.Permanent {
		expiry := time.Now().UTC().Add(time.Duration(input.DurationMinutes) * time.Minute)
		exit.ExpiresAt = &expiry
	}
	if err := s.store.UpdateVPNGateExit(ctx, exit); err != nil {
		return exit, err
	}
	updated, err := s.store.VPNGateExit(ctx, id)
	if err == nil {
		s.recordEvent(ctx, "info", "vpngate_exit_extended",
			fmt.Sprintf("VPNGate 出口 %s 的运行时间已更新", updated.Name))
	}
	return updated, err
}

func (s *Service) Delete(ctx context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	exit, err := s.store.VPNGateExit(ctx, id)
	if err != nil {
		return err
	}
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return err
	}
	for _, node := range nodes {
		if node.OutboundID != nil && *node.OutboundID == exit.OutboundID {
			return conflictError(errors.New("出口仍被节点使用，请先解除绑定"))
		}
	}
	mutationCtx, cancel := s.operationContext(ctx)
	defer cancel()
	if err := s.orchestrator.Stop(mutationCtx, exit); err != nil {
		return err
	}
	if err := s.store.DeleteVPNGateExit(mutationCtx, id); err != nil {
		return err
	}
	delete(s.healthFailures, id)
	s.recordEvent(mutationCtx, "info", "vpngate_exit_deleted",
		fmt.Sprintf("VPNGate 出口 %s 已停止并清理", exit.Name))
	return nil
}

func (s *Service) Reconcile(ctx context.Context) error {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	snapshot, err := s.store.ListVPNGateExits(ctx)
	if err != nil {
		return err
	}
	results := make(map[int64]exitHealthResult)
	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	var healthMu sync.Mutex
	var healthWait sync.WaitGroup
	for _, exit := range snapshot {
		if exit.Status != "running" || (exit.ExpiresAt != nil && time.Now().After(*exit.ExpiresAt)) {
			continue
		}
		exit := exit
		healthWait.Add(1)
		go func() {
			defer healthWait.Done()
			result := exitHealthResult{
				updatedAt:         exit.UpdatedAt,
				candidateHostName: exit.CandidateHostName,
				candidateIP:       exit.CandidateIP,
				observedIP:        exit.ObservedIP,
				remoteProtocol:    exit.RemoteProtocol,
				remotePort:        exit.RemotePort,
				namespace:         exit.Namespace,
				healthy:           s.orchestrator.Healthy(healthCtx, exit),
			}
			healthMu.Lock()
			results[exit.ID] = result
			healthMu.Unlock()
		}()
	}
	healthWait.Wait()
	cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reconcileLocked(ctx, results)
}

func (s *Service) reconcileLocked(
	ctx context.Context,
	health map[int64]exitHealthResult,
) error {
	exits, err := s.store.ListVPNGateExits(ctx)
	if err != nil {
		return err
	}
	for _, exit := range exits {
		if exit.ExpiresAt != nil && time.Now().After(*exit.ExpiresAt) {
			if err := s.expire(ctx, exit); err != nil {
				return err
			}
			continue
		}
		if exit.Status == "running" {
			result, checked := health[exit.ID]
			if !checked || !result.matches(exit) {
				continue
			}
			if result.healthy {
				delete(s.healthFailures, exit.ID)
				continue
			}
			s.healthFailures[exit.ID]++
			if s.healthFailures[exit.ID] < 2 {
				continue
			}
		}
		delete(s.healthFailures, exit.ID)
		switch exit.Status {
		case "running", "provisioning", "swapping":
			if err := s.restoreCurrentLocked(ctx, exit); err == nil {
				continue
			}
			if exit.FailurePolicy == "auto_swap" {
				if _, err := s.swapLocked(ctx, exit.ID); err == nil {
					continue
				}
			}
			if err := s.block(ctx, exit, "VPNGate 隧道恢复失败，流量已阻断"); err != nil {
				return err
			}
			continue
		case "faulted":
			if exit.FailurePolicy == "auto_swap" {
				if _, err := s.swapLocked(ctx, exit.ID); err == nil {
					continue
				}
			}
		}
	}
	return nil
}

func (s *Service) restoreCurrentLocked(ctx context.Context, exit model.VPNGateExit) error {
	if exit.CandidateHostName == "" || exit.CandidateIP == "" {
		return errors.New("VPNGate exit has no previous candidate")
	}
	candidate, err := s.store.VPNGateCandidate(ctx, exit.CandidateHostName)
	if err != nil {
		return err
	}
	if candidate.IP != exit.CandidateIP {
		return errors.New("VPNGate candidate endpoint changed")
	}
	outbound, err := s.store.Outbound(ctx, exit.OutboundID)
	if err != nil {
		return err
	}
	config, remote, err := SanitizeOpenVPN(candidate.OpenVPNConfig, candidate.IP)
	if err != nil {
		return err
	}
	mutationCtx, cancel := s.operationContext(ctx)
	defer cancel()
	exit.Status = "provisioning"
	exit.ObservedIP = ""
	exit.LastError = ""
	exit.RemoteProtocol = remote.Protocol
	exit.RemotePort = remote.Port
	if err := s.store.UpdateVPNGateExit(mutationCtx, exit); err != nil {
		return err
	}
	observed, err := s.orchestrator.Provision(
		mutationCtx, exit, candidate, config, outbound.Username, outbound.Password,
	)
	if err != nil {
		return err
	}
	exit.Status = "running"
	exit.ObservedIP = observed
	checkedAt := time.Now().UTC()
	exit.LastCheckedAt = &checkedAt
	if err := s.persistRunning(mutationCtx, exit); err != nil {
		return err
	}
	s.recordEvent(mutationCtx, "info", "vpngate_exit_restored",
		fmt.Sprintf("VPNGate 出口 %s 已恢复并重新验证出口 IP", exit.Name))
	return nil
}

func (s *Service) tryCandidates(
	ctx context.Context,
	exit model.VPNGateExit,
	candidates []model.VPNGateCandidate,
	username, password string,
) (model.VPNGateExit, string, error) {
	var failures []error
	for _, candidate := range candidates {
		config, remote, err := SanitizeOpenVPN(candidate.OpenVPNConfig, candidate.IP)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", candidate.HostName, err))
			continue
		}
		exit.CandidateHostName = candidate.HostName
		exit.CandidateIP = candidate.IP
		exit.RemoteProtocol = remote.Protocol
		exit.RemotePort = remote.Port
		if err := s.store.UpdateVPNGateExit(ctx, exit); err != nil {
			return exit, "", err
		}
		observed, err := s.orchestrator.Provision(ctx, exit, candidate, config, username, password)
		if err == nil {
			return exit, observed, nil
		}
		failures = append(failures, fmt.Errorf("%s: %w", candidate.HostName, err))
	}
	return exit, "", errors.Join(failures...)
}

func (s *Service) cachedCandidates(ctx context.Context) ([]model.VPNGateCandidate, error) {
	candidates, err := s.store.ListVPNGateCandidates(ctx)
	if err != nil {
		return nil, err
	}
	if len(candidates) != 0 && time.Since(candidates[0].FetchedAt) < 15*time.Minute {
		return candidates, nil
	}
	refreshed, refreshErr := s.fetcher.Fetch(ctx)
	if refreshErr == nil {
		if err := s.store.ReplaceVPNGateCandidates(ctx, refreshed); err != nil {
			return nil, err
		}
		return refreshed, nil
	}
	if len(candidates) != 0 {
		return candidates, nil
	}
	return nil, problem.New(
		problem.Unavailable, "vpngate_unavailable", "VPNGate 列表暂时不可用", refreshErr,
	)
}

func (s *Service) updateOutboundHealth(ctx context.Context, exit model.VPNGateExit, healthy bool) error {
	outbound, err := s.store.Outbound(ctx, exit.OutboundID)
	if err != nil {
		return err
	}
	checkedAt := time.Now().UTC()
	outbound.LastCheckedAt = &checkedAt
	outbound.ObservedIP = exit.ObservedIP
	outbound.Country = exit.Country
	outbound.Status = "healthy"
	outbound.LastError = ""
	if !healthy {
		outbound.Status = "unhealthy"
		outbound.ObservedIP = ""
		outbound.LastError = exit.LastError
	}
	return s.store.UpdateOutbound(ctx, outbound)
}

func (s *Service) persistRunning(ctx context.Context, exit model.VPNGateExit) error {
	if err := s.store.UpdateVPNGateExitAndHealth(ctx, exit, true); err != nil {
		fallbackCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		stopErr := s.orchestrator.Stop(fallbackCtx, exit)
		exit.Status = "faulted"
		exit.ObservedIP = ""
		exit.LastError = "状态保存失败，新隧道已停止"
		exit.LastCheckedAt = nil
		exitErr := s.store.UpdateVPNGateExit(fallbackCtx, exit)
		healthErr := s.updateOutboundHealth(fallbackCtx, exit, false)
		s.recordEvent(fallbackCtx, "error", "vpngate_state_commit_failed",
			fmt.Sprintf("VPNGate 出口 %s 状态保存失败，新隧道已停止", exit.Name))
		return errors.Join(err, stopErr, exitErr, healthErr)
	}
	return nil
}

func (s *Service) expire(ctx context.Context, exit model.VPNGateExit) error {
	exit.Status = "expired"
	exit.LastError = "临时出口已到期，等待关联节点清理"
	exit.ObservedIP = ""
	if err := s.orchestrator.Stop(ctx, exit); err != nil {
		exit.LastError = "到期清理不完整：" + err.Error()
		if updateErr := s.store.UpdateVPNGateExit(ctx, exit); updateErr != nil {
			return errors.Join(err, updateErr)
		}
		_ = s.updateOutboundHealth(ctx, exit, false)
		return err
	}
	if err := s.store.DeleteVPNGateExit(ctx, exit.ID); err != nil {
		if updateErr := s.store.UpdateVPNGateExit(ctx, exit); updateErr != nil {
			return errors.Join(err, updateErr)
		}
		if healthErr := s.updateOutboundHealth(ctx, exit, false); healthErr != nil {
			return errors.Join(err, healthErr)
		}
		if database.IsConflict(err) {
			return nil
		}
		return err
	}
	delete(s.healthFailures, exit.ID)
	s.recordEvent(ctx, "info", "vpngate_exit_expired",
		fmt.Sprintf("VPNGate 出口 %s 已到期并自动清理", exit.Name))
	return nil
}

func (s *Service) block(ctx context.Context, exit model.VPNGateExit, message string) error {
	exit.Status = "faulted"
	exit.LastError = message
	exit.ObservedIP = ""
	if err := s.orchestrator.Stop(ctx, exit); err != nil {
		exit.LastError += "；隔离资源清理不完整：" + err.Error()
	}
	if err := s.store.UpdateVPNGateExit(ctx, exit); err != nil {
		return err
	}
	if err := s.updateOutboundHealth(ctx, exit, false); err != nil {
		return err
	}
	s.recordEvent(ctx, "error", "vpngate_exit_blocked",
		fmt.Sprintf("VPNGate 出口 %s 异常，流量已阻断", exit.Name))
	return nil
}

func (s *Service) recordEvent(ctx context.Context, level, code, message string) {
	_ = s.store.RecordEvent(ctx, level, code, message)
}

func (s *Service) watch() {
	defer close(s.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			_ = s.Reconcile(ctx)
			cancel()
		}
	}
}

func (s *Service) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), s.timeout)
}

func validateCreateInput(input CreateInput) (CreateInput, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.Country = strings.ToUpper(strings.TrimSpace(input.Country))
	input.CandidateHostName = strings.TrimSpace(input.CandidateHostName)
	if input.Name == "" {
		return input, errors.New("出口名称不能为空")
	}
	if len(input.Country) != 2 {
		return input, errors.New("国家代码必须是两个字母")
	}
	for _, character := range input.Country {
		if character < 'A' || character > 'Z' {
			return input, errors.New("国家代码必须是两个字母")
		}
	}
	if !input.Permanent && (input.DurationMinutes < 5 || input.DurationMinutes > 24*60) {
		return input, errors.New("临时出口时长必须在 5 分钟到 24 小时之间")
	}
	if input.FailurePolicy == "" {
		input.FailurePolicy = "auto_swap"
	}
	if input.FailurePolicy != "block" && input.FailurePolicy != "auto_swap" {
		return input, errors.New("故障策略必须是 block 或 auto_swap")
	}
	return input, nil
}

func availableSlot(exits []model.VPNGateExit, maximum int) int {
	used := make(map[int]bool)
	for _, exit := range exits {
		used[exit.Slot] = true
	}
	for slot := 1; slot <= maximum; slot++ {
		if !used[slot] {
			return slot
		}
	}
	return 0
}

func activeCandidates(exits []model.VPNGateExit, ignoreID int64) map[string]bool {
	excluded := make(map[string]bool)
	for _, exit := range exits {
		if exit.ID != ignoreID && exit.CandidateHostName != "" &&
			exit.Status != "stopped" && exit.Status != "expired" {
			excluded[exit.CandidateHostName] = true
		}
	}
	return excluded
}

func validationError(err error) error {
	return problem.New(problem.Validation, "validation_failed", err.Error(), err)
}

func conflictError(err error) error {
	return problem.New(problem.Conflict, "resource_conflict", err.Error(), err)
}
