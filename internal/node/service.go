package node

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Suparluxi/j-ui/internal/database"
	"github.com/Suparluxi/j-ui/internal/engine"
	"github.com/Suparluxi/j-ui/internal/engine/singbox"
	"github.com/Suparluxi/j-ui/internal/exitcheck"
	"github.com/Suparluxi/j-ui/internal/firewall"
	"github.com/Suparluxi/j-ui/internal/model"
	"github.com/Suparluxi/j-ui/internal/problem"
	"github.com/Suparluxi/j-ui/internal/secure"
)

type CreateInput struct {
	Name               string         `json:"name"`
	Protocol           string         `json:"protocol"`
	Listen             string         `json:"listen"`
	Port               int            `json:"port"`
	Enabled            bool           `json:"enabled"`
	ClientName         string         `json:"clientName"`
	Credential         map[string]any `json:"credential"`
	PublicHostOverride string         `json:"publicHostOverride"`
	Settings           map[string]any `json:"settings"`
	ConfirmPublicSOCKS bool           `json:"confirmPublicSocks"`
	OutboundID         *int64         `json:"outboundId"`
}

type UpdateInput struct {
	Name               string         `json:"name"`
	Listen             string         `json:"listen"`
	Port               int            `json:"port"`
	Enabled            bool           `json:"enabled"`
	PublicHostOverride string         `json:"publicHostOverride"`
	Settings           map[string]any `json:"settings"`
	ConfirmPublicSOCKS bool           `json:"confirmPublicSocks"`
	OutboundID         *int64         `json:"outboundId"`
}

const DefaultStartPort = 8881

const (
	TemporarySourceSetting  = "jui_temporary_source"
	TemporaryExpirySetting  = "jui_temporary_expires_at"
	TemporaryCountrySetting = "jui_temporary_country"
)

type PortSettings struct {
	StartPort int `json:"startPort"`
	NextPort  int `json:"nextPort"`
}

type OutboundInput struct {
	Name           string `json:"name"`
	Type           string `json:"type"`
	Server         string `json:"server"`
	Port           int    `json:"port"`
	Enabled        bool   `json:"enabled"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	CredentialMode string `json:"credentialMode"`
}

type Service struct {
	store            *database.Store
	engine           engine.Engine
	firewall         firewall.Manager
	firewallVerified bool
	operationTimeout time.Duration
	certificateDir   string
	allowSelfSigned  bool
	outboundChecker  OutboundChecker
	mu               sync.Mutex
}

type OutboundChecker interface {
	Check(context.Context, model.Outbound) (exitcheck.Result, error)
}

type OutboundCheckFunc func(context.Context, model.Outbound) (exitcheck.Result, error)

func (f OutboundCheckFunc) Check(ctx context.Context, outbound model.Outbound) (exitcheck.Result, error) {
	return f(ctx, outbound)
}

// ConfigureAutomaticCertificates enables certificate discovery for TLS nodes.
// Self-signed generation is deliberately restricted to mock/demo deployments.
func (s *Service) ConfigureAutomaticCertificates(directory string, allowSelfSigned bool) {
	s.certificateDir = directory
	s.allowSelfSigned = allowSelfSigned
}

func (s *Service) ConfigureOutboundChecker(checker OutboundChecker) {
	if checker != nil {
		s.outboundChecker = checker
	}
}

// VerifyAutomaticCertificate confirms that a TLS node can load a certificate for serverName.
func (s *Service) VerifyAutomaticCertificate(serverName string) error {
	return s.prepareAutomaticCertificate(model.ProtocolVLESSWSTLS, map[string]any{
		"server_name": serverName, "certificate_mode": "auto",
	})
}

// VerifyCertificate confirms that a manually configured certificate and key are usable for serverName.
func (s *Service) VerifyCertificate(serverName, certificatePath, keyPath string) error {
	return validateCertificateSettings(map[string]any{
		"server_name": serverName, "certificate_path": certificatePath, "key_path": keyPath,
	})
}

type compensationStep struct {
	name string
	run  func(context.Context) error
}

func NewService(store *database.Store, proxyEngine engine.Engine, firewallManager firewall.Manager) *Service {
	return &Service{
		store: store, engine: proxyEngine, firewall: firewallManager,
		operationTimeout: 30 * time.Second,
	}
}

func (s *Service) PortSettings(ctx context.Context) (PortSettings, error) {
	startPort, err := s.startPort(ctx)
	if err != nil {
		return PortSettings{}, err
	}
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return PortSettings{}, err
	}
	nextPort, err := nextConfiguredPort(startPort, nodes)
	if err != nil {
		return PortSettings{}, conflictError(err)
	}
	return PortSettings{StartPort: startPort, NextPort: nextPort}, nil
}

func (s *Service) SetStartPort(ctx context.Context, startPort int) (PortSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if startPort < 1 || startPort > 65535 {
		return PortSettings{}, validationError(errors.New("start port must be between 1 and 65535"))
	}
	previousStart, err := s.startPort(ctx)
	if err != nil {
		return PortSettings{}, err
	}
	previous, err := s.store.ListNodes(ctx)
	if err != nil {
		return PortSettings{}, err
	}
	managedListeners := make(map[string]bool)
	for _, node := range previous {
		if !node.Enabled {
			continue
		}
		for _, network := range firewallProtocols(node.Protocol) {
			managedListeners[fmt.Sprintf("%s/%d", network, node.Port)] = true
		}
	}
	candidates := make([]model.Node, len(previous))
	copy(candidates, previous)
	usedPorts := make(map[int]bool, len(candidates))
	// Argo listeners are fixed to their cloudflared origin ports. Reserve them
	// before reallocating other nodes so an earlier sequential node cannot take
	// a port that a later Argo node must retain.
	for _, candidate := range candidates {
		if candidate.Protocol == model.ProtocolVLESSArgo {
			if usedPorts[candidate.Port] {
				return PortSettings{}, conflictError(fmt.Errorf("Argo origin port %d conflicts with another node", candidate.Port))
			}
			usedPorts[candidate.Port] = true
		}
	}
	for index := range candidates {
		port := candidates[index].Port
		if candidates[index].Protocol != model.ProtocolVLESSArgo {
			port, err = nextProtocolPort(startPort, candidates[index].Protocol, usedPorts, func(candidate int) bool {
				for _, network := range firewallProtocols(candidates[index].Protocol) {
					if managedListeners[fmt.Sprintf("%s/%d", network, candidate)] {
						continue
					}
					if checkNetworkPort(network, candidates[index].Listen, candidate) != nil {
						return false
					}
				}
				return true
			})
			if err != nil {
				return PortSettings{}, conflictError(err)
			}
		}
		usedPorts[port] = true
		oldSuffix := "_" + strconv.Itoa(candidates[index].Port)
		if strings.HasSuffix(candidates[index].Name, oldSuffix) {
			candidates[index].Name = strings.TrimSuffix(candidates[index].Name, oldSuffix) + "_" + strconv.Itoa(port)
		}
		candidates[index].Port = port
		candidates[index].Status = "pending"
	}
	mutationCtx, cancel := s.detachedContext(ctx)
	defer cancel()
	if err := s.store.SetNodePortsAndStart(mutationCtx, startPort, candidates); err != nil {
		if database.IsConflict(err) {
			return PortSettings{}, conflictError(err)
		}
		return PortSettings{}, err
	}
	if err := s.reconcile(mutationCtx); err != nil {
		return PortSettings{}, s.compensate(mutationCtx, err,
			compensationStep{"restore previous node ports and start port", func(rollbackCtx context.Context) error {
				return s.store.SetNodePortsAndStart(rollbackCtx, previousStart, previous)
			}},
			compensationStep{"restore previous sing-box configuration and firewall rules", func(rollbackCtx context.Context) error {
				return s.reconcile(rollbackCtx)
			}},
		)
	}
	return PortSettings{StartPort: startPort, NextPort: startPort + len(candidates)}, nil
}

func (s *Service) startPort(ctx context.Context) (int, error) {
	raw, err := s.store.Setting(ctx, "node_start_port")
	if err != nil {
		if database.IsNotFound(err) {
			return DefaultStartPort, nil
		}
		return 0, err
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("stored node start port is invalid")
	}
	return port, nil
}

func nextConfiguredPort(startPort int, nodes []model.Node) (int, error) {
	used := make(map[int]bool, len(nodes))
	for _, node := range nodes {
		used[node.Port] = true
	}
	for port := startPort; port <= 65535; port++ {
		if !used[port] {
			return port, nil
		}
	}
	return 0, errors.New("no available node port remains")
}

func nextProtocolPort(
	startPort int,
	protocol string,
	used map[int]bool,
	available func(int) bool,
) (int, error) {
	if protocol == model.ProtocolVLESSWSTLS {
		for _, port := range model.CloudflareHTTPSPorts() {
			if !used[port] && available(port) {
				return port, nil
			}
		}
		return 0, errors.New("Cloudflare 支持的 HTTPS 端口均已被占用：443、2053、2083、2087、2096、8443")
	}
	for port := startPort; port <= 65535; port++ {
		if !used[port] && available(port) {
			return port, nil
		}
	}
	return 0, errors.New("no available node port remains")
}

func (s *Service) nextAvailablePort(ctx context.Context, protocol, listen string) (int, error) {
	startPort, err := s.startPort(ctx)
	if err != nil {
		return 0, err
	}
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return 0, err
	}
	used := make(map[int]bool, len(nodes))
	for _, node := range nodes {
		used[node.Port] = true
	}
	port, err := nextProtocolPort(startPort, protocol, used, func(port int) bool {
		return checkPort(protocol, listen, port) == nil
	})
	if err != nil {
		return 0, conflictError(err)
	}
	return port, nil
}

func (s *Service) ListOutbounds(ctx context.Context) ([]model.Outbound, error) {
	return s.store.ListOutbounds(ctx)
}

func (s *Service) CreateOutbound(ctx context.Context, input OutboundInput) (model.Outbound, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	outbound, err := validateOutboundInput(input)
	if err != nil {
		return model.Outbound{}, validationError(err)
	}
	if input.CredentialMode == "clear" {
		outbound.Username = ""
		outbound.Password = ""
	}
	mutationCtx, cancel := s.detachedContext(ctx)
	defer cancel()
	created, err := s.store.CreateOutbound(mutationCtx, outbound)
	if err != nil {
		return model.Outbound{}, err
	}
	if err := s.reconcile(mutationCtx); err != nil {
		return model.Outbound{}, s.compensate(mutationCtx, err,
			compensationStep{"delete candidate outbound", func(rollbackCtx context.Context) error {
				return s.store.DeleteOutbound(rollbackCtx, created.ID)
			}},
			compensationStep{"restore previous sing-box configuration", func(rollbackCtx context.Context) error {
				return s.reconcile(rollbackCtx)
			}},
		)
	}
	return s.store.Outbound(mutationCtx, created.ID)
}

func (s *Service) UpdateOutbound(ctx context.Context, id int64, input OutboundInput) (model.Outbound, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, err := s.store.Outbound(ctx, id)
	if err != nil {
		return model.Outbound{}, err
	}
	if previous.ManagedKind != "" && previous.ManagedKind != "manual" {
		return model.Outbound{}, conflictError(errors.New("managed outbound must be changed from its provider page"))
	}
	candidate, err := validateOutboundInput(input)
	if err != nil {
		return model.Outbound{}, validationError(err)
	}
	candidate.ID = id
	candidate.CreatedAt = previous.CreatedAt
	candidate.Status = "unchecked"
	switch input.CredentialMode {
	case "", "keep":
		candidate.Username = previous.Username
		candidate.Password = previous.Password
	case "replace":
	case "clear":
		candidate.Username = ""
		candidate.Password = ""
	default:
		return model.Outbound{}, validationError(errors.New("credentialMode must be keep, replace, or clear"))
	}
	if candidate.Password != "" && candidate.Username == "" {
		return model.Outbound{}, validationError(errors.New("username is required when password is set"))
	}
	mutationCtx, cancel := s.detachedContext(ctx)
	defer cancel()
	if err := s.store.UpdateOutbound(mutationCtx, candidate); err != nil {
		return model.Outbound{}, err
	}
	if err := s.reconcile(mutationCtx); err != nil {
		return model.Outbound{}, s.compensate(mutationCtx, err,
			compensationStep{"restore previous outbound", func(rollbackCtx context.Context) error {
				return s.store.UpdateOutbound(rollbackCtx, previous)
			}},
			compensationStep{"restore previous sing-box configuration", func(rollbackCtx context.Context) error {
				return s.reconcile(rollbackCtx)
			}},
		)
	}
	return s.store.Outbound(mutationCtx, id)
}

func (s *Service) DeleteOutbound(ctx context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, err := s.store.Outbound(ctx, id)
	if err != nil {
		return err
	}
	if previous.ManagedKind != "" && previous.ManagedKind != "manual" {
		return conflictError(errors.New("managed outbound must be removed from its provider page"))
	}
	mutationCtx, cancel := s.detachedContext(ctx)
	defer cancel()
	if err := s.store.DeleteOutbound(mutationCtx, id); err != nil {
		if database.IsConflict(err) {
			return conflictError(errors.New("出口仍被节点使用，请先解除绑定"))
		}
		return err
	}
	if err := s.reconcile(mutationCtx); err != nil {
		return s.compensate(mutationCtx, err,
			compensationStep{"restore deleted outbound", func(rollbackCtx context.Context) error {
				return s.store.RestoreOutbound(rollbackCtx, previous)
			}},
			compensationStep{"restore previous sing-box configuration", func(rollbackCtx context.Context) error {
				return s.reconcile(rollbackCtx)
			}},
		)
	}
	return nil
}

func (s *Service) CheckOutbound(ctx context.Context, id int64) (model.Outbound, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	outbound, err := s.store.Outbound(ctx, id)
	if err != nil {
		return model.Outbound{}, err
	}
	checkedAt := time.Now().UTC()
	checker := s.outboundChecker
	if checker == nil {
		checker = exitcheck.New()
	}
	result, checkErr := checker.Check(ctx, outbound)
	outbound.LastCheckedAt = &checkedAt
	if checkErr != nil {
		outbound.Status = "unhealthy"
		outbound.LastError = checkErr.Error()
		outbound.ObservedIP = ""
		outbound.Country = ""
		outbound.ASN = ""
	} else {
		outbound.Status = "healthy"
		outbound.ObservedIP = result.IP
		outbound.Country = result.Country
		outbound.ASN = result.ASN
		outbound.LastError = ""
	}
	if err := s.store.UpdateOutbound(context.WithoutCancel(ctx), outbound); err != nil {
		return model.Outbound{}, err
	}
	sanitized, err := s.store.Outbound(context.WithoutCancel(ctx), id)
	if err != nil {
		return model.Outbound{}, err
	}
	if checkErr != nil {
		return sanitized, problem.New(
			problem.Unavailable, "outbound_check_failed", outboundCheckMessage(checkErr), checkErr,
		)
	}
	return sanitized, nil
}

func outboundCheckMessage(err error) string {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "authentication"), strings.Contains(message, "username or password"), strings.Contains(message, "status 407"):
		return "上游代理认证失败，请检查用户名和密码"
	case strings.Contains(message, "connection refused"):
		return "上游代理拒绝连接，请检查代理地址、端口和服务状态"
	case strings.Contains(message, "timeout"), strings.Contains(message, "deadline exceeded"):
		return "连接上游代理超时，请检查代理地址、端口和网络"
	default:
		return "无法通过该 SOCKS5/HTTP CONNECT 上游代理访问互联网，请确认它是可用的代理服务"
	}
}

func validateOutboundInput(input OutboundInput) (model.Outbound, error) {
	name := strings.TrimSpace(input.Name)
	server, port, hostErr := validateOutboundEndpoint(input.Server, input.Port)
	if name == "" {
		return model.Outbound{}, errors.New("name is required")
	}
	if !model.SupportedOutbound(input.Type) {
		return model.Outbound{}, errors.New("type must be socks5 or http")
	}
	if hostErr != nil {
		return model.Outbound{}, fmt.Errorf("代理地址: %w", hostErr)
	}
	if port < 1 || port > 65535 {
		return model.Outbound{}, errors.New("port must be between 1 and 65535")
	}
	if input.CredentialMode != "keep" && input.CredentialMode != "clear" &&
		input.Password != "" && input.Username == "" {
		return model.Outbound{}, errors.New("username is required when password is set")
	}
	return model.Outbound{
		Name: name, Type: input.Type, Server: server, Port: port,
		Enabled: input.Enabled, Username: input.Username, Password: input.Password,
		Status: "unchecked",
	}, nil
}

func validateOutboundEndpoint(value string, fallbackPort int) (string, int, error) {
	value = strings.TrimSpace(value)
	if host, portText, err := net.SplitHostPort(value); err == nil {
		port, parseErr := strconv.Atoi(portText)
		if parseErr != nil || port < 1 || port > 65535 {
			return "", 0, errors.New("端口无效")
		}
		normalized, hostErr := validateEndpointHost(host)
		if hostErr != nil {
			return "", 0, errors.New("必须包含有效的域名或 IP")
		}
		return normalized, port, nil
	}
	normalized, err := validateEndpointHost(value)
	if err != nil {
		return "", 0, errors.New("必须是域名或 IP，可以附带 :端口")
	}
	return normalized, fallbackPort, nil
}

func (s *Service) validateOutboundBinding(ctx context.Context, id *int64, nodeEnabled bool, ignoreNodeID int64) error {
	if id == nil {
		return nil
	}
	outbound, err := s.store.Outbound(ctx, *id)
	if err != nil {
		if database.IsNotFound(err) {
			return validationError(errors.New("selected outbound does not exist"))
		}
		return err
	}
	if nodeEnabled && !outbound.Enabled {
		return conflictError(errors.New("selected outbound is disabled"))
	}
	return nil
}

func (s *Service) compensate(ctx context.Context, primary error, steps ...compensationStep) error {
	failures := []error{primary}
	for _, step := range steps {
		rollbackCtx, cancel := s.detachedContext(ctx)
		err := step.run(rollbackCtx)
		cancel()
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", step.name, err))
		}
	}
	if len(failures) == 1 {
		return primary
	}
	eventCtx, cancel := s.detachedContext(ctx)
	defer cancel()
	_ = s.store.RecordEvent(eventCtx, "error", "rollback_incomplete",
		"自动回滚未能完整执行；请检查节点、sing-box 配置和防火墙状态")
	return errors.Join(failures...)
}

func (s *Service) List(ctx context.Context) ([]model.Node, error) {
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	engineHealthy := s.engine.Healthy(ctx)
	publicHost, _ := s.store.Setting(ctx, "public_host")
	bulk, canBulk := s.engine.(engine.BulkListenerChecker)
	var allListeners []engine.Listener
	offsets := make([]int, len(nodes)+1)
	if engineHealthy && canBulk {
		for index := range nodes {
			offsets[index] = len(allListeners)
			if nodes[index].Enabled {
				allListeners = append(allListeners, listenersForNode(nodes[index])...)
			}
		}
		offsets[len(nodes)] = len(allListeners)
	}
	var listenerStatuses []bool
	if len(allListeners) != 0 {
		listenerStatuses, err = bulk.ListenerStatuses(ctx, allListeners)
		if err != nil {
			listenerStatuses = nil
		}
	}
	for index := range nodes {
		healthy := engineHealthy
		if nodes[index].Enabled && healthy {
			if canBulk {
				healthy = listenerStatuses != nil &&
					allHealthy(listenerStatuses[offsets[index]:offsets[index+1]])
			} else {
				healthy = s.engine.ListenersHealthy(ctx, listenersForNode(nodes[index])) == nil
			}
		}
		nodes[index].Status = liveStatus(nodes[index].Enabled, healthy)
		decorateNode(&nodes[index], publicHost)
	}
	return nodes, nil
}

func allHealthy(statuses []bool) bool {
	for _, healthy := range statuses {
		if !healthy {
			return false
		}
	}
	return true
}

func (s *Service) Get(ctx context.Context, id int64) (model.Node, error) {
	node, err := s.store.Node(ctx, id)
	if err != nil {
		return node, err
	}
	healthy := s.engine.Healthy(ctx)
	if node.Enabled && healthy {
		healthy = s.engine.ListenersHealthy(ctx, listenersForNode(node)) == nil
	}
	node.Status = liveStatus(node.Enabled, healthy)
	publicHost, _ := s.store.Setting(ctx, "public_host")
	decorateNode(&node, publicHost)
	return node, nil
}

func (s *Service) Create(ctx context.Context, input CreateInput) (model.Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	requestedPort := input.Port
	if input.Port == 0 ||
		(input.Protocol == model.ProtocolVLESSWSTLS && checkPort(input.Protocol, input.Listen, input.Port) != nil) {
		port, err := s.nextAvailablePort(ctx, input.Protocol, input.Listen)
		if err != nil {
			return model.Node{}, err
		}
		input.Port = port
		oldSuffix := "_" + strconv.Itoa(requestedPort)
		if strings.HasSuffix(input.Name, oldSuffix) {
			input.Name = strings.TrimSuffix(input.Name, oldSuffix) + "_" + strconv.Itoa(input.Port)
		}
	}
	input.Settings = cloneMap(input.Settings)
	if err := s.prepareAutomaticCertificate(input.Protocol, input.Settings); err != nil {
		return model.Node{}, validationError(err)
	}
	if err := validateInput(input.Protocol, input.Listen, input.Port, input.Settings, input.ConfirmPublicSOCKS); err != nil {
		return model.Node{}, validationError(err)
	}
	hostOverride, err := validateHostOverride(input.PublicHostOverride)
	if err != nil {
		return model.Node{}, validationError(err)
	}
	hostOverride, err = protocolHostOverride(input.Protocol, hostOverride, input.Settings)
	if err != nil {
		return model.Node{}, validationError(err)
	}
	if err := checkPort(input.Protocol, input.Listen, input.Port); err != nil {
		return model.Node{}, conflictError(err)
	}
	if protocolRequiresCertificate(input.Protocol) {
		expiry, err := certificateExpiration(input.Settings)
		if err != nil {
			return model.Node{}, validationError(err)
		}
		input.Settings["certificate_not_after"] = expiry.UTC().Format(time.RFC3339)
	}
	secret, settings, credential, err := generatedValues(input.Protocol, input.Settings)
	if err != nil {
		return model.Node{}, err
	}
	credential, err = applyCustomCredential(input.Protocol, credential, input.Credential)
	if err != nil {
		return model.Node{}, validationError(err)
	}
	node := model.Node{
		Name:               strings.TrimSpace(input.Name),
		Protocol:           input.Protocol,
		Listen:             defaultListen(input.Listen),
		Port:               input.Port,
		Enabled:            input.Enabled,
		PublicHostOverride: hostOverride,
		Settings:           settings,
		Secret:             secret,
		Status:             "pending",
		OutboundID:         input.OutboundID,
	}
	if err := s.validateOutboundBinding(ctx, node.OutboundID, node.Enabled, 0); err != nil {
		return model.Node{}, err
	}
	if node.Name == "" {
		return model.Node{}, validationError(errors.New("name is required"))
	}
	clientName := strings.TrimSpace(input.ClientName)
	if clientName == "" {
		clientName = "default"
	}
	mutationCtx, cancel := s.detachedContext(ctx)
	defer cancel()
	created, err := s.store.CreateNode(
		mutationCtx, node, model.Client{Name: clientName, Credential: credential},
	)
	if err != nil {
		if database.IsConflict(err) {
			return model.Node{}, conflictError(err)
		}
		return model.Node{}, err
	}
	if err := s.reconcile(mutationCtx); err != nil {
		steps := []compensationStep{
			compensationStep{"delete candidate node", func(rollbackCtx context.Context) error {
				return s.store.DeleteNode(rollbackCtx, created.ID)
			}},
			compensationStep{"restore previous sing-box configuration", func(rollbackCtx context.Context) error {
				return s.reconcile(rollbackCtx)
			}},
		}
		return model.Node{}, s.compensate(mutationCtx, err, steps...)
	}
	created.Status = status(created.Enabled)
	readCtx, cancelRead := s.detachedContext(ctx)
	defer cancelRead()
	return s.Get(readCtx, created.ID)
}

func (s *Service) Update(ctx context.Context, id int64, input UpdateInput) (model.Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.updateLocked(ctx, id, input)
}

func (s *Service) updateLocked(ctx context.Context, id int64, input UpdateInput) (model.Node, error) {
	previous, err := s.store.Node(ctx, id)
	if err != nil {
		return model.Node{}, err
	}
	input.Settings = cloneMap(input.Settings)
	if err := s.prepareAutomaticCertificate(previous.Protocol, input.Settings); err != nil {
		return model.Node{}, validationError(err)
	}
	if err := validateInput(previous.Protocol, input.Listen, input.Port, input.Settings, input.ConfirmPublicSOCKS); err != nil {
		return model.Node{}, validationError(err)
	}
	hostOverride, err := validateHostOverride(input.PublicHostOverride)
	if err != nil {
		return model.Node{}, validationError(err)
	}
	hostOverride, err = protocolHostOverride(previous.Protocol, hostOverride, input.Settings)
	if err != nil {
		return model.Node{}, validationError(err)
	}
	listen := defaultListen(input.Listen)
	if input.Port != previous.Port || listen != previous.Listen || (!previous.Enabled && input.Enabled) {
		if err := checkPort(previous.Protocol, listen, input.Port); err != nil {
			return model.Node{}, conflictError(err)
		}
	}
	candidate := previous
	candidate.Name = strings.TrimSpace(input.Name)
	candidate.Listen = listen
	candidate.Port = input.Port
	candidate.Enabled = input.Enabled
	candidate.PublicHostOverride = hostOverride
	candidate.OutboundID = input.OutboundID
	candidate.Settings = input.Settings
	if protocolUsesReality(previous.Protocol) {
		candidate.Settings["public_key"] = previous.Settings["public_key"]
		candidate.Settings["short_id"] = previous.Settings["short_id"]
	}
	if protocolRequiresCertificate(previous.Protocol) {
		expiry, err := certificateExpiration(candidate.Settings)
		if err != nil {
			return model.Node{}, validationError(err)
		}
		candidate.Settings["certificate_not_after"] = expiry.UTC().Format(time.RFC3339)
	}
	candidate.Status = "pending"
	if candidate.Name == "" {
		return model.Node{}, validationError(errors.New("name is required"))
	}
	if err := s.validateOutboundBinding(ctx, candidate.OutboundID, candidate.Enabled, previous.ID); err != nil {
		return model.Node{}, err
	}
	mutationCtx, cancel := s.detachedContext(ctx)
	defer cancel()
	if err := s.store.UpdateNode(mutationCtx, candidate); err != nil {
		if database.IsConflict(err) {
			return model.Node{}, conflictError(err)
		}
		return model.Node{}, err
	}
	if err := s.reconcile(mutationCtx); err != nil {
		return model.Node{}, s.compensate(mutationCtx, err,
			compensationStep{"restore previous database node", func(rollbackCtx context.Context) error {
				return s.store.UpdateNode(rollbackCtx, previous)
			}},
			compensationStep{"restore previous sing-box configuration and firewall rules", func(rollbackCtx context.Context) error {
				return s.reconcile(rollbackCtx)
			}},
		)
	}
	candidate.Status = status(candidate.Enabled)
	readCtx, cancelRead := s.detachedContext(ctx)
	defer cancelRead()
	return s.Get(readCtx, id)
}

func (s *Service) Delete(ctx context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, err := s.store.Node(ctx, id)
	if err != nil {
		return err
	}
	clients, err := s.store.Clients(ctx, id)
	if err != nil {
		return err
	}
	mutationCtx, cancel := s.detachedContext(ctx)
	defer cancel()
	if err := s.store.DeleteNode(mutationCtx, id); err != nil {
		return err
	}
	if err := s.reconcile(mutationCtx); err != nil {
		return s.compensate(mutationCtx, err,
			compensationStep{"restore deleted database node", func(rollbackCtx context.Context) error {
				return s.store.RestoreNode(rollbackCtx, previous, clients)
			}},
			compensationStep{"restore previous sing-box configuration", func(rollbackCtx context.Context) error {
				return s.reconcile(rollbackCtx)
			}},
		)
	}
	return nil
}

func (s *Service) SetEnabled(ctx context.Context, id int64, enabled bool) (model.Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.store.Node(ctx, id)
	if err != nil {
		return model.Node{}, err
	}
	return s.updateLocked(ctx, id, UpdateInput{
		Name:               current.Name,
		Listen:             current.Listen,
		Port:               current.Port,
		Enabled:            enabled,
		PublicHostOverride: current.PublicHostOverride,
		Settings:           current.Settings,
		ConfirmPublicSOCKS: current.Protocol == model.ProtocolSOCKS5 && !localListen(current.Listen),
		OutboundID:         current.OutboundID,
	})
}

func (s *Service) Clone(ctx context.Context, id int64) (model.Node, error) {
	current, err := s.store.Node(ctx, id)
	if err != nil {
		return model.Node{}, err
	}
	return s.Create(ctx, CreateInput{
		Name:               current.Name + " copy",
		Protocol:           current.Protocol,
		Listen:             current.Listen,
		Port:               0,
		Enabled:            false,
		PublicHostOverride: current.PublicHostOverride,
		Settings:           current.Settings,
		ConfirmPublicSOCKS: current.Protocol == model.ProtocolSOCKS5 && !localListen(current.Listen),
		OutboundID:         current.OutboundID,
	})
}

func (s *Service) CloneTemporary(
	ctx context.Context,
	id int64,
	name string,
	outboundID int64,
	expiresAt *time.Time,
	source string,
	country string,
) (model.Node, error) {
	current, err := s.store.Node(ctx, id)
	if err != nil {
		return model.Node{}, err
	}
	source = strings.TrimSpace(source)
	if source != "vpngate" && source != "manual" {
		return model.Node{}, validationError(errors.New("temporary source must be vpngate or manual"))
	}
	if expiresAt != nil && !expiresAt.After(time.Now().UTC()) {
		return model.Node{}, validationError(errors.New("temporary node expiry must be in the future"))
	}
	settings := cloneMap(current.Settings)
	settings[TemporarySourceSetting] = source
	delete(settings, TemporaryExpirySetting)
	if expiresAt != nil {
		settings[TemporaryExpirySetting] = expiresAt.UTC().Format(time.RFC3339)
	}
	if country = strings.ToUpper(strings.TrimSpace(country)); country != "" {
		settings[TemporaryCountrySetting] = country
	}
	return s.Create(ctx, CreateInput{
		Name:               name,
		Protocol:           current.Protocol,
		Listen:             current.Listen,
		Port:               0,
		Enabled:            true,
		ClientName:         "default",
		PublicHostOverride: current.PublicHostOverride,
		Settings:           settings,
		ConfirmPublicSOCKS: current.Protocol == model.ProtocolSOCKS5 && !localListen(current.Listen),
		OutboundID:         &outboundID,
	})
}

func (s *Service) ExpireTemporary(ctx context.Context) error {
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, current := range nodes {
		expiresAt, temporary := TemporaryExpiry(current)
		if !temporary || TemporarySource(current) != "vpngate" || expiresAt.After(now) {
			continue
		}
		if err := s.Delete(ctx, current.ID); err != nil {
			return err
		}
		_ = s.store.RecordEvent(ctx, "info", "temporary_node_expired",
			fmt.Sprintf("VPNGate 住宅节点 %s 已到期并自动删除，监听端口已关闭", current.Name))
	}
	return nil
}

// NormalizeProtocolPorts migrates VLESS-WS nodes created by older releases
// away from arbitrary sequential ports and onto Cloudflare HTTPS ports.
func (s *Service) NormalizeProtocolPorts(ctx context.Context) error {
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return err
	}
	used := make(map[int]bool, len(nodes))
	for _, current := range nodes {
		used[current.Port] = true
	}
	for _, current := range nodes {
		if current.Protocol != model.ProtocolVLESSWSTLS || model.CloudflareHTTPSPort(current.Port) {
			continue
		}
		delete(used, current.Port)
		port, portErr := nextProtocolPort(DefaultStartPort, current.Protocol, used, func(candidate int) bool {
			return checkPort(current.Protocol, current.Listen, candidate) == nil
		})
		if portErr != nil {
			return portErr
		}
		name := current.Name
		oldSuffix := "_" + strconv.Itoa(current.Port)
		if strings.HasSuffix(name, oldSuffix) {
			name = strings.TrimSuffix(name, oldSuffix) + "_" + strconv.Itoa(port)
		}
		if _, err := s.Update(ctx, current.ID, UpdateInput{
			Name: name, Listen: current.Listen, Port: port, Enabled: current.Enabled,
			PublicHostOverride: current.PublicHostOverride, Settings: current.Settings,
			OutboundID: current.OutboundID,
		}); err != nil {
			return err
		}
		used[port] = true
		_ = s.store.RecordEvent(ctx, "info", "websocket_port_migrated",
			fmt.Sprintf("VLESS-WS 节点 %s 已自动迁移到 Cloudflare HTTPS 端口 %d", name, port))
	}
	return nil
}

func TemporarySource(node model.Node) string {
	return strings.TrimSpace(mapString(node.Settings, TemporarySourceSetting))
}

func TemporaryExpiry(node model.Node) (time.Time, bool) {
	value := strings.TrimSpace(mapString(node.Settings, TemporaryExpirySetting))
	if value == "" || TemporarySource(node) == "" {
		return time.Time{}, false
	}
	expiresAt, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, false
	}
	return expiresAt, true
}

func (s *Service) Clients(ctx context.Context, nodeID int64) ([]model.Client, error) {
	if _, err := s.store.Node(ctx, nodeID); err != nil {
		return nil, err
	}
	return s.store.Clients(ctx, nodeID)
}

func (s *Service) AddClient(ctx context.Context, nodeID int64, name string) (model.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	node, err := s.store.Node(ctx, nodeID)
	if err != nil {
		return model.Client{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return model.Client{}, validationError(errors.New("client name is required"))
	}
	credential, err := generatedCredential(node.Protocol)
	if err != nil {
		return model.Client{}, err
	}
	mutationCtx, cancel := s.detachedContext(ctx)
	defer cancel()
	client, err := s.store.CreateClient(mutationCtx, model.Client{
		NodeID: nodeID, UserID: 1, Name: name, Enabled: true, Credential: credential,
	})
	if err != nil {
		return model.Client{}, err
	}
	if err := s.reconcile(mutationCtx); err != nil {
		return model.Client{}, s.compensate(mutationCtx, err,
			compensationStep{"delete candidate client", func(rollbackCtx context.Context) error {
				return s.store.DeleteClient(rollbackCtx, nodeID, client.ID)
			}},
			compensationStep{"restore previous sing-box configuration", func(rollbackCtx context.Context) error {
				return s.reconcile(rollbackCtx)
			}},
		)
	}
	return client, nil
}

func (s *Service) UpdateClient(ctx context.Context, nodeID, clientID int64, name string, enabled bool, reset bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	node, err := s.store.Node(ctx, nodeID)
	if err != nil {
		return err
	}
	clients, err := s.store.Clients(ctx, nodeID)
	if err != nil {
		return err
	}
	var previous model.Client
	found := false
	for _, client := range clients {
		if client.ID == clientID {
			previous = client
			found = true
			break
		}
	}
	if !found {
		return notFoundError(errors.New("client not found"))
	}
	candidate := previous
	candidate.Name = strings.TrimSpace(name)
	if candidate.Name == "" {
		return validationError(errors.New("client name is required"))
	}
	candidate.Enabled = enabled
	if reset {
		candidate.Credential, err = generatedCredential(node.Protocol)
		if err != nil {
			return err
		}
	}
	mutationCtx, cancel := s.detachedContext(ctx)
	defer cancel()
	if err := s.store.UpdateClient(mutationCtx, candidate); err != nil {
		return err
	}
	if err := s.reconcile(mutationCtx); err != nil {
		return s.compensate(mutationCtx, err,
			compensationStep{"restore previous client", func(rollbackCtx context.Context) error {
				return s.store.UpdateClient(rollbackCtx, previous)
			}},
			compensationStep{"restore previous sing-box configuration", func(rollbackCtx context.Context) error {
				return s.reconcile(rollbackCtx)
			}},
		)
	}
	return nil
}

func (s *Service) DeleteClient(ctx context.Context, nodeID, clientID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clients, err := s.store.Clients(ctx, nodeID)
	if err != nil {
		return err
	}
	if len(clients) <= 1 {
		return problem.New(problem.Conflict, "last_client", "a node must have at least one client", nil)
	}
	var previous model.Client
	for _, client := range clients {
		if client.ID == clientID {
			previous = client
		}
	}
	if previous.ID == 0 {
		return notFoundError(errors.New("client not found"))
	}
	mutationCtx, cancel := s.detachedContext(ctx)
	defer cancel()
	if err := s.store.DeleteClient(mutationCtx, nodeID, clientID); err != nil {
		return err
	}
	if err := s.reconcile(mutationCtx); err != nil {
		return s.compensate(mutationCtx, err,
			compensationStep{"restore deleted client", func(rollbackCtx context.Context) error {
				return s.store.RestoreClient(rollbackCtx, previous)
			}},
			compensationStep{"restore previous sing-box configuration", func(rollbackCtx context.Context) error {
				return s.reconcile(rollbackCtx)
			}},
		)
	}
	return nil
}

func (s *Service) detachedContext(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := s.operationTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return context.WithTimeout(context.WithoutCancel(ctx), timeout)
}

func (s *Service) Reconcile(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reconcile(ctx)
}

func (s *Service) CleanupFirewall(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return err
	}
	rules, err := s.store.ManagedFirewallRules(ctx)
	if err != nil {
		return err
	}
	unique := make(map[string]database.ManagedFirewallRule)
	for _, rule := range rules {
		unique[firewallRuleKey(rule.Protocol, rule.Port)] = rule
	}
	for _, node := range nodes {
		if !node.Enabled || localListen(node.Listen) {
			continue
		}
		for _, protocol := range firewallProtocols(node.Protocol) {
			rule := database.ManagedFirewallRule{Protocol: protocol, Port: node.Port}
			key := firewallRuleKey(protocol, node.Port)
			if _, tracked := unique[key]; !tracked {
				unique[key] = rule
			}
		}
	}
	var failures []error
	for _, rule := range unique {
		if rule.Ownership != database.FirewallBorrowed {
			if err := s.firewall.Close(ctx, rule.Protocol, rule.Port, rule.Backend); err != nil {
				failures = append(failures, fmt.Errorf("close %s/%d: %w", rule.Protocol, rule.Port, err))
				continue
			}
		}
		if err := s.store.ForgetFirewallRule(ctx, rule.Protocol, rule.Port); err != nil {
			failures = append(failures, fmt.Errorf("forget %s/%d: %w", rule.Protocol, rule.Port, err))
		}
	}
	return errors.Join(failures...)
}

func (s *Service) reconcile(ctx context.Context) error {
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return err
	}
	if err := s.syncFirewall(ctx, nodes); err != nil {
		return err
	}
	items := make([]singbox.NodeWithClients, 0, len(nodes))
	for _, node := range nodes {
		clients, err := s.store.Clients(ctx, node.ID)
		if err != nil {
			return err
		}
		items = append(items, singbox.NodeWithClients{Node: node, Clients: clients})
	}
	outbounds, err := s.store.ListOutbounds(ctx)
	if err != nil {
		return err
	}
	config, err := singbox.GenerateWithOutbounds(items, outbounds)
	if err != nil {
		_ = s.store.RecordEvent(ctx, "error", "config_generation_failed", "节点配置生成失败，现有配置保持不变")
		return err
	}
	listeners := make([]engine.Listener, 0, len(nodes))
	for _, node := range nodes {
		if !node.Enabled {
			continue
		}
		listeners = append(listeners, listenersForNode(node)...)
	}
	if err := s.engine.Apply(ctx, config, listeners); err != nil {
		_ = s.store.RecordEvent(ctx, "error", "config_apply_failed", "sing-box 配置部署失败，上一可用版本已保留")
		return err
	}
	if err := s.store.SaveConfigVersion(ctx, config, true); err != nil {
		_ = s.store.RecordEvent(ctx, "error", "config_version_failed", "配置版本写入失败，调用方将执行状态回滚")
		return err
	}
	_ = s.store.RecordEvent(ctx, "info", "config_applied", "sing-box 配置已校验、重启并通过端口健康检查")
	return nil
}

func (s *Service) syncFirewall(ctx context.Context, nodes []model.Node) error {
	desired := make(map[string]database.ManagedFirewallRule)
	for _, node := range nodes {
		if !node.Enabled || localListen(node.Listen) {
			continue
		}
		for _, protocol := range firewallProtocols(node.Protocol) {
			rule := database.ManagedFirewallRule{Protocol: protocol, Port: node.Port}
			desired[firewallRuleKey(protocol, node.Port)] = rule
		}
	}
	tracked, err := s.store.ManagedFirewallRules(ctx)
	if err != nil {
		return err
	}
	trackedSet := make(map[string]database.ManagedFirewallRule, len(tracked))
	for _, rule := range tracked {
		trackedSet[firewallRuleKey(rule.Protocol, rule.Port)] = rule
		if _, keep := desired[firewallRuleKey(rule.Protocol, rule.Port)]; keep {
			continue
		}
		if rule.Ownership != database.FirewallBorrowed {
			if err := s.firewall.Close(ctx, rule.Protocol, rule.Port, rule.Backend); err != nil {
				return fmt.Errorf("remove stale firewall rule %s/%d: %w", rule.Protocol, rule.Port, err)
			}
		}
		if err := s.store.ForgetFirewallRule(ctx, rule.Protocol, rule.Port); err != nil {
			return fmt.Errorf("forget stale firewall rule %s/%d: %w", rule.Protocol, rule.Port, err)
		}
	}
	desiredKeys := make([]string, 0, len(desired))
	for key := range desired {
		desiredKeys = append(desiredKeys, key)
	}
	sort.Strings(desiredKeys)
	for _, key := range desiredKeys {
		rule := desired[key]
		trackedRule, wasTracked := trackedSet[key]
		if wasTracked && s.firewallVerified {
			continue
		}
		// Persist ownership intent first. A crash before or during Ensure is
		// repaired on the next reconciliation, and stale intent is removable.
		if err := s.store.TrackFirewallRule(ctx, rule.Protocol, rule.Port); err != nil {
			return fmt.Errorf("track firewall rule %s/%d: %w", rule.Protocol, rule.Port, err)
		}
		activeBackend, err := s.firewall.Backend(ctx)
		if err != nil {
			return fmt.Errorf("select firewall backend for %s/%d: %w", rule.Protocol, rule.Port, err)
		}
		if wasTracked && trackedRule.Ownership == database.FirewallOwned &&
			trackedRule.Backend != database.FirewallUnknown && trackedRule.Backend != activeBackend {
			if err := s.firewall.Close(ctx, rule.Protocol, rule.Port, trackedRule.Backend); err != nil {
				return fmt.Errorf("remove firewall rule from previous backend %s for %s/%d: %w",
					trackedRule.Backend, rule.Protocol, rule.Port, err)
			}
		}
		ownership, err := s.firewall.Ensure(ctx, rule.Protocol, rule.Port)
		if err != nil {
			return fmt.Errorf("restore firewall rule %s/%d: %w", rule.Protocol, rule.Port, err)
		}
		databaseOwnership := string(ownership.Ownership)
		if databaseOwnership != database.FirewallOwned && databaseOwnership != database.FirewallBorrowed {
			return fmt.Errorf("firewall returned invalid ownership %q for %s/%d",
				ownership.Ownership, rule.Protocol, rule.Port)
		}
		if ownership.Backend != firewall.BackendFirewalld && ownership.Backend != firewall.BackendUFW &&
			ownership.Backend != firewall.BackendNFTables {
			return fmt.Errorf("firewall returned invalid backend %q for %s/%d",
				ownership.Backend, rule.Protocol, rule.Port)
		}
		if ownership.Backend != activeBackend {
			if databaseOwnership == database.FirewallOwned {
				_ = s.firewall.Close(ctx, rule.Protocol, rule.Port, ownership.Backend)
			}
			return fmt.Errorf("firewall backend changed from %s to %s while reconciling %s/%d",
				activeBackend, ownership.Backend, rule.Protocol, rule.Port)
		}
		if err := s.store.SetFirewallRuleOwnership(
			ctx, rule.Protocol, rule.Port, databaseOwnership, ownership.Backend,
		); err != nil {
			return fmt.Errorf("record firewall ownership for %s/%d: %w", rule.Protocol, rule.Port, err)
		}
	}
	s.firewallVerified = true
	return nil
}

func listenersForNode(node model.Node) []engine.Listener {
	listeners := make([]engine.Listener, 0, 2)
	for _, network := range firewallProtocols(node.Protocol) {
		listeners = append(listeners, engine.Listener{
			Network: network,
			Host:    defaultListen(node.Listen),
			Port:    node.Port,
		})
	}
	return listeners
}

func generatedValues(protocol string, input map[string]any) (map[string]any, map[string]any, map[string]any, error) {
	settings := cloneMap(input)
	secret := map[string]any{}
	if protocolUsesReality(protocol) {
		if strings.TrimSpace(mapString(settings, "handshake_server")) == "" {
			settings["handshake_server"] = "www.visa.com.sg"
		}
		if mapNumber(settings, "handshake_port") == 0 {
			settings["handshake_port"] = 443
		}
		if strings.TrimSpace(mapString(settings, "server_name")) == "" {
			settings["server_name"] = mapString(settings, "handshake_server")
		}
		privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		shortID, err := secure.RandomHex(8)
		if err != nil {
			return nil, nil, nil, err
		}
		secret["private_key"] = base64.RawURLEncoding.EncodeToString(privateKey.Bytes())
		settings["public_key"] = base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())
		settings["short_id"] = shortID
	}
	credential, err := generatedCredential(protocol)
	return secret, settings, credential, err
}

func generatedCredential(protocol string) (map[string]any, error) {
	switch protocol {
	case model.ProtocolVLESSReality:
		uuid, err := secure.UUID()
		return map[string]any{"uuid": uuid, "flow": "xtls-rprx-vision"}, err
	case model.ProtocolVLESSH2Reality, model.ProtocolVLESSGRPCReality,
		model.ProtocolVLESSWSTLS, model.ProtocolVLESSArgo:
		uuid, err := secure.UUID()
		return map[string]any{"uuid": uuid}, err
	case model.ProtocolTrojanTLS, model.ProtocolHysteria2, model.ProtocolAnyTLS,
		model.ProtocolAnyTLSReality:
		password, err := secure.RandomToken(24)
		return map[string]any{"password": password}, err
	case model.ProtocolTUIC:
		uuid, err := secure.UUID()
		if err != nil {
			return nil, err
		}
		password, err := secure.RandomToken(18)
		return map[string]any{"uuid": uuid, "password": password}, err
	case model.ProtocolSOCKS5, model.ProtocolNaive:
		username, err := secure.RandomHex(6)
		if err != nil {
			return nil, err
		}
		password, err := secure.RandomToken(18)
		return map[string]any{"username": "jui-" + username, "password": password}, err
	default:
		return nil, errors.New("unsupported protocol")
	}
}

var (
	credentialUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	credentialUserPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

func applyCustomCredential(protocol string, generated, custom map[string]any) (map[string]any, error) {
	if len(custom) == 0 {
		return generated, nil
	}
	allowed := map[string]bool{}
	switch protocol {
	case model.ProtocolVLESSReality, model.ProtocolVLESSH2Reality,
		model.ProtocolVLESSGRPCReality, model.ProtocolVLESSWSTLS, model.ProtocolVLESSArgo:
		allowed["uuid"] = true
	case model.ProtocolTrojanTLS, model.ProtocolHysteria2, model.ProtocolAnyTLS,
		model.ProtocolAnyTLSReality:
		allowed["password"] = true
	case model.ProtocolTUIC:
		allowed["uuid"] = true
		allowed["password"] = true
	case model.ProtocolSOCKS5, model.ProtocolNaive:
		allowed["username"] = true
		allowed["password"] = true
	default:
		return nil, errors.New("unsupported protocol")
	}

	credential := cloneMap(generated)
	for key, raw := range custom {
		if !allowed[key] {
			return nil, fmt.Errorf("credential %s is not supported by %s", key, protocol)
		}
		value, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("credential %s must be a string", key)
		}
		if key != "password" {
			value = strings.TrimSpace(value)
		}
		credential[key] = value
	}

	if allowed["uuid"] && !credentialUUIDPattern.MatchString(mapString(credential, "uuid")) {
		return nil, errors.New("credential uuid must be a valid UUID")
	}
	if allowed["username"] && !credentialUserPattern.MatchString(mapString(credential, "username")) {
		return nil, errors.New("credential username may contain only letters, numbers, dot, underscore, or dash")
	}
	if allowed["password"] {
		password := mapString(credential, "password")
		if len(password) < 8 || len(password) > 256 {
			return nil, errors.New("credential password must be between 8 and 256 characters")
		}
	}
	return credential, nil
}

func validateInput(protocol, listen string, port int, settings map[string]any, confirmPublicSOCKS bool) error {
	if !model.SupportedProtocol(protocol) {
		return errors.New("unsupported protocol")
	}
	if port < 1 || port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	if protocol == model.ProtocolVLESSWSTLS && !model.CloudflareHTTPSPort(port) {
		return errors.New("VLESS-WS port must be a Cloudflare-supported HTTPS port: 443, 2053, 2083, 2087, 2096, or 8443")
	}
	listen = defaultListen(listen)
	if net.ParseIP(listen) == nil {
		return errors.New("listen must be an IP address")
	}
	if protocol == model.ProtocolSOCKS5 && !localListen(listen) && !confirmPublicSOCKS {
		return errors.New("public SOCKS5 listening requires explicit confirmation")
	}
	if protocolUsesReality(protocol) {
		server := mapString(settings, "handshake_server")
		if server != "" {
			if _, err := validateEndpointHost(server); err != nil {
				return fmt.Errorf("handshake_server: %w", err)
			}
		}
		if value, supplied := settings["handshake_port"]; supplied {
			if _, err := validateSettingPort(value); err != nil {
				return fmt.Errorf("handshake_port: %w", err)
			}
		}
		serverName := mapString(settings, "server_name")
		if serverName != "" {
			if _, err := validateEndpointHost(serverName); err != nil {
				return fmt.Errorf("server_name: %w", err)
			}
		}
		if protocol == model.ProtocolVLESSH2Reality {
			return validatePathSetting(settings, "transport_path")
		}
		if protocol == model.ProtocolVLESSGRPCReality {
			serviceName := mapString(settings, "service_name")
			if serviceName == "" || strings.ContainsAny(serviceName, "?#/\\\r\n\t") {
				return errors.New("service_name is required and must not contain separators or control characters")
			}
		}
		return nil
	}
	if protocol == model.ProtocolVLESSArgo {
		if !localListen(listen) {
			return errors.New("VLESS Argo must listen on a loopback address")
		}
		serverName := mapString(settings, "server_name")
		if serverName == "" {
			return errors.New("Argo domain is required")
		}
		if _, err := validateEndpointHost(serverName); err != nil {
			return fmt.Errorf("server_name: %w", err)
		}
		path := mapString(settings, "ws_path")
		if path == "" || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#\r\n\t") {
			return errors.New("ws_path must start with / and must not contain a query, fragment, or control characters")
		}
		return nil
	}
	if protocol != model.ProtocolSOCKS5 {
		if err := validateCertificateSettings(settings); err != nil {
			return err
		}
		if protocol == model.ProtocolVLESSWSTLS {
			return validatePathSetting(settings, "ws_path")
		}
	}
	return nil
}

func protocolHostOverride(protocol, host string, settings map[string]any) (string, error) {
	if protocol != model.ProtocolVLESSArgo {
		return host, nil
	}
	argoHost := mapString(settings, "server_name")
	if host == "" {
		return argoHost, nil
	}
	if !strings.EqualFold(host, argoHost) {
		return "", errors.New("VLESS Argo external address must match the Argo domain")
	}
	return host, nil
}

func (s *Service) prepareAutomaticCertificate(protocol string, settings map[string]any) error {
	if !protocolRequiresCertificate(protocol) || mapString(settings, "certificate_mode") != "auto" {
		return nil
	}
	serverName, err := validateEndpointHost(mapString(settings, "server_name"))
	if err != nil {
		return fmt.Errorf("server_name: %w", err)
	}
	if serverName == "" {
		return errors.New("server_name is required for automatic certificates")
	}
	settings["server_name"] = serverName

	certificatePath := filepath.Join("/etc/letsencrypt/live", serverName, "fullchain.pem")
	keyPath := filepath.Join("/etc/letsencrypt/live", serverName, "privkey.pem")
	if regularFile(certificatePath) && regularFile(keyPath) {
		settings["certificate_path"] = certificatePath
		settings["key_path"] = keyPath
		if err := validateCertificateSettings(settings); err == nil {
			return nil
		}
	}

	if !s.allowSelfSigned {
		return fmt.Errorf("no valid certificate found for %s; issue it under /etc/letsencrypt/live/%s or use manual certificate paths", serverName, serverName)
	}
	if strings.TrimSpace(s.certificateDir) == "" {
		return errors.New("automatic certificate directory is not configured")
	}
	certificatePath, keyPath, err = s.ensureDemoCertificate(serverName)
	if err != nil {
		return fmt.Errorf("generate demo certificate: %w", err)
	}
	settings["certificate_path"] = certificatePath
	settings["key_path"] = keyPath
	return nil
}

func protocolRequiresCertificate(protocol string) bool {
	switch protocol {
	case model.ProtocolVLESSWSTLS, model.ProtocolTrojanTLS, model.ProtocolHysteria2,
		model.ProtocolTUIC, model.ProtocolAnyTLS, model.ProtocolNaive:
		return true
	default:
		return false
	}
}

func protocolUsesReality(protocol string) bool {
	switch protocol {
	case model.ProtocolVLESSReality, model.ProtocolVLESSH2Reality,
		model.ProtocolVLESSGRPCReality, model.ProtocolAnyTLSReality:
		return true
	default:
		return false
	}
}

func validatePathSetting(settings map[string]any, key string) error {
	path := mapString(settings, key)
	if path == "" || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#\r\n\t") {
		return fmt.Errorf("%s must start with / and must not contain a query, fragment, or control characters", key)
	}
	return nil
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func (s *Service) ensureDemoCertificate(serverName string) (string, string, error) {
	digest := sha256.Sum256([]byte(strings.ToLower(serverName)))
	baseName := fmt.Sprintf("demo-%x", digest[:8])
	certificatePath := filepath.Join(s.certificateDir, baseName+".crt")
	keyPath := filepath.Join(s.certificateDir, baseName+".key")
	settings := map[string]any{
		"server_name": serverName, "certificate_path": certificatePath, "key_path": keyPath,
	}
	if validateCertificateSettings(settings) == nil {
		return certificatePath, keyPath, nil
	}
	if err := os.MkdirAll(s.certificateDir, 0o700); err != nil {
		return "", "", err
	}
	if err := os.Chmod(s.certificateDir, 0o700); err != nil {
		return "", "", err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: serverName, Organization: []string{"J-UI Demo"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(serverName); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{serverName}
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}
	if err := writeFileAtomic(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o644); err != nil {
		return "", "", err
	}
	if err := writeFileAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return "", "", err
	}
	if err := validateCertificateSettings(settings); err != nil {
		return "", "", err
	}
	return certificatePath, keyPath, nil
}

func writeFileAtomic(path string, content []byte, mode os.FileMode) (err error) {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".jui-certificate-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if err != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err = temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err = temporary.Write(content); err != nil {
		return err
	}
	if err = temporary.Sync(); err != nil {
		return err
	}
	if err = temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func validateCertificateSettings(settings map[string]any) error {
	serverName := mapString(settings, "server_name")
	certificatePath := mapString(settings, "certificate_path")
	keyPath := mapString(settings, "key_path")
	if serverName == "" || !filepath.IsAbs(certificatePath) || !filepath.IsAbs(keyPath) {
		return errors.New("server_name and absolute certificate/key paths are required")
	}
	if certificatePath == keyPath {
		return errors.New("certificate and private key paths must be different")
	}
	certificateInfo, err := os.Stat(certificatePath)
	if err != nil {
		return fmt.Errorf("read certificate metadata: %w", err)
	}
	if !certificateInfo.Mode().IsRegular() || certificateInfo.Mode().Perm()&0o022 != 0 {
		return errors.New("certificate must be a regular file not writable by group or others")
	}
	certificatePEM, err := os.ReadFile(certificatePath)
	if err != nil {
		return fmt.Errorf("read certificate: %w", err)
	}
	block, _ := pem.Decode(certificatePEM)
	if block == nil {
		return errors.New("certificate is not valid PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	now := time.Now()
	if now.Before(certificate.NotBefore) {
		return errors.New("certificate is not valid yet")
	}
	if now.After(certificate.NotAfter) {
		return errors.New("certificate has expired")
	}
	if err := certificate.VerifyHostname(serverName); err != nil {
		return fmt.Errorf("certificate does not match server_name: %w", err)
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		return fmt.Errorf("read private key metadata: %w", err)
	}
	if !keyInfo.Mode().IsRegular() || keyInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("private key must be a regular file inaccessible to group and others")
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return errors.New("private key is not valid PEM")
	}
	privateKey, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}
	certificatePublicKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return fmt.Errorf("encode certificate public key: %w", err)
	}
	privatePublicKey, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return fmt.Errorf("encode private key public key: %w", err)
	}
	if !bytes.Equal(certificatePublicKey, privatePublicKey) {
		return errors.New("private key does not match certificate")
	}
	return nil
}

func certificateExpiration(settings map[string]any) (time.Time, error) {
	certificatePEM, err := os.ReadFile(mapString(settings, "certificate_path"))
	if err != nil {
		return time.Time{}, fmt.Errorf("read certificate: %w", err)
	}
	block, _ := pem.Decode(certificatePEM)
	if block == nil {
		return time.Time{}, errors.New("certificate is not valid PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return certificate.NotAfter, nil
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if value, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if signer, ok := value.(crypto.Signer); ok {
			return signer, nil
		}
		return nil, errors.New("private key type is not supported")
	}
	if value, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return value, nil
	}
	if value, err := x509.ParseECPrivateKey(der); err == nil {
		return value, nil
	}
	return nil, errors.New("private key format is not supported")
}

func checkPort(protocol, listen string, port int) error {
	for _, network := range firewallProtocols(protocol) {
		if err := checkNetworkPort(network, listen, port); err != nil {
			return err
		}
	}
	return nil
}

func checkNetworkPort(network, listen string, port int) error {
	address := net.JoinHostPort(defaultListen(listen), strconv.Itoa(port))
	if network == "udp" {
		connection, err := net.ListenPacket(network, address)
		if err != nil {
			return fmt.Errorf("%s port conflict: %w", network, err)
		}
		return connection.Close()
	}
	listener, err := net.Listen(network, address)
	if err != nil {
		return fmt.Errorf("%s port conflict: %w", network, err)
	}
	return listener.Close()
}

func firewallRuleKey(protocol string, port int) string {
	return fmt.Sprintf("%s/%d", protocol, port)
}

func firewallProtocols(protocol string) []string {
	switch protocol {
	case model.ProtocolHysteria2, model.ProtocolTUIC:
		return []string{"udp"}
	default:
		return []string{"tcp"}
	}
}

func defaultListen(value string) string {
	if strings.TrimSpace(value) == "" {
		return "0.0.0.0"
	}
	return strings.TrimSpace(value)
}

func localListen(value string) bool {
	ip := net.ParseIP(value)
	return ip != nil && ip.IsLoopback()
}

func mapString(settings map[string]any, key string) string {
	value, _ := settings[key].(string)
	return strings.TrimSpace(value)
}

func mapNumber(settings map[string]any, key string) int {
	switch value := settings[key].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	default:
		return 0
	}
}

func validateHostOverride(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if strings.Contains(value, "://") || strings.ContainsAny(value, "/?#@") {
		return "", errors.New("public host override must be a hostname or IP")
	}
	value = strings.TrimPrefix(strings.TrimSuffix(value, "]"), "[")
	if net.ParseIP(value) != nil {
		return value, nil
	}
	if strings.Contains(value, ":") {
		return "", errors.New("public host override must not include a port")
	}
	if len(value) > 253 {
		return "", errors.New("public host override is too long")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("public host override is invalid")
		}
		for _, character := range label {
			if !((character >= 'a' && character <= 'z') ||
				(character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') || character == '-') {
				return "", errors.New("public host override is invalid")
			}
		}
	}
	return strings.ToLower(value), nil
}

func validateEndpointHost(value string) (string, error) {
	host, err := validateHostOverride(value)
	if err != nil || host == "" {
		if err == nil {
			err = errors.New("hostname or IP is required")
		}
		return "", err
	}
	return host, nil
}

func validateSettingPort(value any) (int, error) {
	var port int
	switch typed := value.(type) {
	case int:
		port = typed
	case int32:
		port = int(typed)
	case int64:
		port = int(typed)
	case float64:
		port = int(typed)
		if typed != float64(port) {
			return 0, errors.New("must be an integer")
		}
	default:
		return 0, errors.New("must be an integer")
	}
	if port < 1 || port > 65535 {
		return 0, errors.New("must be between 1 and 65535")
	}
	return port, nil
}

func validationError(err error) error {
	return problem.New(problem.Validation, "validation_failed", err.Error(), err)
}

func conflictError(err error) error {
	return problem.New(problem.Conflict, "resource_conflict", err.Error(), err)
}

func notFoundError(err error) error {
	return problem.New(problem.NotFound, "not_found", "resource not found", err)
}

func cloneMap(source map[string]any) map[string]any {
	target := make(map[string]any, len(source))
	for key, value := range source {
		target[key] = value
	}
	return target
}

func status(enabled bool) string {
	if enabled {
		return "running"
	}
	return "disabled"
}

func decorateNode(node *model.Node, publicHost string) {
	node.ExternalAddress = node.PublicHostOverride
	if node.ExternalAddress == "" {
		node.ExternalAddress = publicHost
	}
	node.CurrentOutbound = "native"
	if node.OutboundID != nil {
		node.CurrentOutbound = fmt.Sprintf("outbound-%d", *node.OutboundID)
	}
	switch node.Status {
	case "running":
		node.ListenerStatus = "listening"
		node.PublicConnectivity = "unknown"
	case "faulted":
		node.ListenerStatus = "faulted"
		node.PublicConnectivity = "unknown"
	default:
		node.ListenerStatus = "stopped"
		node.PublicConnectivity = "not-applicable"
	}
	switch node.Protocol {
	case model.ProtocolVLESSH2Reality:
		node.Transport = "http2"
	case model.ProtocolVLESSGRPCReality:
		node.Transport = "grpc"
	case model.ProtocolVLESSWSTLS, model.ProtocolVLESSArgo:
		node.Transport = "websocket"
	case model.ProtocolHysteria2, model.ProtocolTUIC:
		node.Transport = "quic"
	case model.ProtocolSOCKS5:
		node.Transport = "socks"
	case model.ProtocolAnyTLS, model.ProtocolAnyTLSReality:
		node.Transport = "anytls"
	case model.ProtocolNaive:
		node.Transport = "naive"
	default:
		node.Transport = "tcp"
	}
}

func liveStatus(enabled, healthy bool) string {
	if !enabled {
		return "disabled"
	}
	if healthy {
		return "running"
	}
	return "faulted"
}
