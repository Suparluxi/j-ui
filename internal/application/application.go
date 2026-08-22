package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Suparluxi/j-ui/internal/api"
	"github.com/Suparluxi/j-ui/internal/auth"
	"github.com/Suparluxi/j-ui/internal/backup"
	"github.com/Suparluxi/j-ui/internal/config"
	"github.com/Suparluxi/j-ui/internal/database"
	"github.com/Suparluxi/j-ui/internal/engine"
	"github.com/Suparluxi/j-ui/internal/exitcheck"
	"github.com/Suparluxi/j-ui/internal/firewall"
	"github.com/Suparluxi/j-ui/internal/model"
	"github.com/Suparluxi/j-ui/internal/monitor"
	"github.com/Suparluxi/j-ui/internal/netns"
	nodeservice "github.com/Suparluxi/j-ui/internal/node"
	"github.com/Suparluxi/j-ui/internal/secure"
	"github.com/Suparluxi/j-ui/internal/subscription"
	"github.com/Suparluxi/j-ui/internal/vpngate"
	"gopkg.in/yaml.v3"
)

type Application struct {
	Config        config.Config
	Dependencies  api.Dependencies
	Store         *database.Store
	Nodes         *nodeservice.Service
	VPNGate       *vpngate.Service
	Credentials   *Credentials
	temporaryStop chan struct{}
	temporaryDone chan struct{}
}

type Credentials struct {
	Username          string
	Password          string
	AdminPath         string
	SubscriptionToken string
}

func New(ctx context.Context, cfg config.Config) (*Application, error) {
	return open(ctx, cfg, true)
}

func OpenExisting(ctx context.Context, cfg config.Config) (*Application, error) {
	return open(ctx, cfg, false)
}

func open(ctx context.Context, cfg config.Config, allowBootstrap bool) (*Application, error) {
	if !allowBootstrap {
		if _, err := os.Stat(cfg.SecretKeyPath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, errors.New("J-UI is not initialized; run `j-ui init` from a secure terminal")
			}
			return nil, err
		}
		if _, err := os.Stat(cfg.DatabasePath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, errors.New("J-UI is not initialized; run `j-ui init` from a secure terminal")
			}
			return nil, err
		}
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.ConfigDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(cfg.ConfigDir, 0o700); err != nil {
		return nil, err
	}
	key, err := secure.LoadOrCreateKey(cfg.SecretKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load instance key: %w", err)
	}
	sealer, err := secure.NewSealer(key)
	if err != nil {
		return nil, err
	}
	store, err := database.Open(cfg.DatabasePath, sealer)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	var credentials *Credentials
	if allowBootstrap {
		credentials, err = bootstrap(ctx, store, sealer, cfg.NodeStartPort)
		if err != nil {
			store.Close()
			return nil, err
		}
	} else {
		initialized, err := store.Initialized(ctx)
		if err != nil {
			store.Close()
			return nil, err
		}
		if !initialized {
			store.Close()
			return nil, errors.New("J-UI is not initialized; run `j-ui init` from a secure terminal")
		}
	}

	var proxyEngine engine.Engine
	var firewallManager firewall.Manager
	if cfg.MockEngine {
		proxyEngine = &engine.Mock{}
		firewallManager = firewall.Mock{}
	} else {
		proxyEngine = &engine.System{
			Binary: cfg.SingBoxBinary, ConfigPath: cfg.SingBoxConfig,
		}
		firewallManager = firewall.System{}
	}
	nodeService := nodeservice.NewService(store, proxyEngine, firewallManager)
	nodeService.ConfigureAutomaticCertificates(filepath.Join(cfg.ConfigDir, "certificates"), cfg.MockEngine)
	if !cfg.MockEngine {
		nodeService.ConfigureTemporaryRuntime(nodeservice.NewSystemTemporaryRuntime(
			cfg.SingBoxBinary, filepath.Join(cfg.ConfigDir, "residential"),
		))
	}
	if cfg.MockEngine {
		nodeService.ConfigureOutboundChecker(nodeservice.OutboundCheckFunc(
			func(context.Context, model.Outbound) (exitcheck.Result, error) {
				return exitcheck.Result{IP: "203.0.113.10", Country: "ZZ", ASN: "AS0 test"}, nil
			},
		))
	}
	var vpnOrchestrator netns.Orchestrator
	if cfg.MockEngine {
		vpnOrchestrator = netns.Mock{}
	} else {
		manager, err := netns.New(cfg.DataDir)
		if err != nil {
			store.Close()
			return nil, err
		}
		vpnOrchestrator = manager
	}
	vpnGateService := vpngate.NewService(
		store, vpnOrchestrator, vpngate.NewFetcher(), cfg.VPNGateMaxExits,
	)
	vpnGateService.Start()
	authService := auth.NewService(store, cfg.SessionTTL)
	subscriptionService := subscription.NewService(store, sealer)
	monitorService := monitor.NewService(store, proxyEngine)
	createBackup := func(ctx context.Context, destination string) error {
		if err := store.IntegrityCheck(ctx); err != nil {
			return err
		}
		if err := store.Checkpoint(ctx); err != nil {
			return err
		}
		directory, err := os.MkdirTemp("", "j-ui-sqlite-snapshot-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(directory)
		snapshot := filepath.Join(directory, "j-ui.db")
		if err := store.Snapshot(ctx, snapshot); err != nil {
			return err
		}
		return backup.CreateWithDatabaseSnapshot(destination, cfg.DataDir, cfg.ConfigDir, snapshot)
	}
	systemAction := func(arguments ...string) func(context.Context) error {
		if cfg.MockEngine {
			return func(context.Context) error {
				return errors.New("system service operations are disabled in mock mode")
			}
		}
		return func(ctx context.Context) error {
			output, err := exec.CommandContext(ctx, "systemctl", arguments...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("systemctl %v: %w: %s", arguments, err, output)
			}
			return nil
		}
	}
	resolveDomain := func(ctx context.Context, domain string) error {
		addresses, err := net.DefaultResolver.LookupHost(ctx, domain)
		if err != nil || len(addresses) == 0 {
			return fmt.Errorf("域名 %s 尚未解析到公网地址", domain)
		}
		for _, address := range addresses {
			if publiclyRoutableIP(address) {
				return nil
			}
		}
		return fmt.Errorf("域名 %s 未解析到公网 IP", domain)
	}
	verifyHTTPSIngress := func(ctx context.Context, domain string) error {
		if err := resolveDomain(ctx, domain); err != nil {
			return err
		}
		if err := nodeService.VerifyAutomaticCertificate(domain); err == nil {
			return nil
		}
		escaped, escapeErr := exec.CommandContext(ctx, "systemd-escape", "--template=j-ui-certificate-issue@.service", domain).Output()
		if escapeErr != nil {
			return fmt.Errorf("无法生成证书任务名称：%w", escapeErr)
		}
		unit := strings.TrimSpace(string(escaped))
		output, err := exec.CommandContext(ctx, "systemctl", "start", unit).CombinedOutput()
		if err != nil {
			return fmt.Errorf("自动申请域名证书失败，请确认 DNS 已指向本机且 TCP 80 可访问：%s", strings.TrimSpace(string(output)))
		}
		if err := nodeService.VerifyAutomaticCertificate(domain); err != nil {
			return fmt.Errorf("自动申请后仍未找到有效证书：%w", err)
		}
		return nil
	}
	verifyCloudflareTunnel := func(ctx context.Context, domain string, requestedOriginPort int) (int, error) {
		if err := resolveDomain(ctx, domain); err != nil {
			return 0, err
		}
		if _, err := exec.LookPath("cloudflared"); err != nil {
			return 0, errors.New("未安装 cloudflared")
		}
		originPort, ok := requestedOriginPort, requestedOriginPort >= 1 && requestedOriginPort <= 65535
		if !ok {
			originPort, ok = cloudflaredConfigOriginPort(domain)
		}
		if !ok {
			originPort, ok = cloudflaredProfileOriginPort("/etc/j-ui/argo-profile.json", domain)
		}
		if !ok {
			return 0, fmt.Errorf("未找到 Tunnel 域名 %s 的本机入口配置", domain)
		}
		output, err := exec.CommandContext(ctx, "systemctl", "is-active", "cloudflared.service").CombinedOutput()
		if err != nil || strings.TrimSpace(string(output)) != "active" {
			return 0, errors.New("cloudflared 服务未运行")
		}
		if err := verifyCloudflarePublicRoute(ctx, domain, originPort); err != nil {
			return 0, err
		}
		return originPort, nil
	}

	app := &Application{
		Config:      cfg,
		Store:       store,
		Nodes:       nodeService,
		VPNGate:     vpnGateService,
		Credentials: credentials,
		Dependencies: api.Dependencies{
			Store: store, Auth: authService, Nodes: nodeService,
			VPNGate:       vpnGateService,
			Subscriptions: subscriptionService, Monitor: monitorService,
			MockMode:               cfg.MockEngine,
			LiveMockIPInspection:   cfg.MockEngine && os.Getenv("JUI_MOCK_LIVE_IP_INSPECTION") == "1",
			VerifyHTTPSIngress:     verifyHTTPSIngress,
			VerifyCloudflareTunnel: verifyCloudflareTunnel,
			Backup:                 createBackup,
			Restart:                systemAction("--no-block", "restart", "j-ui"),
			Update:                 systemAction("--no-block", "start", "j-ui-update.service"),
		},
		temporaryStop: make(chan struct{}),
		temporaryDone: make(chan struct{}),
	}
	app.startTemporaryWatcher()
	return app, nil
}

func publiclyRoutableIP(value string) bool {
	address, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("2001:db8::/32"),
	} {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func cloudflaredConfigOriginPort(domain string) (int, bool) {
	var data []byte
	for _, path := range []string{"/etc/cloudflared/config.yml", "/etc/cloudflared/config.yaml"} {
		contents, err := os.ReadFile(path)
		if err == nil {
			data = contents
			break
		}
	}
	return cloudflaredConfigDataOriginPort(data, domain)
}

func cloudflaredProfileOriginPort(path, domain string) (int, bool) {
	var profile struct {
		Domain     string `json:"domain"`
		OriginPort int    `json:"originPort"`
	}
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &profile) != nil ||
		!strings.EqualFold(strings.TrimSpace(profile.Domain), strings.TrimSpace(domain)) ||
		profile.OriginPort < 1 || profile.OriginPort > 65535 {
		return 0, false
	}
	return profile.OriginPort, true
}

func verifyCloudflarePublicRoute(ctx context.Context, domain string, originPort int) error {
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(originPort)))
	if err != nil {
		return fmt.Errorf("无法占用 127.0.0.1:%d 执行端到端检测，请先停用使用该端口的节点或服务", originPort)
	}
	nonce, err := secure.RandomHex(16)
	if err != nil {
		_ = listener.Close()
		return err
	}
	path := "/.well-known/j-ui-tunnel-check-" + nonce
	server := &http.Server{
		ReadHeaderTimeout: 3 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if r.URL.Path != path {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, nonce)
		}),
	}
	go func() { _ = server.Serve(listener) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, "https://"+domain+path, nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "J-UI-Tunnel-Check/1")
	client := &http.Client{Timeout: 5 * time.Second}
	for {
		response, requestErr := client.Do(request.Clone(probeCtx))
		if requestErr == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 256))
			_ = response.Body.Close()
			if readErr == nil && response.StatusCode == http.StatusOK && strings.TrimSpace(string(body)) == nonce {
				return nil
			}
		}
		select {
		case <-probeCtx.Done():
			return fmt.Errorf("Tunnel 公网域名未转发到 127.0.0.1:%d，请检查 Cloudflare Published application 路由", originPort)
		case <-time.After(time.Second):
		}
	}
}

func cloudflaredConfigDataOriginPort(data []byte, domain string) (int, bool) {
	var config struct {
		Tunnel  string `yaml:"tunnel"`
		Ingress []struct {
			Hostname string `yaml:"hostname"`
			Service  string `yaml:"service"`
		} `yaml:"ingress"`
	}
	if len(data) == 0 || yaml.Unmarshal(data, &config) != nil || strings.TrimSpace(config.Tunnel) == "" {
		return 0, false
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	for _, rule := range config.Ingress {
		hostname := strings.ToLower(strings.TrimSpace(rule.Hostname))
		matchesDomain := hostname == domain ||
			strings.HasPrefix(hostname, "*.") && strings.HasSuffix(domain, hostname[1:])
		if originPort, ok := cloudflaredOriginPort(rule.Service); matchesDomain && ok {
			return originPort, true
		}
	}
	return 0, false
}

func cloudflaredOriginPort(service string) (int, bool) {
	origin, err := url.Parse(strings.TrimSpace(service))
	if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") || origin.User != nil {
		return 0, false
	}
	host := origin.Hostname()
	ip := net.ParseIP(host)
	if !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
		return 0, false
	}
	port, err := strconv.Atoi(origin.Port())
	return port, err == nil && port >= 1 && port <= 65535
}

func (a *Application) Close() error {
	select {
	case <-a.temporaryStop:
	default:
		close(a.temporaryStop)
	}
	<-a.temporaryDone
	a.VPNGate.Close()
	return a.Store.Close()
}

func (a *Application) Reconcile(ctx context.Context) error {
	if err := a.Nodes.NormalizeProtocolPorts(ctx); err != nil {
		_ = a.Store.RecordEvent(ctx, "error", "protocol_port_migration_failed",
			"J-UI 启动时未能迁移 VLESS-WS 专用端口")
		return err
	}
	if err := a.Nodes.ExpireTemporary(ctx); err != nil {
		_ = a.Store.RecordEvent(ctx, "error", "temporary_node_reconcile_failed",
			"J-UI 启动时未能停用已过期的临时住宅节点")
		return err
	}
	if err := a.VPNGate.Reconcile(ctx); err != nil {
		_ = a.Store.RecordEvent(ctx, "error", "vpngate_reconcile_failed",
			"J-UI 启动时未能恢复临时出口，相关节点保持阻断")
		return err
	}
	if err := a.Nodes.Reconcile(ctx); err != nil {
		_ = a.Store.RecordEvent(ctx, "error", "startup_reconcile_failed",
			"J-UI 启动时未能恢复节点配置，服务将退出并等待人工检查")
		return err
	}
	return nil
}

func (a *Application) startTemporaryWatcher() {
	go func() {
		defer close(a.temporaryDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-a.temporaryStop:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				_ = a.Nodes.ExpireTemporary(ctx)
				cancel()
			}
		}
	}()
}

func bootstrap(ctx context.Context, store *database.Store, sealer *secure.Sealer, nodeStartPort int) (*Credentials, error) {
	password, err := secure.RandomToken(18)
	if err != nil {
		return nil, err
	}
	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		return nil, err
	}
	adminSuffix, err := secure.RandomHex(12)
	if err != nil {
		return nil, err
	}
	token, err := secure.RandomToken(32)
	if err != nil {
		return nil, err
	}
	encryptedToken, err := sealer.Seal([]byte(token))
	if err != nil {
		return nil, err
	}
	adminPath := "manage-" + adminSuffix
	if nodeStartPort < 1 || nodeStartPort > 65535 {
		nodeStartPort = nodeservice.DefaultStartPort
	}
	created, err := store.Bootstrap(ctx, database.Bootstrap{
		AdminPasswordHash: passwordHash,
		AdminPath:         adminPath,
		TokenHash:         secure.HashToken(token),
		TokenEncrypted:    encryptedToken,
		NodeStartPort:     nodeStartPort,
	})
	if err != nil {
		return nil, err
	}
	if !created {
		return nil, nil
	}
	return &Credentials{
		Username: "admin", Password: password, AdminPath: adminPath,
		SubscriptionToken: token,
	}, nil
}
