package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Suparluxi/j-ui/internal/api"
	"github.com/Suparluxi/j-ui/internal/application"
	"github.com/Suparluxi/j-ui/internal/auth"
	"github.com/Suparluxi/j-ui/internal/backup"
	"github.com/Suparluxi/j-ui/internal/config"
	"github.com/Suparluxi/j-ui/internal/database"
	"github.com/Suparluxi/j-ui/internal/engine"
	"github.com/Suparluxi/j-ui/internal/firewall"
	"github.com/Suparluxi/j-ui/internal/model"
	"github.com/Suparluxi/j-ui/internal/monitor"
	"github.com/Suparluxi/j-ui/internal/netns"
	"github.com/Suparluxi/j-ui/internal/secure"
	"github.com/Suparluxi/j-ui/internal/socksbridge"
	"github.com/Suparluxi/j-ui/internal/tundns"
	"github.com/Suparluxi/j-ui/web"
)

const singBoxUnit = "j-ui-sing-box.service"

var (
	systemctlCommand      = runSystemctl
	verifyStartedServices = startAndVerify
	cleanupStateFirewall  = cleanupFirewallForState
	cleanupVPNGateState   = cleanupVPNGateSlots
	loadRecoveryRules     = firewallRecoveryRulesForState
	mergeRecoveryRules    = mergeFirewallRecoveryRulesIntoState
	lifecycleLockPath     = "/run/lock/j-ui-lifecycle.lock"
)

func main() {
	cfg := config.Load()
	if len(os.Args) == 1 && os.Getenv("JUI_SERVICE_MODE") != "server" {
		if err := runManagementMenu(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) > 1 {
		if err := runCommand(cfg, os.Args[1:]); err != nil {
			log.Fatal(err)
		}
		return
	}

	app, err := application.OpenExisting(context.Background(), cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer app.Close()
	if err := app.Reconcile(context.Background()); err != nil {
		log.Fatalf("initial sing-box reconciliation failed: %v", err)
	}

	server := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           api.NewHandler(web.Assets(), app.Dependencies),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	shutdownSignals, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stop()

	go func() {
		<-shutdownSignals.Done()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
		}
	}()

	scheme := "http"
	serve := server.ListenAndServe
	if cfg.TLSCertificate != "" || cfg.TLSPrivateKey != "" {
		if cfg.TLSCertificate == "" || cfg.TLSPrivateKey == "" {
			log.Fatal("both JUI_TLS_CERTIFICATE_PATH and JUI_TLS_KEY_PATH are required")
		}
		scheme = "https"
		serve = func() error { return server.ListenAndServeTLS(cfg.TLSCertificate, cfg.TLSPrivateKey) }
	}
	log.Printf("J-UI listening on %s://%s", scheme, cfg.ListenAddress)
	if err := serve(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func runCommand(cfg config.Config, args []string) error {
	switch args[0] {
	case "internal-socks-bridge":
		if len(args) != 2 {
			return errors.New("invalid internal SOCKS bridge invocation")
		}
		bridgeConfig, err := socksbridge.LoadConfig(args[1])
		if err != nil {
			return err
		}
		signals, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		return socksbridge.Serve(signals, bridgeConfig)
	case "internal-probe":
		if len(args) != 2 || (args[1] != "https://api64.ipify.org?format=json" &&
			args[1] != "https://ifconfig.co/json") {
			return errors.New("invalid internal probe invocation")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, args[1], nil)
		if err != nil {
			return err
		}
		transport := &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
				return tundns.IPv4Dialer().DialContext(ctx, "tcp4", address)
			},
			ForceAttemptHTTP2: true,
		}
		defer transport.CloseIdleConnections()
		response, err := (&http.Client{Transport: transport, Timeout: 10 * time.Second}).Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("identity probe returned HTTP %d", response.StatusCode)
		}
		var body struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&body); err != nil {
			return err
		}
		if net.ParseIP(body.IP) == nil {
			return errors.New("identity probe returned an invalid IP")
		}
		return json.NewEncoder(os.Stdout).Encode(body)
	case "init":
		app, err := application.New(context.Background(), cfg)
		if err != nil {
			return err
		}
		defer app.Close()
		if app.Credentials == nil {
			fmt.Println("J-UI is already initialized")
			return nil
		}
		printCredentials(cfg, app)
		return nil
	case "get-public-host":
		return printPublicHost(cfg)
	case "get-admin-path":
		return printAdminPath(cfg)
	case "get-node-start-port":
		return printNodeStartPort(cfg)
	case "get-admin-username":
		return printAdminUsername(cfg)
	case "reset-password":
		return resetAdminPassword(cfg, args[1:])
	case "set-credentials":
		return setAdminCredentials(cfg, args[1:])
	case "set-language":
		return setUILanguage(cfg, args[1:])
	case "configure-install":
		return configureInstall(cfg, args[1:])
	case "configure-argo":
		return configureArgo(cfg, args[1:])
	case "ssl":
		return runExternal("/usr/local/lib/j-ui/ssl.sh", args[1:]...)
	case "argo":
		return runExternal("/usr/local/lib/j-ui/argo.sh", args[1:]...)
	case "status":
		return systemctlCommand("status", "--no-pager", "j-ui")
	case "start":
		return systemctlCommand("start", singBoxUnit, "j-ui.service")
	case "stop":
		return systemctlCommand("stop", "j-ui.service", singBoxUnit)
	case "info":
		return printInfo(cfg)
	case "settings":
		return printInfo(cfg)
	case "restart":
		return systemctlCommand("restart", singBoxUnit, "j-ui.service")
	case "enable":
		return systemctlCommand("enable", "--now", singBoxUnit, "j-ui.service")
	case "disable":
		return systemctlCommand("disable", "--now", "j-ui.service", singBoxUnit)
	case "log":
		command := []string{"-u", "j-ui.service", "-u", singBoxUnit, "--no-pager", "-n", "200"}
		return runExternal("journalctl", command...)
	case "backup":
		destination := backup.DefaultName()
		if len(args) > 1 {
			destination = args[1]
		}
		absolute, err := filepath.Abs(destination)
		if err != nil {
			return err
		}
		app, err := application.OpenExisting(context.Background(), cfg)
		if err != nil {
			return err
		}
		if err := app.Store.IntegrityCheck(context.Background()); err != nil {
			app.Close()
			return err
		}
		if err := app.Store.Checkpoint(context.Background()); err != nil {
			app.Close()
			return err
		}
		snapshotDirectory, err := os.MkdirTemp("", "j-ui-sqlite-snapshot-*")
		if err != nil {
			app.Close()
			return err
		}
		defer os.RemoveAll(snapshotDirectory)
		snapshot := filepath.Join(snapshotDirectory, "j-ui.db")
		if err := app.Store.Snapshot(context.Background(), snapshot); err != nil {
			app.Close()
			return err
		}
		if err := app.Close(); err != nil {
			return err
		}
		if err := backup.CreateWithDatabaseSnapshot(absolute, cfg.DataDir, cfg.ConfigDir, snapshot); err != nil {
			return err
		}
		fmt.Println(absolute)
		return nil
	case "restore":
		if len(args) != 2 {
			return errors.New("usage: j-ui restore <backup.tar.gz>")
		}
		lock, err := acquireLifecycleLock()
		if err != nil {
			return err
		}
		defer releaseLifecycleLock(lock)
		if err := systemctlCommand("stop", "j-ui.service", singBoxUnit); err != nil {
			return err
		}
		if err := cleanupVPNGateState(context.Background(), cfg); err != nil {
			_ = systemctlCommand("start", singBoxUnit, "j-ui.service")
			return fmt.Errorf("clean VPNGate slots before restore: %w", err)
		}
		rollbackDirectory, err := os.MkdirTemp("", "j-ui-pre-restore-*")
		if err != nil {
			_ = systemctlCommand("start", singBoxUnit, "j-ui.service")
			return err
		}
		defer os.RemoveAll(rollbackDirectory)
		rollbackArchive := filepath.Join(rollbackDirectory, "backup.tar.gz")
		if err := backup.Create(rollbackArchive, cfg.DataDir, cfg.ConfigDir); err != nil {
			_ = systemctlCommand("start", singBoxUnit, "j-ui.service")
			return fmt.Errorf("create restore rollback point: %w", err)
		}
		if err := cleanupStateFirewall(cfg); err != nil {
			recoveryErr := verifyStartedServices(cfg)
			return fmt.Errorf(
				"close current managed firewall rules before restore: %w; service recovery: %v",
				err, recoveryErr,
			)
		}
		if restoreErr := backup.Restore(args[1], cfg.DataDir, cfg.ConfigDir); restoreErr != nil {
			rollbackErr := backup.Restore(rollbackArchive, cfg.DataDir, cfg.ConfigDir)
			if rollbackErr != nil {
				return fmt.Errorf("restore failed: %w; rollback failed: %v", restoreErr, rollbackErr)
			}
			rollbackCfg := restoredConfig(cfg)
			startErr := verifyStartedServices(rollbackCfg)
			if startErr != nil {
				return fmt.Errorf("restore failed: %w; rollback: %v; service recovery: %v",
					restoreErr, rollbackErr, startErr)
			}
			return fmt.Errorf("restore failed and the previous data and services were restored: %w", restoreErr)
		}
		targetCfg := restoredConfig(cfg)
		if targetCfg.DataDir != cfg.DataDir || targetCfg.ConfigDir != cfg.ConfigDir ||
			targetCfg.SingBoxBinary != cfg.SingBoxBinary || targetCfg.MockEngine != cfg.MockEngine {
			restoreErr := errors.New(
				"backup changes data/config roots, engine mode, or sing-box binary; restore it into a matching installation",
			)
			rollbackErr := backup.Restore(rollbackArchive, cfg.DataDir, cfg.ConfigDir)
			if rollbackErr != nil {
				return fmt.Errorf("restore configuration is incompatible: %w; rollback failed: %v",
					restoreErr, rollbackErr)
			}
			rollbackCfg := restoredConfig(cfg)
			startErr := verifyStartedServices(rollbackCfg)
			return fmt.Errorf("restore configuration is incompatible: %w; rollback: %v; service recovery: %v",
				restoreErr, rollbackErr, startErr)
		}
		if err := verifyStartedServices(targetCfg); err != nil {
			_ = systemctlCommand("stop", "j-ui.service", singBoxUnit)
			targetFirewallErr := cleanupStateFirewall(targetCfg)
			targetVPNGateErr := cleanupVPNGateState(context.Background(), targetCfg)
			targetFirewallErr = errors.Join(targetFirewallErr, targetVPNGateErr)
			recoveryRules, recoveryReadErr := loadRecoveryRules(targetCfg)
			targetFirewallErr = errors.Join(targetFirewallErr, recoveryReadErr)
			if rollbackErr := backup.Restore(rollbackArchive, cfg.DataDir, cfg.ConfigDir); rollbackErr != nil {
				return fmt.Errorf(
					"start restored services: %w; target firewall cleanup: %v; restore rollback failed: %v",
					err, targetFirewallErr, rollbackErr,
				)
			}
			rollbackCfg := restoredConfig(cfg)
			if mergeErr := mergeRecoveryRules(rollbackCfg, recoveryRules); mergeErr != nil {
				return fmt.Errorf(
					"start restored services: %w; target firewall cleanup: %v; previous data restored but residual firewall recovery state could not be saved: %v",
					err, targetFirewallErr, mergeErr,
				)
			}
			if rollbackStartErr := verifyStartedServices(rollbackCfg); rollbackStartErr != nil {
				return fmt.Errorf(
					"start restored services: %w; target firewall cleanup: %v; previous data restored but services failed to start: %v",
					err, targetFirewallErr, rollbackStartErr,
				)
			}
			return fmt.Errorf(
				"start restored services: %w; target firewall cleanup: %v; previous data and services were restored",
				err, targetFirewallErr,
			)
		}
		return nil
	case "update":
		return runExternal("/usr/local/lib/j-ui/update.sh")
	case "internal-update-result":
		if len(args) != 3 || (args[1] != "success" && args[1] != "failed") {
			return errors.New("invalid internal update result")
		}
		app, err := application.OpenExisting(context.Background(), cfg)
		if err != nil {
			return err
		}
		defer app.Close()
		level, code, message := "info", "update_succeeded", "在线更新已完成并通过服务健康检查"
		if args[1] == "failed" {
			level, code, message = "error", "update_rolled_back", "在线更新失败；旧版本、数据库和配置已自动恢复"
		}
		return app.Store.RecordEvent(context.Background(), level, code, message+"（v"+args[2]+"）")
	case "internal-health-url":
		url, err := healthURL(cfg)
		if err != nil {
			return err
		}
		fmt.Println(url)
		return nil
	case "cleanup-firewall":
		app, err := application.OpenExisting(context.Background(), cfg)
		if err != nil {
			return err
		}
		defer app.Close()
		return app.Nodes.CleanupFirewall(context.Background())
	case "ensure-management-firewall":
		_, port, err := net.SplitHostPort(cfg.ListenAddress)
		if err != nil {
			return err
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil {
			return err
		}
		result, err := firewall.EnsureManagement(context.Background(), firewall.System{Runner: engine.ExecRunner{}}, filepath.Join(cfg.ConfigDir, "management-firewall.json"), portNumber)
		if err != nil {
			return err
		}
		fmt.Printf("Ownership: %s\nBackend: %s\n", result.Ownership, result.Backend)
		return nil
	case "close-management-firewall":
		return firewall.CloseManagement(context.Background(), firewall.System{Runner: engine.ExecRunner{}}, filepath.Join(cfg.ConfigDir, "management-firewall.json"))
	case "ensure-acme-firewall":
		result, err := firewall.EnsureManagement(context.Background(), firewall.System{Runner: engine.ExecRunner{}}, filepath.Join(cfg.ConfigDir, "acme-firewall.json"), 80)
		if err != nil {
			return err
		}
		fmt.Printf("Ownership: %s\nBackend: %s\n", result.Ownership, result.Backend)
		return nil
	case "close-acme-firewall":
		return firewall.CloseManagement(context.Background(), firewall.System{Runner: engine.ExecRunner{}}, filepath.Join(cfg.ConfigDir, "acme-firewall.json"))
	case "cleanup-vpngate":
		return cleanupVPNGateSlots(context.Background(), cfg)
	case "uninstall":
		return runExternal("/usr/local/lib/j-ui/uninstall.sh")
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

type installConfigureOptions struct {
	publicHost         string
	language           string
	certificateMode    string
	certificatePath    string
	certificateKeyPath string
	cloudflareDomain   string
}

type installCertificateDefaults struct {
	Mode        string `json:"mode"`
	Certificate string `json:"certificatePath,omitempty"`
	PrivateKey  string `json:"keyPath,omitempty"`
}

type installProtocolPrerequisites struct {
	HTTPSIngressEnabled     bool   `json:"httpsIngressEnabled"`
	HTTPSIngressDomain      string `json:"httpsIngressDomain"`
	HTTPSIngressVerifiedAt  string `json:"httpsIngressVerifiedAt,omitempty"`
	HTTPSIngressSimulated   bool   `json:"httpsIngressSimulated,omitempty"`
	CloudflareTunnelEnabled bool   `json:"cloudflareTunnelEnabled"`
	CloudflareTunnelDomain  string `json:"cloudflareTunnelDomain"`
	CloudflareOriginPort    int    `json:"cloudflareTunnelOriginPort,omitempty"`
	CloudflareVerifiedAt    string `json:"cloudflareTunnelVerifiedAt,omitempty"`
	CloudflareSimulated     bool   `json:"cloudflareTunnelSimulated,omitempty"`
}

type argoConfigureOptions struct {
	domain     string
	originPort int
}

func configureArgo(cfg config.Config, args []string) error {
	options, err := parseArgoConfigureArgs(args)
	if err != nil {
		return err
	}
	app, err := application.OpenExisting(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer app.Close()
	if app.Dependencies.VerifyCloudflareTunnel == nil {
		return errors.New("Cloudflare Tunnel verification is unavailable")
	}
	verifiedPort, err := app.Dependencies.VerifyCloudflareTunnel(context.Background(), options.domain, options.originPort)
	if err != nil {
		return fmt.Errorf("Cloudflare Tunnel verification failed: %w", err)
	}
	if verifiedPort != options.originPort {
		return fmt.Errorf("verified origin port is %d, expected %d", verifiedPort, options.originPort)
	}

	stored, settingErr := app.Store.Setting(context.Background(), "protocol_prerequisites")
	if settingErr != nil && !errors.Is(settingErr, sql.ErrNoRows) {
		return settingErr
	}
	prerequisites := installProtocolPrerequisites{}
	if stored != "" {
		if err := json.Unmarshal([]byte(stored), &prerequisites); err != nil {
			return err
		}
	}
	if prerequisites.CloudflareTunnelEnabled &&
		(!strings.EqualFold(prerequisites.CloudflareTunnelDomain, options.domain) ||
			prerequisites.CloudflareOriginPort != options.originPort) {
		nodes, listErr := app.Nodes.List(context.Background())
		if listErr != nil {
			return listErr
		}
		for _, node := range nodes {
			if node.Enabled && node.Protocol == model.ProtocolVLESSArgo {
				return errors.New("stop existing Argo nodes before changing the Tunnel domain or origin port")
			}
		}
	}
	prerequisites.CloudflareTunnelEnabled = true
	prerequisites.CloudflareTunnelDomain = options.domain
	prerequisites.CloudflareOriginPort = options.originPort
	prerequisites.CloudflareVerifiedAt = time.Now().UTC().Format(time.RFC3339)
	prerequisites.CloudflareSimulated = app.Config.MockEngine
	encoded, err := json.Marshal(prerequisites)
	if err != nil {
		return err
	}
	if err := app.Store.SetSetting(context.Background(), "protocol_prerequisites", string(encoded)); err != nil {
		return err
	}
	fmt.Printf("Argo Tunnel configured: %s -> 127.0.0.1:%d\n", options.domain, options.originPort)
	return nil
}

func parseArgoConfigureArgs(args []string) (argoConfigureOptions, error) {
	options := argoConfigureOptions{}
	for index := 0; index < len(args); index++ {
		if index+1 >= len(args) {
			return options, fmt.Errorf("missing value for %s", args[index])
		}
		value := args[index+1]
		switch args[index] {
		case "--domain":
			options.domain = value
		case "--origin-port":
			port, err := strconv.Atoi(value)
			if err != nil {
				return options, errors.New("origin port must be a number")
			}
			options.originPort = port
		default:
			return options, fmt.Errorf("unknown configure-argo option %q", args[index])
		}
		index++
	}
	normalizedDomain, err := normalizeInstallDomain(options.domain)
	if err != nil {
		return options, errors.New("a valid Tunnel public domain is required")
	}
	options.domain = normalizedDomain
	if options.originPort < 1 || options.originPort > 65535 {
		return options, errors.New("origin port must be between 1 and 65535")
	}
	return options, nil
}

func printPublicHost(cfg config.Config) error {
	app, err := application.OpenExisting(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer app.Close()
	value, err := app.Store.Setting(context.Background(), "public_host")
	if err != nil {
		return nil
	}
	fmt.Println(value)
	return nil
}

func printAdminPath(cfg config.Config) error {
	app, err := application.OpenExisting(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer app.Close()
	value, err := app.Store.Setting(context.Background(), "admin_path")
	if err != nil {
		return err
	}
	fmt.Println(value)
	return nil
}

func printInfo(cfg config.Config) error {
	info := monitor.SystemInfo()
	webBasePath, managementURL, err := managementDetails(cfg)
	if err != nil {
		webBasePath = "unavailable"
		managementURL = "unavailable"
	}
	fmt.Printf("Version: %s\nsing-box version: %s\nnet.ipv4.tcp_congestion_control: %s\nnet.core.default_qdisc: %s\nListen address: %s\nWebBasePath: %s\nManagement URL: %s\nData directory: %s\nConfig directory: %s\nOS: %s\nArchitecture: %s\nVirtualization: %s\nTUN available: %t\n",
		api.Version, installedSingBoxVersion(cfg.SingBoxBinary),
		kernelSetting("/proc/sys/net/ipv4/tcp_congestion_control"),
		kernelSetting("/proc/sys/net/core/default_qdisc"),
		cfg.ListenAddress, webBasePath, managementURL, cfg.DataDir, cfg.ConfigDir,
		info.OS, info.Arch, info.Virtualization, info.TunAvailable)
	return nil
}

func installedSingBoxVersion(binary string) string {
	if strings.TrimSpace(binary) == "" {
		return "unavailable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, "version").Output()
	if err != nil {
		return "unavailable"
	}
	line := strings.TrimSpace(strings.SplitN(string(output), "\n", 2)[0])
	version := strings.TrimSpace(strings.TrimPrefix(line, "sing-box version"))
	if version == "" || version == line {
		return "unavailable"
	}
	return version
}

func kernelSetting(path string) string {
	value, err := os.ReadFile(path)
	if err != nil {
		return "unavailable"
	}
	trimmed := strings.TrimSpace(string(value))
	if trimmed == "" {
		return "unavailable"
	}
	return trimmed
}

func managementDetails(cfg config.Config) (string, string, error) {
	app, err := application.OpenExisting(context.Background(), cfg)
	if err != nil {
		return "", "", err
	}
	defer app.Close()
	adminPath, err := app.Store.Setting(context.Background(), "admin_path")
	if err != nil {
		return "", "", err
	}
	publicHost, err := app.Store.Setting(context.Background(), "public_host")
	if err != nil {
		return "", "", err
	}
	_, port, err := net.SplitHostPort(cfg.ListenAddress)
	if err != nil {
		return "", "", err
	}
	webBasePath := "/" + strings.Trim(adminPath, "/") + "/"
	return webBasePath, managementScheme(cfg) + "://" + net.JoinHostPort(publicHost, port) + webBasePath, nil
}

func managementScheme(cfg config.Config) string {
	if cfg.TLSCertificate != "" && cfg.TLSPrivateKey != "" {
		return "https"
	}
	return "http"
}

// resetAdminPassword is intentionally root-only: it is a local recovery path
// for an administrator who lost the randomly generated bootstrap password.
// It changes no node, subscription, or system settings and invalidates all
// existing sessions through Store.ChangePassword.
func resetAdminPassword(cfg config.Config, args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("run password reset as root")
	}
	if len(args) > 1 || (len(args) == 1 && args[0] != "--generate") {
		return errors.New("usage: j-ui reset-password [--generate]")
	}
	app, err := application.OpenExisting(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer app.Close()

	ctx := context.Background()
	username, err := app.Store.AdministratorUsername(ctx)
	if err != nil {
		return err
	}
	password, err := generateAndSaveAdminPassword(ctx, app.Store)
	if err != nil {
		return err
	}
	fmt.Printf("J-UI administrator password reset\nUsername: %s\nPassword: %s\n", username, password)
	return nil
}

func printAdminUsername(cfg config.Config) error {
	app, err := application.OpenExisting(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer app.Close()
	username, err := app.Store.AdministratorUsername(context.Background())
	if err != nil {
		return err
	}
	fmt.Println(username)
	return nil
}

func setAdminCredentials(cfg config.Config, args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("run credential replacement as root")
	}
	if len(args) != 3 || args[0] != "--username" || args[2] != "--password-stdin" {
		return errors.New("usage: j-ui set-credentials --username NAME --password-stdin")
	}
	username := strings.TrimSpace(args[1])
	passwordBytes, err := io.ReadAll(io.LimitReader(os.Stdin, 1025))
	if err != nil {
		return fmt.Errorf("read administrator password: %w", err)
	}
	if len(passwordBytes) > 1024 {
		return errors.New("administrator password is too long")
	}
	password := strings.TrimSuffix(strings.TrimSuffix(string(passwordBytes), "\n"), "\r")
	app, err := application.OpenExisting(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer app.Close()
	if err := replaceAdminCredentials(context.Background(), app.Store, username, password); err != nil {
		return err
	}
	fmt.Printf("J-UI administrator credentials replaced\nUsername: %s\n", username)
	return nil
}

func replaceAdminCredentials(ctx context.Context, store *database.Store, username, password string) error {
	if !auth.ValidAdministratorUsername(username) {
		return errors.New("administrator username must be 3-32 ASCII letters, digits, dots, underscores, or hyphens")
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	if err := store.ChangeAdministrator(ctx, username, hash); err != nil {
		return err
	}
	storedHash, err := store.PasswordHash(ctx, username)
	if err != nil || !auth.VerifyPassword(storedHash, password) {
		return errors.New("administrator credentials failed post-write verification")
	}
	return nil
}

func setUILanguage(cfg config.Config, args []string) error {
	if len(args) != 1 || (args[0] != "zh-CN" && args[0] != "en") {
		return errors.New("usage: j-ui set-language zh-CN|en")
	}
	app, err := application.OpenExisting(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer app.Close()
	return app.Store.SetSetting(context.Background(), "ui_language", args[0])
}

func generateAndSaveAdminPassword(ctx context.Context, store *database.Store) (string, error) {
	password, err := secure.RandomToken(18)
	if err != nil {
		return "", fmt.Errorf("generate administrator password: %w", err)
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return "", fmt.Errorf("hash administrator password: %w", err)
	}
	if err := store.ChangePassword(ctx, hash); err != nil {
		return "", fmt.Errorf("save administrator password: %w", err)
	}
	return password, nil
}

func printNodeStartPort(cfg config.Config) error {
	app, err := application.OpenExisting(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer app.Close()
	settings, err := app.Nodes.PortSettings(context.Background())
	if err != nil {
		return err
	}
	fmt.Println(settings.StartPort)
	return nil
}

func configureInstall(cfg config.Config, args []string) (err error) {
	options, err := parseInstallConfigureArgs(args)
	if err != nil {
		return err
	}
	if options.certificateMode != "auto" && options.certificateMode != "manual" {
		return errors.New("certificate mode must be auto or manual")
	}
	if options.language != "" && options.language != "zh-CN" && options.language != "en" {
		return errors.New("language must be zh-CN or en")
	}
	if options.certificateMode == "manual" {
		if err := validateInstallCertificate(options.certificatePath, options.certificateKeyPath); err != nil {
			return err
		}
		if options.certificatePath == options.certificateKeyPath {
			return errors.New("certificate and private key paths must be different")
		}
	} else {
		options.certificatePath, options.certificateKeyPath = "", ""
	}
	if options.publicHost != "" {
		options.publicHost, err = normalizeInstallHost(options.publicHost)
		if err != nil {
			return err
		}
	}
	if options.cloudflareDomain != "" {
		options.cloudflareDomain, err = normalizeInstallDomain(options.cloudflareDomain)
		if err != nil {
			return err
		}
	}

	app, err := application.OpenExisting(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer app.Close()
	ctx := context.Background()
	oldPublicHost, _ := app.Store.Setting(ctx, "public_host")
	oldLanguage, _ := app.Store.Setting(ctx, "ui_language")
	oldCertificateDefaults, _ := app.Store.Setting(ctx, "certificate_defaults")
	oldPrerequisites, _ := app.Store.Setting(ctx, "protocol_prerequisites")
	committed := false
	defer func() {
		if err == nil || committed {
			return
		}
		_ = app.Store.SetSetting(ctx, "public_host", oldPublicHost)
		_ = app.Store.SetSetting(ctx, "ui_language", oldLanguage)
		_ = app.Store.SetSetting(ctx, "certificate_defaults", oldCertificateDefaults)
		_ = app.Store.SetSetting(ctx, "protocol_prerequisites", oldPrerequisites)
	}()

	if options.publicHost != "" {
		if err = app.Store.SetSetting(ctx, "public_host", options.publicHost); err != nil {
			return err
		}
	}
	if options.language != "" {
		if err = app.Store.SetSetting(ctx, "ui_language", options.language); err != nil {
			return err
		}
	}
	certificateJSON, err := json.Marshal(installCertificateDefaults{
		Mode: options.certificateMode, Certificate: options.certificatePath, PrivateKey: options.certificateKeyPath,
	})
	if err != nil {
		return err
	}
	if err = app.Store.SetSetting(ctx, "certificate_defaults", string(certificateJSON)); err != nil {
		return err
	}
	prerequisites := installProtocolPrerequisites{}
	if oldPrerequisites != "" {
		_ = json.Unmarshal([]byte(oldPrerequisites), &prerequisites)
	}
	prerequisitesChanged := false
	if options.publicHost != "" {
		// An installation profile is authoritative. Never carry a previously
		// verified HTTPS ingress domain into a reinstall whose public host or
		// certificate has changed.
		prerequisites.HTTPSIngressEnabled = false
		prerequisites.HTTPSIngressDomain = ""
		prerequisites.HTTPSIngressVerifiedAt = ""
		prerequisites.HTTPSIngressSimulated = false
		prerequisitesChanged = true
		if options.certificateMode == "auto" && net.ParseIP(options.publicHost) == nil {
			if certificateErr := app.Nodes.VerifyAutomaticCertificate(options.publicHost); certificateErr != nil {
				return fmt.Errorf("verify automatically issued certificate: %w", certificateErr)
			}
			prerequisites.HTTPSIngressEnabled = true
			prerequisites.HTTPSIngressDomain = options.publicHost
			prerequisites.HTTPSIngressVerifiedAt = time.Now().UTC().Format(time.RFC3339)
			prerequisites.HTTPSIngressSimulated = app.Config.MockEngine
		}
	}
	if options.cloudflareDomain != "" {
		if app.Dependencies.VerifyCloudflareTunnel == nil {
			return errors.New("Cloudflare Tunnel verification is unavailable")
		}
		originPort, verifyErr := app.Dependencies.VerifyCloudflareTunnel(ctx, options.cloudflareDomain, 0)
		if verifyErr != nil {
			return fmt.Errorf("Cloudflare Tunnel verification failed: %w", verifyErr)
		}
		prerequisites.CloudflareTunnelEnabled = true
		prerequisites.CloudflareTunnelDomain = options.cloudflareDomain
		prerequisites.CloudflareOriginPort = originPort
		prerequisites.CloudflareVerifiedAt = time.Now().UTC().Format(time.RFC3339)
		prerequisites.CloudflareSimulated = app.Config.MockEngine
		prerequisitesChanged = true
	}
	if prerequisitesChanged {
		encoded, marshalErr := json.Marshal(prerequisites)
		if marshalErr != nil {
			return marshalErr
		}
		if err = app.Store.SetSetting(ctx, "protocol_prerequisites", string(encoded)); err != nil {
			return err
		}
	}
	committed = true
	fmt.Println("J-UI installation profile saved")
	return nil
}

func parseInstallConfigureArgs(args []string) (installConfigureOptions, error) {
	options := installConfigureOptions{certificateMode: "auto"}
	for index := 0; index < len(args); index++ {
		if index+1 >= len(args) {
			return options, fmt.Errorf("missing value for %s", args[index])
		}
		value := args[index+1]
		switch args[index] {
		case "--public-host":
			options.publicHost = value
		case "--language":
			options.language = value
		case "--certificate-mode":
			options.certificateMode = value
		case "--certificate-path":
			options.certificatePath = value
		case "--key-path":
			options.certificateKeyPath = value
		case "--argo-domain":
			options.cloudflareDomain = value
		default:
			return options, fmt.Errorf("unknown configure-install option %q", args[index])
		}
		index++
	}
	return options, nil
}

func validateInstallCertificate(certificatePath, keyPath string) error {
	for label, path := range map[string]string{"certificate": certificatePath, "private key": keyPath} {
		if !filepath.IsAbs(path) {
			return fmt.Errorf("%s path must be absolute", label)
		}
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("stat %s: %w", label, err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s must be a regular file not writable by group or others", label)
		}
	}
	return nil
}

func normalizeInstallHost(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "://") || strings.ContainsAny(value, "/?#@") {
		return "", errors.New("public host must be a domain or IP without a scheme or path")
	}
	value = strings.TrimPrefix(strings.TrimSuffix(value, "]"), "[")
	if net.ParseIP(value) != nil {
		return value, nil
	}
	return normalizeInstallDomain(value)
}

func normalizeInstallDomain(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) > 253 || !strings.Contains(value, ".") {
		return "", errors.New("domain format is invalid")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("domain format is invalid")
		}
		for _, character := range label {
			if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-') {
				return "", errors.New("domain may contain only letters, digits, dots, and hyphens")
			}
		}
	}
	return value, nil
}

func cleanupVPNGateSlots(ctx context.Context, cfg config.Config) error {
	if cfg.MockEngine {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	manager, err := netns.New(cfg.DataDir)
	if err != nil {
		return err
	}
	var failures []error
	for slot := 1; slot <= 5; slot++ {
		if err := manager.Stop(ctx, model.VPNGateExit{Slot: slot}); err != nil {
			failures = append(failures, fmt.Errorf("slot %d: %w", slot, err))
		}
	}
	return errors.Join(failures...)
}

func cleanupFirewallForState(cfg config.Config) error {
	app, err := application.OpenExisting(context.Background(), cfg)
	if err != nil {
		return err
	}
	cleanupErr := app.Nodes.CleanupFirewall(context.Background())
	closeErr := app.Close()
	return errors.Join(cleanupErr, closeErr)
}

func restoredConfig(fallback config.Config) config.Config {
	return config.ReloadFromFile(filepath.Join(fallback.ConfigDir, "j-ui.env"), fallback)
}

func acquireLifecycleLock() (*os.File, error) {
	lock, err := os.OpenFile(lifecycleLockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lifecycle lock: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, errors.New("another J-UI install, update, or restore operation is running")
	}
	return lock, nil
}

func releaseLifecycleLock(lock *os.File) {
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	_ = lock.Close()
}

func firewallRecoveryRulesForState(cfg config.Config) ([]database.ManagedFirewallRule, error) {
	app, err := application.OpenExisting(context.Background(), cfg)
	if err != nil {
		return nil, err
	}
	rules, rulesErr := app.Store.ManagedFirewallRules(context.Background())
	closeErr := app.Close()
	recovery := make([]database.ManagedFirewallRule, 0, len(rules))
	for _, rule := range rules {
		if rule.Ownership == database.FirewallOwned || rule.Ownership == database.FirewallPending {
			recovery = append(recovery, rule)
		}
	}
	return recovery, errors.Join(rulesErr, closeErr)
}

func mergeFirewallRecoveryRulesIntoState(
	cfg config.Config, rules []database.ManagedFirewallRule,
) error {
	app, err := application.OpenExisting(context.Background(), cfg)
	if err != nil {
		return err
	}
	mergeErr := app.Store.MergeFirewallRecoveryRules(context.Background(), rules)
	closeErr := app.Close()
	return errors.Join(mergeErr, closeErr)
}

func startAndVerify(cfg config.Config) error {
	if err := runSystemctl("start", singBoxUnit, "j-ui.service"); err != nil {
		return err
	}
	healthURL, err := healthURL(cfg)
	if err != nil {
		return err
	}
	client := internalHealthClient(cfg)
	var lastErr error
	for attempt := 0; attempt < 20; attempt++ {
		if err := runSystemctl("is-active", "--quiet", singBoxUnit, "j-ui.service"); err != nil {
			lastErr = err
		} else {
			response, requestErr := client.Get(healthURL)
			if requestErr == nil {
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK {
					return nil
				}
				lastErr = fmt.Errorf("management health returned %s", response.Status)
			} else {
				lastErr = requestErr
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("services did not become healthy: %w", lastErr)
}

func healthURL(cfg config.Config) (string, error) {
	host, port, err := net.SplitHostPort(cfg.ListenAddress)
	if err != nil {
		return "", err
	}
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	} else if host == "::" {
		host = "::1"
	}
	return managementScheme(cfg) + "://" + net.JoinHostPort(host, port) + "/api/v1/health", nil
}

func internalHealthClient(cfg config.Config) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if managementScheme(cfg) == "https" {
		// The readiness probe only reaches J-UI on loopback. Public browser
		// connections still perform normal certificate verification.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402
	}
	return &http.Client{Transport: transport, Timeout: time.Second}
}

func printCredentials(cfg config.Config, app *application.Application) {
	fmt.Printf("J-UI initialized\nUsername: %s\nPassword: %s\nManagement URL: %s://%s/%s/\nSubscription Token: %s\n",
		app.Credentials.Username,
		app.Credentials.Password,
		managementScheme(cfg),
		cfg.ListenAddress,
		app.Credentials.AdminPath,
		app.Credentials.SubscriptionToken,
	)
}

func runSystemctl(args ...string) error {
	return runExternal("systemctl", args...)
}

func runManagementMenu() error {
	menuPath := os.Getenv("JUI_MENU_PATH")
	if menuPath == "" {
		menuPath = "/usr/local/lib/j-ui/manage.sh"
	}
	return runExternal(menuPath)
}

func runExternal(name string, args ...string) error {
	command := exec.Command(name, args...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	return command.Run()
}
