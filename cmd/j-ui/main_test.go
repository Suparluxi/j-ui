package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Suparluxi/j-ui/internal/application"
	"github.com/Suparluxi/j-ui/internal/auth"
	"github.com/Suparluxi/j-ui/internal/backup"
	"github.com/Suparluxi/j-ui/internal/config"
	"github.com/Suparluxi/j-ui/internal/database"
	"github.com/Suparluxi/j-ui/internal/model"
)

func TestRestoreCleansTargetFirewallBeforeFailedTargetRollback(t *testing.T) {
	root := t.TempDir()
	current := commandTestConfig(filepath.Join(root, "current"))
	target := commandTestConfig(filepath.Join(root, "target"))
	initializeCommandTestState(t, current, "old.example.com")
	initializeCommandTestState(t, target, "new.example.com")
	if err := os.WriteFile(
		filepath.Join(target.ConfigDir, "j-ui.env"),
		[]byte("JUI_LISTEN_ADDRESS=127.0.0.1:9090\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	targetArchive := filepath.Join(root, "target.tar.gz")
	if err := backup.Create(targetArchive, target.DataDir, target.ConfigDir); err != nil {
		t.Fatal(err)
	}

	oldSystemctl := systemctlCommand
	oldVerify := verifyStartedServices
	oldCleanup := cleanupStateFirewall
	oldVPNCleanup := cleanupVPNGateState
	oldLoadRules := loadRecoveryRules
	oldMergeRules := mergeRecoveryRules
	oldLockPath := lifecycleLockPath
	t.Cleanup(func() {
		systemctlCommand = oldSystemctl
		verifyStartedServices = oldVerify
		cleanupStateFirewall = oldCleanup
		cleanupVPNGateState = oldVPNCleanup
		loadRecoveryRules = oldLoadRules
		mergeRecoveryRules = oldMergeRules
		lifecycleLockPath = oldLockPath
	})
	lifecycleLockPath = filepath.Join(root, "j-ui-lifecycle.lock")
	systemctlCommand = func(...string) error { return nil }
	vpnCleanupCalls := 0
	cleanupVPNGateState = func(_ context.Context, cfg config.Config) error {
		vpnCleanupCalls++
		if vpnCleanupCalls == 1 && cfg.DataDir != current.DataDir {
			t.Fatalf("current VPNGate cleanup config = %#v", cfg)
		}
		if vpnCleanupCalls == 2 && cfg.ListenAddress != "127.0.0.1:9090" {
			t.Fatalf("target VPNGate cleanup config = %#v", cfg)
		}
		return nil
	}
	cleanupCalls := 0
	cleanupStateFirewall = func(config.Config) error {
		cleanupCalls++
		if cleanupCalls == 2 {
			return errors.New("injected partial target firewall cleanup")
		}
		return nil
	}
	recoveryRule := database.ManagedFirewallRule{
		Protocol: "tcp", Port: 24443,
		Ownership: database.FirewallOwned, Backend: database.FirewallUFW,
	}
	loadRecoveryRules = func(config.Config) ([]database.ManagedFirewallRule, error) {
		return []database.ManagedFirewallRule{recoveryRule}, nil
	}
	mergeCalls := 0
	mergeRecoveryRules = func(_ config.Config, rules []database.ManagedFirewallRule) error {
		mergeCalls++
		if len(rules) != 1 || rules[0] != recoveryRule {
			t.Fatalf("merged firewall recovery rules = %#v", rules)
		}
		return nil
	}
	startCalls := 0
	verifyStartedServices = func(cfg config.Config) error {
		startCalls++
		if startCalls == 1 {
			if cfg.ListenAddress != "127.0.0.1:9090" {
				t.Fatalf("target verify config = %#v", cfg)
			}
			return errors.New("injected target health failure")
		}
		if cfg.ListenAddress != current.ListenAddress {
			t.Fatalf("rollback verify config = %#v", cfg)
		}
		return nil
	}

	err := runCommand(current, []string{"restore", targetArchive})
	if err == nil || !strings.Contains(err.Error(), "previous data and services were restored") {
		t.Fatalf("restore error = %v", err)
	}
	if cleanupCalls != 2 {
		t.Fatalf("firewall cleanup calls = %d, want current and failed target", cleanupCalls)
	}
	if vpnCleanupCalls != 2 {
		t.Fatalf("VPNGate cleanup calls = %d, want current and failed target", vpnCleanupCalls)
	}
	if mergeCalls != 1 {
		t.Fatalf("firewall recovery merge calls = %d", mergeCalls)
	}
	app, err := application.OpenExisting(context.Background(), current)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	host, err := app.Store.Setting(context.Background(), "public_host")
	if err != nil || host != "old.example.com" {
		t.Fatalf("state after rollback host=%q err=%v", host, err)
	}
}

func TestLifecycleLockRejectsConcurrentRestore(t *testing.T) {
	oldPath := lifecycleLockPath
	lifecycleLockPath = filepath.Join(t.TempDir(), "j-ui-lifecycle.lock")
	t.Cleanup(func() { lifecycleLockPath = oldPath })
	first, err := acquireLifecycleLock()
	if err != nil {
		t.Fatal(err)
	}
	defer releaseLifecycleLock(first)
	if second, err := acquireLifecycleLock(); err == nil {
		releaseLifecycleLock(second)
		t.Fatal("second lifecycle operation acquired the lock")
	}
}

func TestConfigureInstallStoresPublicHostAndCertificateDefaults(t *testing.T) {
	root := t.TempDir()
	cfg := commandTestConfig(root)
	app, err := application.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	if err := configureInstall(cfg, []string{
		"--public-host", "198.51.100.10",
		"--language", "en",
		"--certificate-mode", "auto",
	}); err != nil {
		t.Fatal(err)
	}
	configured, err := application.OpenExisting(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer configured.Close()
	host, err := configured.Store.Setting(context.Background(), "public_host")
	if err != nil || host != "198.51.100.10" {
		t.Fatalf("public host = %q, err=%v", host, err)
	}
	language, err := configured.Store.Setting(context.Background(), "ui_language")
	if err != nil || language != "en" {
		t.Fatalf("UI language = %q, err=%v", language, err)
	}
	certificateDefaults, err := configured.Store.Setting(context.Background(), "certificate_defaults")
	if err != nil || !strings.Contains(certificateDefaults, `"mode":"auto"`) {
		t.Fatalf("certificate defaults = %q, err=%v", certificateDefaults, err)
	}
}

func TestConfigureInstallClearsStaleHTTPSIngressForIPProfile(t *testing.T) {
	root := t.TempDir()
	cfg := commandTestConfig(root)
	app, err := application.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Store.SetSetting(context.Background(), "protocol_prerequisites",
		`{"httpsIngressEnabled":true,"httpsIngressDomain":"old.example.com","httpsIngressVerifiedAt":"2026-08-01T00:00:00Z","cloudflareTunnelEnabled":true,"cloudflareTunnelDomain":"argo.example.com"}`); err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	if err := configureInstall(cfg, []string{
		"--public-host", "198.51.100.10",
		"--certificate-mode", "auto",
	}); err != nil {
		t.Fatal(err)
	}
	configured, err := application.OpenExisting(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer configured.Close()
	prerequisites, err := configured.Store.Setting(context.Background(), "protocol_prerequisites")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(prerequisites, "old.example.com") || strings.Contains(prerequisites, `"httpsIngressEnabled":true`) {
		t.Fatalf("stale HTTPS ingress survived reinstall: %s", prerequisites)
	}
	if !strings.Contains(prerequisites, "argo.example.com") {
		t.Fatalf("unrelated Argo prerequisite was not preserved: %s", prerequisites)
	}
}

func TestParseArgoConfigureArgs(t *testing.T) {
	options, err := parseArgoConfigureArgs([]string{
		"--domain", "Argo.Example.com", "--origin-port", "2080",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.domain != "argo.example.com" || options.originPort != 2080 {
		t.Fatalf("Argo options = %#v", options)
	}
	for _, args := range [][]string{
		{"--domain", "invalid", "--origin-port", "2080"},
		{"--domain", "argo.example.com", "--origin-port", "0"},
		{"--domain", "argo.example.com", "--origin-port", "not-a-port"},
	} {
		if _, err := parseArgoConfigureArgs(args); err == nil {
			t.Fatalf("expected invalid Argo options %#v to fail", args)
		}
	}
}

func TestManagementDetailsUsesPublicHostAndAdminPath(t *testing.T) {
	root := t.TempDir()
	cfg := commandTestConfig(root)
	cfg.ListenAddress = "0.0.0.0:8080"
	initializeCommandTestState(t, cfg, "2001:db8::10")

	webBasePath, managementURL, err := managementDetails(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(webBasePath, "/manage-") || !strings.HasSuffix(webBasePath, "/") {
		t.Fatalf("WebBasePath = %q", webBasePath)
	}
	if managementURL != "http://[2001:db8::10]:8080"+webBasePath {
		t.Fatalf("management URL = %q", managementURL)
	}
	cfg.TLSCertificate = "/etc/letsencrypt/live/example/fullchain.pem"
	cfg.TLSPrivateKey = "/etc/letsencrypt/live/example/privkey.pem"
	_, managementURL, err = managementDetails(cfg)
	if err != nil || managementURL != "https://[2001:db8::10]:8080"+webBasePath {
		t.Fatalf("TLS management URL = %q err=%v", managementURL, err)
	}
}

func TestInfoWorksBeforeInitialization(t *testing.T) {
	if err := printInfo(commandTestConfig(t.TempDir())); err != nil {
		t.Fatal(err)
	}
}

func TestInstalledSingBoxVersion(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "sing-box")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf 'sing-box version 1.13.16\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := installedSingBoxVersion(binary); got != "1.13.16" {
		t.Fatalf("installedSingBoxVersion() = %q", got)
	}
	if got := installedSingBoxVersion(filepath.Join(t.TempDir(), "missing")); got != "unavailable" {
		t.Fatalf("missing sing-box version = %q", got)
	}
}

func TestKernelSetting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "setting")
	if err := os.WriteFile(path, []byte("bbr\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := kernelSetting(path); got != "bbr" {
		t.Fatalf("kernelSetting() = %q", got)
	}
	if got := kernelSetting(filepath.Join(t.TempDir(), "missing")); got != "unavailable" {
		t.Fatalf("missing kernel setting = %q", got)
	}
}

func TestLifecycleCommandsUsePanelServices(t *testing.T) {
	oldSystemctl := systemctlCommand
	t.Cleanup(func() { systemctlCommand = oldSystemctl })
	var calls [][]string
	systemctlCommand = func(args ...string) error {
		calls = append(calls, append([]string(nil), args...))
		return nil
	}
	cfg := commandTestConfig(t.TempDir())
	commands := []string{"start", "stop", "restart", "enable", "disable"}
	for _, command := range commands {
		if err := runCommand(cfg, []string{command}); err != nil {
			t.Fatalf("%s: %v", command, err)
		}
	}
	want := [][]string{
		{"start", singBoxUnit, "j-ui.service"},
		{"stop", "j-ui.service", singBoxUnit},
		{"restart", singBoxUnit, "j-ui.service"},
		{"enable", "--now", singBoxUnit, "j-ui.service"},
		{"disable", "--now", "j-ui.service", singBoxUnit},
	}
	if fmt.Sprint(calls) != fmt.Sprint(want) {
		t.Fatalf("systemctl calls = %#v, want %#v", calls, want)
	}
}

func TestRunManagementMenuUsesConfiguredPath(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "menu-invoked")
	menu := filepath.Join(root, "menu.sh")
	if err := os.WriteFile(menu, []byte("#!/bin/sh\nprintf invoked >\""+marker+"\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldPath := os.Getenv("JUI_MENU_PATH")
	t.Cleanup(func() {
		if oldPath == "" {
			_ = os.Unsetenv("JUI_MENU_PATH")
		} else {
			_ = os.Setenv("JUI_MENU_PATH", oldPath)
		}
	})
	if err := os.Setenv("JUI_MENU_PATH", menu); err != nil {
		t.Fatal(err)
	}
	if err := runManagementMenu(); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(marker); err != nil || string(content) != "invoked" {
		t.Fatalf("management menu marker = %q, err=%v", content, err)
	}
}

func TestGenerateAndSaveAdminPassword(t *testing.T) {
	root := t.TempDir()
	cfg := commandTestConfig(root)
	app, err := application.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	password, err := generateAndSaveAdminPassword(context.Background(), app.Store)
	if err != nil {
		t.Fatal(err)
	}
	if len(password) < 12 {
		t.Fatalf("generated password length = %d, want at least 12", len(password))
	}
	hash, err := app.Store.PasswordHash(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !auth.VerifyPassword(hash, password) {
		t.Fatal("generated password does not verify")
	}
	if auth.VerifyPassword(hash, app.Credentials.Password) {
		t.Fatal("old bootstrap password still verifies")
	}
}

func TestAdministratorReplacementChangesUsernameAndPassword(t *testing.T) {
	root := t.TempDir()
	cfg := commandTestConfig(root)
	app, err := application.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	sessionHash := "replacement-session"
	if err := app.Store.CreateSession(context.Background(), model.Session{
		TokenHash: sessionHash, CSRFToken: "csrf", ExpiresAt: time.Now().Add(time.Hour),
	}, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := replaceAdminCredentials(context.Background(), app.Store, "jui-a1b2c3", "new-unique-password-123"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Store.PasswordHash(context.Background(), "admin"); err == nil {
		t.Fatal("old administrator username still resolves")
	}
	stored, err := app.Store.PasswordHash(context.Background(), "jui-a1b2c3")
	if err != nil || !auth.VerifyPassword(stored, "new-unique-password-123") {
		t.Fatalf("replacement credentials do not verify: %v", err)
	}
	if _, err := app.Store.Session(context.Background(), sessionHash); err == nil {
		t.Fatal("existing administrator session survived credential replacement")
	}
	if err := replaceAdminCredentials(context.Background(), app.Store, "invalid account", "valid-password"); err == nil {
		t.Fatal("invalid replacement administrator username was accepted")
	}
}

func TestSetUILanguagePersistsInstallerSelection(t *testing.T) {
	root := t.TempDir()
	cfg := commandTestConfig(root)
	app, err := application.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	if err := setUILanguage(cfg, []string{"en"}); err != nil {
		t.Fatal(err)
	}
	configured, err := application.OpenExisting(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer configured.Close()
	language, err := configured.Store.Setting(context.Background(), "ui_language")
	if err != nil || language != "en" {
		t.Fatalf("stored language = %q, err=%v", language, err)
	}
}

func initializeCommandTestState(t *testing.T, cfg config.Config, host string) {
	t.Helper()
	app, err := application.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Store.SetSetting(context.Background(), "public_host", host); err != nil {
		app.Close()
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
}

func commandTestConfig(root string) config.Config {
	return config.Config{
		ListenAddress: "127.0.0.1:8080",
		DataDir:       filepath.Join(root, "data"),
		ConfigDir:     filepath.Join(root, "config"),
		DatabasePath:  filepath.Join(root, "data", "j-ui.db"),
		SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"),
		SessionTTL:    time.Hour,
		MockEngine:    true,
	}
}
