package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const serviceUnit = "j-ui-sing-box.service"

type Engine interface {
	Apply(context.Context, []byte, []Listener) error
	Healthy(context.Context) bool
	ListenersHealthy(context.Context, []Listener) error
	Version(context.Context) string
}

type BulkListenerChecker interface {
	ListenerStatuses(context.Context, []Listener) ([]bool, error)
}

type Listener struct {
	Network string
	Host    string
	Port    int
}

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "LC_ALL=") {
			command.Env = append(command.Env, entry)
		}
	}
	command.Env = append(command.Env, "LC_ALL=C")
	return command.CombinedOutput()
}

type System struct {
	Binary                  string
	ConfigPath              string
	ServiceUnit             string
	StartIfInactive         bool
	Runner                  Runner
	ListenerChecker         func(context.Context, []Listener) error
	RollbackListenerChecker func(context.Context, []Listener) error
	CommitTimeout           time.Duration
	RollbackTimeout         time.Duration
}

func (s *System) Apply(ctx context.Context, candidate []byte, listeners []Listener) error {
	runner := s.runner()
	if err := os.MkdirAll(filepath.Dir(s.ConfigPath), 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(s.ConfigPath), ".sing-box-*.json")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(candidate); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}

	if output, err := runner.Run(ctx, s.Binary, "check", "-c", tempPath); err != nil {
		return fmt.Errorf("sing-box validation failed: %w: %s", err, output)
	}

	previous, readErr := os.ReadFile(s.ConfigPath)
	hadPrevious := readErr == nil
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	if hadPrevious && bytes.Equal(previous, candidate) {
		if s.Healthy(ctx) && s.ListenersHealthy(ctx, listeners) == nil {
			return nil
		}
		if output, err := runner.Run(ctx, "systemctl", "restart", s.unit()); err != nil {
			return fmt.Errorf("restart unhealthy sing-box runtime: %w: %s", err, output)
		}
		if !s.Healthy(ctx) {
			return errors.New("sing-box remained unhealthy after restart")
		}
		checkListeners := s.ListenerChecker
		if checkListeners == nil {
			checkListeners = s.waitForListeners
		}
		if err := checkListeners(ctx, listeners); err != nil {
			return fmt.Errorf("sing-box listener health check after restart: %w", err)
		}
		return nil
	}
	if err := os.Rename(tempPath, s.ConfigPath); err != nil {
		return err
	}
	commitCtx, cancelCommit := context.WithTimeout(context.WithoutCancel(ctx), s.commitTimeout())
	defer cancelCommit()
	if err := syncDirectory(filepath.Dir(s.ConfigPath)); err != nil {
		if rollbackErr := s.rollbackSafely(ctx, previous, hadPrevious); rollbackErr != nil {
			return fmt.Errorf("sync configuration directory: %w; rollback failed: %v", err, rollbackErr)
		}
		return fmt.Errorf("sync configuration directory: %w; configuration rolled back", err)
	}

	// sing-box 1.13 validates the live file again on SIGHUP before replacing
	// the running instance. The systemd reload action delivers that signal.
	// Dedicated residential instances may not exist yet, so start them on
	// their first apply instead of trying to reload a missing unit.
	action := "reload"
	if s.StartIfInactive && !s.Healthy(commitCtx) {
		action = "start"
	}
	if output, err := runner.Run(commitCtx, "systemctl", action, s.unit()); err != nil {
		if rollbackErr := s.rollbackSafely(ctx, previous, hadPrevious); rollbackErr != nil {
			return fmt.Errorf("%s failed: %w: %s; rollback failed: %v", action, err, output, rollbackErr)
		}
		return fmt.Errorf("%s failed and was rolled back: %w: %s", action, err, output)
	}
	if err := settleReload(commitCtx); err != nil {
		if rollbackErr := s.rollbackSafely(ctx, previous, hadPrevious); rollbackErr != nil {
			return fmt.Errorf("wait for %s: %w; rollback failed: %v", action, err, rollbackErr)
		}
		return fmt.Errorf("wait for %s: %w; configuration rolled back", action, err)
	}
	if !s.Healthy(commitCtx) {
		if rollbackErr := s.rollbackSafely(ctx, previous, hadPrevious); rollbackErr != nil {
			return fmt.Errorf("sing-box unhealthy after %s; rollback failed: %v", action, rollbackErr)
		}
		return fmt.Errorf("sing-box unhealthy after %s; configuration rolled back", action)
	}
	checkListeners := s.ListenerChecker
	if checkListeners == nil {
		checkListeners = s.waitForListeners
	}
	if err := checkListeners(commitCtx, listeners); err != nil {
		if rollbackErr := s.rollbackSafely(ctx, previous, hadPrevious); rollbackErr != nil {
			return fmt.Errorf("sing-box listener health check failed after %s: %w; rollback failed: %v", action, err, rollbackErr)
		}
		return fmt.Errorf("sing-box listener health check failed after %s: %w; configuration rolled back", action, err)
	}
	return nil
}

func (s *System) rollbackSafely(ctx context.Context, previous []byte, hadPrevious bool) error {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.rollbackTimeout())
	defer cancel()
	return s.rollback(rollbackCtx, previous, hadPrevious)
}

func (s *System) commitTimeout() time.Duration {
	if s.CommitTimeout > 0 {
		return s.CommitTimeout
	}
	return 30 * time.Second
}

func (s *System) rollbackTimeout() time.Duration {
	if s.RollbackTimeout > 0 {
		return s.RollbackTimeout
	}
	return 30 * time.Second
}

func (s *System) rollback(ctx context.Context, previous []byte, hadPrevious bool) error {
	if hadPrevious {
		if err := atomicWrite(s.ConfigPath, previous); err != nil {
			return err
		}
	} else if err := os.Remove(s.ConfigPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !hadPrevious && s.StartIfInactive {
		_, _ = s.runner().Run(ctx, "systemctl", "stop", s.unit())
		return nil
	}
	if output, err := s.runner().Run(ctx, "systemctl", "reload", s.unit()); err != nil {
		reloadErr := fmt.Errorf("reload previous configuration: %w: %s", err, output)
		if restartOutput, restartErr := s.runner().Run(ctx, "systemctl", "restart", s.unit()); restartErr != nil {
			return fmt.Errorf("%w; restart fallback: %v: %s", reloadErr, restartErr, restartOutput)
		}
	}
	if err := settleReload(ctx); err != nil {
		return err
	}
	if !s.Healthy(ctx) {
		return errors.New("previous configuration restored but sing-box is unhealthy")
	}
	previousListeners, err := listenersFromConfiguration(previous, hadPrevious)
	if err != nil {
		return fmt.Errorf("previous configuration restored but listener metadata is invalid: %w", err)
	}
	checkListeners := s.RollbackListenerChecker
	if checkListeners == nil {
		checkListeners = s.waitForListeners
	}
	if err := checkListeners(ctx, previousListeners); err != nil {
		return fmt.Errorf("previous configuration restored but listener health failed: %w", err)
	}
	return nil
}

func settleReload(ctx context.Context) error {
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func atomicWrite(path string, content []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".rollback-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(content); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func (s *System) Healthy(ctx context.Context) bool {
	_, err := s.runner().Run(ctx, "systemctl", "is-active", "--quiet", s.unit())
	return err == nil
}

func (s *System) ListenersHealthy(ctx context.Context, listeners []Listener) error {
	statuses, err := s.ListenerStatuses(ctx, listeners)
	if err != nil {
		return err
	}
	for index, healthy := range statuses {
		if !healthy {
			return fmt.Errorf("%s port %d is not owned by sing-box",
				listeners[index].Network, listeners[index].Port)
		}
	}
	return nil
}

func (s *System) Version(ctx context.Context) string {
	output, err := s.runner().Run(ctx, s.Binary, "version")
	if err != nil {
		return "unavailable"
	}
	return firstLine(string(output))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func firstLine(value string) string {
	for i, character := range value {
		if character == '\n' || character == '\r' {
			return value[:i]
		}
	}
	return value
}

func (s *System) waitForListeners(ctx context.Context, listeners []Listener) error {
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	var lastErr error
	for {
		lastErr = s.ListenersHealthy(ctx, listeners)
		if lastErr == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return lastErr
		case <-ticker.C:
		}
	}
}

func (s *System) ListenerStatuses(ctx context.Context, listeners []Listener) ([]bool, error) {
	statuses := make([]bool, len(listeners))
	if len(listeners) == 0 {
		return statuses, nil
	}
	pidOutput, err := s.runner().Run(ctx, "systemctl", "show", "--property=MainPID", "--value", s.unit())
	if err != nil {
		return nil, fmt.Errorf("resolve sing-box MainPID: %w: %s", err, pidOutput)
	}
	mainPID, err := strconv.Atoi(strings.TrimSpace(string(pidOutput)))
	if err != nil || mainPID < 1 {
		return nil, fmt.Errorf("resolve sing-box MainPID: invalid value %q", strings.TrimSpace(string(pidOutput)))
	}
	output, err := s.runner().Run(ctx, "ss", "-H", "-ltnup")
	if err != nil {
		return nil, fmt.Errorf("inspect socket owners: %w: %s", err, output)
	}
	for index, expected := range listeners {
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 5 || fields[0] != expected.Network ||
				socketPort(fields[4]) != expected.Port ||
				!socketHostMatches(fields[4], expected.Host) ||
				!socketOwnedByPID(line, mainPID) {
				continue
			}
			statuses[index] = true
			break
		}
	}
	return statuses, nil
}

func socketOwnedByPID(line string, expected int) bool {
	for {
		index := strings.Index(line, "pid=")
		if index < 0 {
			return false
		}
		line = line[index+len("pid="):]
		end := 0
		for end < len(line) && line[end] >= '0' && line[end] <= '9' {
			end++
		}
		if end > 0 {
			pid, err := strconv.Atoi(line[:end])
			if err == nil && pid == expected {
				return true
			}
		}
		line = line[end:]
	}
}

func (s *System) runner() Runner {
	if s.Runner != nil {
		return s.Runner
	}
	return ExecRunner{}
}

func (s *System) unit() string {
	if strings.TrimSpace(s.ServiceUnit) != "" {
		return s.ServiceUnit
	}
	return serviceUnit
}

func socketPort(address string) int {
	index := strings.LastIndex(address, ":")
	if index < 0 || index == len(address)-1 {
		return 0
	}
	port, _ := strconv.Atoi(address[index+1:])
	return port
}

func socketHostMatches(address, expected string) bool {
	index := strings.LastIndex(address, ":")
	if index < 0 {
		return false
	}
	actual := strings.Trim(strings.TrimSpace(address[:index]), "[]")
	if zone := strings.LastIndex(actual, "%"); zone >= 0 {
		actual = actual[:zone]
	}
	expected = strings.Trim(strings.TrimSpace(expected), "[]")
	if zone := strings.LastIndex(expected, "%"); zone >= 0 {
		expected = expected[:zone]
	}
	if expected == "" {
		expected = "0.0.0.0"
	}
	if actual == "*" {
		// Current iproute2 renders an IPv6 wildcard as "*:port"; IPv4
		// wildcards remain "0.0.0.0:port".
		actual = "::"
	}
	actualIP := net.ParseIP(actual)
	expectedIP := net.ParseIP(expected)
	if actualIP == nil || expectedIP == nil {
		return actual == expected
	}
	if actualIP.IsUnspecified() {
		if expectedIP.IsUnspecified() {
			return (actualIP.To4() == nil) == (expectedIP.To4() == nil)
		}
		return (actualIP.To4() == nil) == (expectedIP.To4() == nil)
	}
	return actualIP.Equal(expectedIP)
}

func listenersFromConfiguration(config []byte, present bool) ([]Listener, error) {
	if !present {
		return []Listener{}, nil
	}
	var document struct {
		Inbounds []struct {
			Type       string `json:"type"`
			Listen     string `json:"listen"`
			ListenPort int    `json:"listen_port"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(config, &document); err != nil {
		return nil, err
	}
	listeners := make([]Listener, 0, len(document.Inbounds))
	for _, inbound := range document.Inbounds {
		network := ""
		switch inbound.Type {
		case "vless", "trojan", "socks", "anytls":
			network = "tcp"
		case "hysteria2", "tuic":
			network = "udp"
		default:
			return nil, fmt.Errorf("unsupported inbound type %q", inbound.Type)
		}
		if inbound.ListenPort < 1 || inbound.ListenPort > 65535 ||
			net.ParseIP(inbound.Listen) == nil {
			return nil, fmt.Errorf("invalid %s listener %q:%d",
				inbound.Type, inbound.Listen, inbound.ListenPort)
		}
		listeners = append(listeners, Listener{
			Network: network, Host: inbound.Listen, Port: inbound.ListenPort,
		})
	}
	return listeners, nil
}

func listenersHealthy(ctx context.Context, listeners []Listener) error {
	for _, listener := range listeners {
		address := net.JoinHostPort(healthCheckHost(listener.Host), strconv.Itoa(listener.Port))
		switch listener.Network {
		case "tcp":
			connection, err := net.Listen("tcp", address)
			if err == nil {
				_ = connection.Close()
				return fmt.Errorf("tcp %s is not bound", address)
			}
			if !errors.Is(err, syscall.EADDRINUSE) {
				return fmt.Errorf("check tcp %s: %w", address, err)
			}
		case "udp":
			connection, err := net.ListenPacket("udp", address)
			if err == nil {
				_ = connection.Close()
				return fmt.Errorf("udp %s is not bound", address)
			}
			if !errors.Is(err, syscall.EADDRINUSE) {
				return fmt.Errorf("check udp %s: %w", address, err)
			}
		default:
			return fmt.Errorf("unsupported listener network %q", listener.Network)
		}
	}
	return nil
}

func healthCheckHost(host string) string {
	switch host {
	case "", "0.0.0.0":
		return "127.0.0.1"
	case "::":
		return "::1"
	default:
		return host
	}
}

type Mock struct {
	Configuration []byte
}

func (m *Mock) Apply(_ context.Context, config []byte, _ []Listener) error {
	m.Configuration = append(m.Configuration[:0], config...)
	return nil
}

func (*Mock) Healthy(context.Context) bool {
	return true
}

func (*Mock) ListenersHealthy(context.Context, []Listener) error {
	return nil
}

func (*Mock) ListenerStatuses(_ context.Context, listeners []Listener) ([]bool, error) {
	statuses := make([]bool, len(listeners))
	for index := range statuses {
		statuses[index] = true
	}
	return statuses, nil
}

func (*Mock) Version(context.Context) string {
	return "mock"
}
