package monitor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Suparluxi/j-ui/internal/database"
	"github.com/Suparluxi/j-ui/internal/engine"
	"github.com/Suparluxi/j-ui/internal/model"
)

type Snapshot struct {
	Timestamp time.Time           `json:"timestamp"`
	CPU       float64             `json:"cpuPercent"`
	Memory    Memory              `json:"memory"`
	Disk      Disk                `json:"disk"`
	Network   Network             `json:"network"`
	Uptime    uint64              `json:"uptimeSeconds"`
	Load      []float64           `json:"load"`
	Services  Services            `json:"services"`
	Nodes     NodeSummary         `json:"nodes"`
	Exits     ExitSummary         `json:"exits"`
	Events    []model.SystemEvent `json:"events"`
}

type Memory struct {
	Total   uint64  `json:"totalBytes"`
	Used    uint64  `json:"usedBytes"`
	Percent float64 `json:"percent"`
}

type Disk struct {
	Total   uint64  `json:"totalBytes"`
	Used    uint64  `json:"usedBytes"`
	Percent float64 `json:"percent"`
}

type Network struct {
	UploadRate    uint64 `json:"uploadBytesPerSecond"`
	DownloadRate  uint64 `json:"downloadBytesPerSecond"`
	UploadTotal   uint64 `json:"uploadTotalBytes"`
	DownloadTotal uint64 `json:"downloadTotalBytes"`
}

type Services struct {
	JUI           string `json:"jui"`
	SingBox       string `json:"singBox"`
	OpenVPN       string `json:"openVPN"`
	Version       string `json:"singBoxVersion"`
	ConfigVersion int64  `json:"configVersion"`
}

type NodeSummary struct {
	Total   int `json:"total"`
	Enabled int `json:"enabled"`
	Faulted int `json:"faulted"`
}

type ExitSummary struct {
	Total   int `json:"total"`
	Running int `json:"running"`
	Faulted int `json:"faulted"`
}

type Info struct {
	OS             string `json:"os"`
	Kernel         string `json:"kernel"`
	Arch           string `json:"arch"`
	Hostname       string `json:"hostname"`
	IPv4           string `json:"ipv4,omitempty"`
	IPv6           string `json:"ipv6,omitempty"`
	CountryCode    string `json:"countryCode,omitempty"`
	Virtualization string `json:"virtualization"`
	TunAvailable   bool   `json:"tunAvailable"`
	MockMode       bool   `json:"mockMode"`
}

type Service struct {
	store       *database.Store
	engine      engine.Engine
	mu          sync.Mutex
	lastAt      time.Time
	lastCPU     cpuTimes
	lastRX      uint64
	lastTX      uint64
	versionOnce sync.Once
	version     string
	cachedAt    time.Time
	cached      Snapshot
}

type cpuTimes struct {
	total uint64
	idle  uint64
}

func NewService(store *database.Store, proxyEngine engine.Engine) *Service {
	return &Service{store: store, engine: proxyEngine}
}

func (s *Service) Snapshot(ctx context.Context) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if !s.cachedAt.IsZero() && now.Sub(s.cachedAt) < 1500*time.Millisecond {
		return s.cached, nil
	}
	cpu, err := readCPU()
	if err != nil {
		return Snapshot{}, err
	}
	rx, tx, err := readNetwork()
	if err != nil {
		return Snapshot{}, err
	}
	memory, err := readMemory()
	if err != nil {
		return Snapshot{}, err
	}
	disk, err := readDisk("/")
	if err != nil {
		return Snapshot{}, err
	}
	uptime, load, err := readUptimeAndLoad()
	if err != nil {
		return Snapshot{}, err
	}
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	exits, err := s.store.ListVPNGateExits(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	configVersion, err := s.store.LatestConfigVersion(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	events, err := s.store.RecentEvents(ctx, 10)
	if err != nil {
		return Snapshot{}, err
	}

	engineHealthy := s.engine.Healthy(ctx)
	s.versionOnce.Do(func() {
		s.version = s.engine.Version(ctx)
	})
	result := Snapshot{
		Timestamp: now.UTC(),
		Memory:    memory,
		Disk:      disk,
		Uptime:    uptime,
		Load:      load,
		Network: Network{
			UploadTotal: tx, DownloadTotal: rx,
		},
		Services: Services{
			JUI: "active", OpenVPN: "not-configured", SingBox: "inactive",
			Version: s.version, ConfigVersion: configVersion,
		},
		Nodes:  NodeSummary{Total: len(nodes)},
		Exits:  ExitSummary{Total: len(exits)},
		Events: events,
	}
	if len(exits) != 0 {
		result.Services.OpenVPN = "inactive"
	}
	for _, exit := range exits {
		switch exit.Status {
		case "running":
			result.Exits.Running++
		case "faulted":
			result.Exits.Faulted++
		}
	}
	if result.Exits.Running != 0 {
		result.Services.OpenVPN = "active"
	}
	if result.Exits.Faulted != 0 {
		result.Services.OpenVPN = "degraded"
	}
	if engineHealthy {
		result.Services.SingBox = "active"
	}
	var enabledListeners []engine.Listener
	type listenerRange struct{ start, end int }
	ranges := make([]listenerRange, len(nodes))
	for index, node := range nodes {
		ranges[index].start = len(enabledListeners)
		if node.Enabled {
			enabledListeners = append(enabledListeners, nodeListeners(node)...)
		}
		ranges[index].end = len(enabledListeners)
	}
	var statuses []bool
	if engineHealthy && len(enabledListeners) > 0 {
		if bulk, ok := s.engine.(engine.BulkListenerChecker); ok {
			statuses, err = bulk.ListenerStatuses(ctx, enabledListeners)
			if err != nil {
				statuses = nil
			}
		}
	}
	for index, node := range nodes {
		if node.Enabled {
			result.Nodes.Enabled++
		}
		listenersHealthy := engineHealthy
		if node.Enabled && listenersHealthy {
			if _, ok := s.engine.(engine.BulkListenerChecker); ok {
				listenersHealthy = statuses != nil && allHealthy(statuses[ranges[index].start:ranges[index].end])
			} else {
				listenersHealthy = s.engine.ListenersHealthy(ctx, nodeListeners(node)) == nil
			}
		}
		if node.Enabled && !listenersHealthy {
			result.Nodes.Faulted++
		}
	}
	if !s.lastAt.IsZero() {
		result.CPU, result.Network.UploadRate, result.Network.DownloadRate =
			calculateRates(cpu, s.lastCPU, tx, s.lastTX, rx, s.lastRX, now.Sub(s.lastAt).Seconds())
	}
	s.lastAt, s.lastCPU, s.lastRX, s.lastTX = now, cpu, rx, tx
	s.cachedAt, s.cached = now, result
	return result, nil
}

func allHealthy(statuses []bool) bool {
	for _, healthy := range statuses {
		if !healthy {
			return false
		}
	}
	return true
}

func nodeListeners(node model.Node) []engine.Listener {
	networks := []string{"tcp"}
	switch node.Protocol {
	case model.ProtocolHysteria2, model.ProtocolTUIC:
		networks = []string{"udp"}
	}
	listeners := make([]engine.Listener, 0, len(networks))
	for _, network := range networks {
		listeners = append(listeners, engine.Listener{
			Network: network, Host: node.Listen, Port: node.Port,
		})
	}
	return listeners
}

func SystemInfo() Info {
	hostname, _ := os.Hostname()
	ipv4, ipv6 := interfaceAddresses()
	kernel := "unknown"
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kernel = strings.TrimSpace(string(data))
	}
	osName := runtime.GOOS
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				osName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
			}
		}
	}
	return Info{
		OS: osName, Kernel: kernel, Arch: runtime.GOARCH, Hostname: hostname,
		IPv4: ipv4, IPv6: ipv6, CountryCode: countryCode(),
		Virtualization: virtualization(kernel), TunAvailable: tunAvailable(),
	}
}

func interfaceAddresses() (string, string) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", ""
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, address := range addrs {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil {
			ips = append(ips, ip)
		}
	}
	return selectAddresses(ips)
}

func selectAddresses(ips []net.IP) (string, string) {
	var ipv4, ipv6 net.IP
	for _, ip := range ips {
		if ip == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			if ipv4 == nil || ipv4.IsPrivate() && !v4.IsPrivate() {
				ipv4 = append(net.IP(nil), v4...)
			}
			continue
		}
		if ipv6 == nil || ipv6.IsPrivate() && !ip.IsPrivate() {
			ipv6 = append(net.IP(nil), ip...)
		}
	}
	var ipv4Text, ipv6Text string
	if ipv4 != nil {
		ipv4Text = ipv4.String()
	}
	if ipv6 != nil {
		ipv6Text = ipv6.String()
	}
	return ipv4Text, ipv6Text
}

func countryCode() string {
	code := strings.ToUpper(strings.TrimSpace(os.Getenv("JUI_COUNTRY_CODE")))
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return ""
	}
	return code
}

func tunAvailable() bool {
	info, err := os.Stat("/dev/net/tun")
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func virtualization(kernel string) string {
	if strings.Contains(strings.ToLower(kernel), "microsoft") {
		return "wsl"
	}
	data, _ := os.ReadFile("/proc/1/cgroup")
	value := strings.ToLower(string(data))
	switch {
	case strings.Contains(value, "docker"):
		return "docker"
	case strings.Contains(value, "kubepods"):
		return "kubernetes"
	case strings.Contains(value, "lxc"):
		return "lxc"
	default:
		return "unknown"
	}
}

func readCPU() (cpuTimes, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return cpuTimes{}, err
	}
	defer file.Close()
	var line string
	if scanner := bufio.NewScanner(file); scanner.Scan() {
		line = scanner.Text()
	}
	return parseCPU(line)
}

func parseCPU(line string) (cpuTimes, error) {
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuTimes{}, fmt.Errorf("unexpected /proc/stat")
	}
	var values []uint64
	for _, field := range fields[1:] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return cpuTimes{}, err
		}
		values = append(values, value)
	}
	var total uint64
	for _, value := range values {
		total += value
	}
	return cpuTimes{total: total, idle: values[3] + valueAt(values, 4)}, nil
}

func readMemory() (Memory, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return Memory{}, err
	}
	return parseMemory(string(data))
}

func parseMemory(data string) (Memory, error) {
	values := map[string]uint64{}
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			value, _ := strconv.ParseUint(fields[1], 10, 64)
			values[strings.TrimSuffix(fields[0], ":")] = value * 1024
		}
	}
	total, available := values["MemTotal"], values["MemAvailable"]
	if total == 0 || available > total {
		return Memory{}, errors.New("unexpected /proc/meminfo")
	}
	used := total - available
	return Memory{Total: total, Used: used, Percent: percent(used, total)}, nil
}

func readDisk(path string) (Disk, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return Disk{}, err
	}
	total := stat.Blocks * uint64(stat.Bsize)
	available := stat.Bavail * uint64(stat.Bsize)
	used := total - available
	return Disk{Total: total, Used: used, Percent: percent(used, total)}, nil
}

func readNetwork() (uint64, uint64, error) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0, err
	}
	return parseNetwork(string(data))
}

func parseNetwork(data string) (uint64, uint64, error) {
	var rx, tx uint64
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(strings.ReplaceAll(line, ":", " "))
		if len(fields) < 17 || fields[0] == "lo" {
			continue
		}
		received, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("parse receive bytes for %s: %w", fields[0], err)
		}
		transmitted, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("parse transmit bytes for %s: %w", fields[0], err)
		}
		rx += received
		tx += transmitted
	}
	return rx, tx, nil
}

func calculateRates(currentCPU, previousCPU cpuTimes, tx, previousTX, rx, previousRX uint64, seconds float64) (float64, uint64, uint64) {
	var cpuPercent float64
	if currentCPU.total >= previousCPU.total && currentCPU.idle >= previousCPU.idle {
		totalDelta := currentCPU.total - previousCPU.total
		idleDelta := currentCPU.idle - previousCPU.idle
		if totalDelta > 0 && idleDelta <= totalDelta {
			cpuPercent = float64(totalDelta-idleDelta) / float64(totalDelta) * 100
		}
	}
	var upload, download uint64
	if seconds > 0 {
		if tx >= previousTX {
			upload = uint64(float64(tx-previousTX) / seconds)
		}
		if rx >= previousRX {
			download = uint64(float64(rx-previousRX) / seconds)
		}
	}
	return cpuPercent, upload, download
}

func readUptimeAndLoad() (uint64, []float64, error) {
	uptimeData, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, nil, err
	}
	var uptime float64
	if _, err := fmt.Sscanf(string(uptimeData), "%f", &uptime); err != nil {
		return 0, nil, err
	}
	loadData, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, nil, err
	}
	var one, five, fifteen float64
	if _, err := fmt.Sscanf(string(loadData), "%f %f %f", &one, &five, &fifteen); err != nil {
		return 0, nil, err
	}
	return uint64(uptime), []float64{one, five, fifteen}, nil
}

func valueAt(values []uint64, index int) uint64 {
	if index < len(values) {
		return values[index]
	}
	return 0
}

func percent(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(used) / float64(total) * 100
}
