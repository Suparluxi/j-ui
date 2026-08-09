package monitor

import (
	"math"
	"net"
	"testing"

	"github.com/Suparluxi/j-ui/internal/model"
)

func TestMetricParsers(t *testing.T) {
	cpu, err := parseCPU("cpu  100 20 30 400 50 6 7 8 0 0")
	if err != nil {
		t.Fatal(err)
	}
	if cpu.total != 621 || cpu.idle != 450 {
		t.Fatalf("CPU = %#v", cpu)
	}
	memory, err := parseMemory("MemTotal: 1000 kB\nMemAvailable: 250 kB\n")
	if err != nil {
		t.Fatal(err)
	}
	if memory.Total != 1024000 || memory.Used != 768000 || memory.Percent != 75 {
		t.Fatalf("memory = %#v", memory)
	}
	rx, tx, err := parseNetwork(
		"Inter-| Receive | Transmit\n" +
			" lo: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0\n" +
			"eth0: 1000 0 0 0 0 0 0 0 3000 0 0 0 0 0 0 0\n" +
			"eth1: 2000 0 0 0 0 0 0 0 4000 0 0 0 0 0 0 0\n")
	if err != nil {
		t.Fatal(err)
	}
	if rx != 3000 || tx != 7000 {
		t.Fatalf("network totals = %d, %d", rx, tx)
	}
}

func TestSelectAddressesPrefersPublicInterfaces(t *testing.T) {
	ipv4, ipv6 := selectAddresses([]net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("10.0.0.8"),
		net.ParseIP("203.0.113.7"),
		net.ParseIP("fd00::8"),
		net.ParseIP("2001:db8::7"),
	})
	if ipv4 != "203.0.113.7" || ipv6 != "2001:db8::7" {
		t.Fatalf("addresses = %q, %q", ipv4, ipv6)
	}
}

func TestSOCKS5MonitoringOnlyChecksFixedTCPListener(t *testing.T) {
	listeners := nodeListeners(model.Node{
		Protocol: model.ProtocolSOCKS5, Listen: "127.0.0.1", Port: 1080,
	})
	if len(listeners) != 1 || listeners[0].Network != "tcp" {
		t.Fatalf("SOCKS5 listeners = %#v", listeners)
	}
}

func TestRateDeltasAndCounterReset(t *testing.T) {
	cpu, upload, download := calculateRates(
		cpuTimes{total: 1200, idle: 700}, cpuTimes{total: 1000, idle: 600},
		5000, 3000, 9000, 5000, 2,
	)
	if math.Abs(cpu-50) > 0.001 || upload != 1000 || download != 2000 {
		t.Fatalf("rates = %.2f, %d, %d", cpu, upload, download)
	}
	cpu, upload, download = calculateRates(
		cpuTimes{total: 10, idle: 5}, cpuTimes{total: 1000, idle: 600},
		10, 3000, 20, 5000, 2,
	)
	if cpu != 0 || upload != 0 || download != 0 {
		t.Fatalf("counter reset underflowed: %.2f, %d, %d", cpu, upload, download)
	}
}
