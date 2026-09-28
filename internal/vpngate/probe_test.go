package vpngate

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Suparluxi/j-ui/internal/model"
)

func resetResponse(session []byte) []byte {
	response := make([]byte, 26)
	response[0] = 8 << 3
	response[1] = 1
	response[9] = 1
	copy(response[14:22], session)
	return response
}

func TestResetResponseValidation(t *testing.T) {
	session := []byte("12345678")
	valid := resetResponse(session)
	if !validResetResponse(valid, session) {
		t.Fatal("valid reset rejected")
	}
	for _, packet := range [][]byte{nil, valid[:20], resetResponse([]byte("87654321")), []byte("HTTP/1.1 200 OK")} {
		if validResetResponse(packet, session) {
			t.Fatalf("invalid reset accepted: %x", packet)
		}
	}
	valid[13] = 1
	if validResetResponse(valid, session) {
		t.Fatal("unrelated ACK accepted")
	}
}

func TestProbeOpenVPNUDP(t *testing.T) {
	for _, reply := range []string{"reset", "garbage", "silent"} {
		t.Run(reply, func(t *testing.T) {
			server, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			go func() {
				packet := make([]byte, 64)
				n, address, err := server.ReadFrom(packet)
				if err != nil || n != 14 {
					return
				}
				switch reply {
				case "reset":
					_, _ = server.WriteTo(resetResponse(packet[1:9]), address)
				case "garbage":
					_, _ = server.WriteTo([]byte("not OpenVPN"), address)
				}
			}()
			connection, err := net.Dial("udp4", server.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			_ = connection.SetDeadline(time.Now().Add(100 * time.Millisecond))
			err = probeOpenVPN(ctx, connection, false)
			if (err == nil) != (reply == "reset") {
				t.Fatalf("reply=%s err=%v", reply, err)
			}
		})
	}
}

func TestCandidateProbeRejectsUnsafeConfiguration(t *testing.T) {
	for _, candidate := range []model.VPNGateCandidate{
		{IP: "127.0.0.1", OpenVPNConfig: "client\ndev tun\nremote localhost 1194\n"},
		{IP: "198.51.100.1", OpenVPNConfig: "client\ndev tun\nremote test 1194\nup /tmp/script\n"},
	} {
		if err := probeCandidate(context.Background(), candidate); err == nil {
			t.Fatal("unsafe candidate accepted")
		}
	}
}

func TestFilterReachableBoundedAndCancelAware(t *testing.T) {
	var active, peak atomic.Int32
	fetcher := &Fetcher{Probe: func(ctx context.Context, c model.VPNGateCandidate) error {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
			if c.HostName == "bad" {
				return context.DeadlineExceeded
			}
			return nil
		}
	}}
	candidates := make([]model.VPNGateCandidate, 100)
	for i := range candidates {
		candidates[i].HostName = "good"
	}
	candidates[0].HostName = "bad"
	got, err := fetcher.filterReachable(context.Background(), candidates)
	if err != nil || len(got) != 99 || peak.Load() > 16 {
		t.Fatalf("count=%d peak=%d err=%v", len(got), peak.Load(), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fetcher.filterReachable(ctx, candidates); err == nil {
		t.Fatal("canceled checks accepted")
	}
}

func TestParseMirrorDirectoryRejectsNonPublicAndDeduplicates(t *testing.T) {
	html := "<html><head><meta charset='UTF-8'></head><body>" +
		"<a href='http://150.40.105.1:1234/en/'>valid</a>" +
		"<a href='http://150.40.105.1:1234/en/'>duplicate</a>" +
		"<a href='http://127.0.0.1/en/'>local</a>" +
		"<a href='http://10.0.0.1/en/'>private</a>" +
		"<a href='http://user:pass@150.40.105.2/en/'>credentials</a>" +
		"<a href='http://150.40.105.2/other'>wrong path</a></body></html>"
	mirrors, err := parseMirrorList(strings.NewReader(html))
	if err != nil || len(mirrors) != 1 || mirrors[0] != "http://150.40.105.1:1234/api/iphone/" {
		t.Fatalf("mirrors=%v err=%v", mirrors, err)
	}
	if _, err := parseMirrorList(strings.NewReader("<html>blocked</html>")); err == nil {
		t.Fatal("empty directory accepted")
	}
}
