package vpngate

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Suparluxi/j-ui/internal/model"
)

func catalogCSV(host, ip, protocol string, port int) string {
	config := base64.StdEncoding.EncodeToString([]byte("client\ndev tun\nproto " + protocol + "\nremote " + ip + " " + fmt.Sprint(port) + "\n"))
	return host + "," + ip + ",20,50,2000,Japan,JP,2,2000,0,0,2weeks,op,msg," + config + "\n"
}

func TestFetcherPrimaryWinsWithoutMirrorFetch(t *testing.T) {
	mirrorCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mirror" {
			mirrorCalls++
		}
		_, _ = w.Write([]byte(catalogCSV("primary", "198.51.100.1", "udp", 1194)))
	}))
	defer server.Close()
	fetcher := &Fetcher{URL: server.URL, MirrorURLs: []string{server.URL + "/mirror"}, Client: server.Client()}
	got, err := fetcher.Fetch(context.Background())
	if err != nil || len(got) != 1 || mirrorCalls != 0 {
		t.Fatalf("got=%v err=%v mirrorCalls=%d", got, err, mirrorCalls)
	}
}

func TestRefreshMirrorsDiscoversOfficialEndpoints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method=%s", r.Method)
		}
		_, _ = w.Write([]byte("<html><body><a href='http://150.40.105.19:35399/en/'>mirror</a></body></html>"))
	}))
	defer server.Close()
	fetcher := &Fetcher{MirrorListURL: server.URL, MirrorURLs: []string{"http://198.51.100.2/en/"}, Client: server.Client()}
	if err := fetcher.RefreshMirrors(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fetcher.MirrorURLs) != 1 || fetcher.MirrorURLs[0] != "http://150.40.105.19:35399/api/iphone/" {
		t.Fatalf("mirrors=%v", fetcher.MirrorURLs)
	}
}

func TestRefreshMirrorsFailurePreservesPreviousAddresses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>no mirrors</html>"))
	}))
	defer server.Close()
	fetcher := &Fetcher{MirrorListURL: server.URL, MirrorURLs: []string{"http://198.51.100.1:8080/api/iphone/"}, Client: server.Client()}
	if err := fetcher.RefreshMirrors(context.Background()); err == nil {
		t.Fatal("discovery failure accepted")
	}
	if len(fetcher.MirrorURLs) != 1 || fetcher.MirrorURLs[0] != "http://198.51.100.1:8080/api/iphone/" {
		t.Fatal("previous addresses lost")
	}
}

func TestCatalogRedirectBlocksMirrorSSRFAndHTTPSDowngrade(t *testing.T) {
	origin, _ := http.NewRequest(http.MethodGet, DefaultMirrorListURL, nil)
	for _, address := range []string{"http://www.vpngate.net/en/sites.aspx", "https://127.0.0.1/en/", "https://user:pass@www.vpngate.net/en/"} {
		request, _ := http.NewRequest(http.MethodGet, address, nil)
		if err := catalogRedirect(request, []*http.Request{origin}); err == nil {
			t.Fatalf("unsafe redirect accepted: %s", address)
		}
	}
	request, _ := http.NewRequest(http.MethodGet, "https://www.vpngate.net/en/", nil)
	if err := catalogRedirect(request, []*http.Request{origin}); err != nil {
		t.Fatal(err)
	}
}

func TestFetcherFallsBackWhenPrimaryCandidatesAreUnreachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := "primary"
		if r.URL.Path == "/mirror" {
			host = "mirror"
		}
		_, _ = w.Write([]byte(catalogCSV(host, "198.51.100.1", "udp", 1194)))
	}))
	defer server.Close()
	fetcher := &Fetcher{URL: server.URL, MirrorURLs: []string{server.URL + "/mirror"}, Client: server.Client(), Probe: func(_ context.Context, c model.VPNGateCandidate) error {
		if c.HostName == "primary" {
			return errors.New("unreachable")
		}
		return nil
	}}
	got, err := fetcher.Fetch(context.Background())
	if err != nil || len(got) != 1 || got[0].HostName != "mirror" {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestProbeOpenVPNTCP(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		request := make([]byte, 16)
		if _, err := io.ReadFull(conn, request); err != nil {
			return
		}
		response := resetResponse(request[3:11])
		_, _ = conn.Write(append([]byte{0, byte(len(response))}, response...))
	}()
	conn, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := probeOpenVPN(ctx, conn, true); err != nil {
		t.Fatal(err)
	}
}

func TestLiveOfficialCatalog(t *testing.T) {
	if os.Getenv("VPNGATE_LIVE_TEST") == "" {
		t.Skip("VPNGATE_LIVE_TEST is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	fetcher := NewFetcher()
	if err := fetcher.RefreshMirrors(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("discovered mirrors: %d", len(fetcher.MirrorURLs))
	candidates, err := fetcher.Fetch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) == 0 {
		t.Fatal("official VPNGate catalog returned no usable candidates")
	}
	t.Logf("responsive candidates: %d", len(candidates))
	for _, candidate := range candidates {
		if candidate.HostName == "" || candidate.IP == "" || candidate.CountryShort == "" ||
			candidate.OpenVPNConfig == "" {
			t.Fatalf("incomplete live candidate: host=%q ip=%q", candidate.HostName, candidate.IP)
		}
	}
}

func TestFetcherFallsBackToMirrorWhenPrimaryIsNotCSV(t *testing.T) {
	config := base64.StdEncoding.EncodeToString([]byte("client\ndev tun\nproto udp\nremote old.example 1194\n"))
	csvBody := "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n" +
		"mirror,198.51.100.10,20,50,2000,Japan,JP,2,2000,0,0,2weeks,op,msg," + config + "\n"
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>blocked</html>"))
	}))
	defer primary.Close()
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept-Encoding"); got != "identity" {
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(csvBody))
	}))
	defer mirror.Close()

	fetcher := &Fetcher{
		URL:        primary.URL,
		MirrorURLs: []string{mirror.URL},
		Client:     primary.Client(),
	}
	candidates, err := fetcher.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].HostName != "mirror" {
		t.Fatalf("fallback candidates = %#v", candidates)
	}
}
func TestParseCSVAndRank(t *testing.T) {
	config := base64.StdEncoding.EncodeToString([]byte("client\ndev tun\nproto udp\nremote old.example 1194\n"))
	input := "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n" +
		"slow,198.51.100.1,10,100,1000,Japan,JP,4,1000,0,0,2weeks,op,msg," + config + "\n" +
		"fast,198.51.100.2,20,50,2000,Japan,JP,2,2000,0,0,2weeks,op,msg," + config + "\n" +
		"bad,not-an-ip,99,1,9999,Japan,JP,1,1,0,0,x,x,x," + config + "\n*\n"
	candidates, err := ParseCSV(strings.NewReader(input), time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 || candidates[0].HostName != "slow" {
		t.Fatalf("parsed candidates = %#v", candidates)
	}
	ranked := FilterAndRank(candidates, Filter{Country: "jp"}, map[string]bool{"slow": true})
	if len(ranked) != 1 || ranked[0].HostName != "fast" {
		t.Fatalf("ranked candidates = %#v", ranked)
	}
}

func TestFilterAndRankPrefersScoreThenSpeed(t *testing.T) {
	candidates := []model.VPNGateCandidate{
		{HostName: "a", Score: 10, Speed: 100, Ping: 10},
		{HostName: "b", Score: 20, Speed: 10, Ping: 100},
		{HostName: "c", Score: 20, Speed: 20, Ping: 200},
	}
	ranked := FilterAndRank(candidates, Filter{}, nil)
	if ranked[0].HostName != "c" || ranked[1].HostName != "b" {
		t.Fatalf("rank order = %#v", ranked)
	}
}
