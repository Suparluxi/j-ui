package vpngate

import (
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Suparluxi/j-ui/internal/model"
)

func TestLiveOfficialCatalog(t *testing.T) {
	if os.Getenv("VPNGATE_LIVE_TEST") == "" {
		t.Skip("VPNGATE_LIVE_TEST is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	candidates, err := NewFetcher().Fetch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) == 0 {
		t.Fatal("official VPNGate catalog returned no usable candidates")
	}
	for _, candidate := range candidates {
		if candidate.HostName == "" || candidate.IP == "" || candidate.CountryShort == "" ||
			candidate.OpenVPNConfig == "" {
			t.Fatalf("incomplete live candidate: %#v", candidate)
		}
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
