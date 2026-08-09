package vpngate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Suparluxi/j-ui/internal/model"
)

func TestIPInspectorKeepsVPNGateReportSeparate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/198.51.100.40" {
			t.Fatalf("lookup path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
	  "ip": "198.51.100.40", "country": "Japan", "countryCode": "JP",
	  "region": "Tokyo", "city": "Tokyo", "registered_country_code": "JP",
	  "trust_score": 98, "asn": 12345, "asname": "EXAMPLE-NET",
	  "asOrganization": "Example Network", "company_name": "Example Inc.", "isp": "Example ISP",
	  "company_type": "isp", "asn_kind": "residential", "isResidential": true,
	  "cidr": "198.51.100.0/24", "range": {"first":"198.51.100.0","last":"198.51.100.255","count":256},
	  "asn_ipv4_count": 1000000, "asn_tbps": "10-20Gbps", "asn_allocated": "2001-01-01",
	  "rpki_status": "valid", "intelligence": {"threats":[],"abuser_level":"safe","rep_threat":0}
	}`))
	}))
	defer server.Close()

	fetchedAt := time.Unix(123, 0).UTC()
	inspection, err := (&IPInspector{
		Endpoint: server.URL, Client: server.Client(), Timeout: time.Second,
	}).Inspect(context.Background(), model.VPNGateCandidate{
		HostName: "candidate", IP: "198.51.100.40", Score: 99, Ping: 20,
		Speed: 10_000_000, NumSessions: 2, FetchedAt: fetchedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if inspection.CandidateHostName != "candidate" || inspection.VPNGate.Score != 99 ||
		inspection.VPNGate.Ping != 20 || inspection.Lookup.CountryCode != "JP" ||
		inspection.VPNGate.SpeedBitsPerSecond != 10_000_000 ||
		inspection.Lookup.Connection.ASN != "AS12345" ||
		inspection.Lookup.Connection.ISP != "Example ISP" ||
		inspection.Lookup.Connection.Org != "Example Network" ||
		inspection.Lookup.Connection.ASName != "EXAMPLE-NET" ||
		inspection.Lookup.TrustScore != 98 || inspection.Lookup.CIDR != "198.51.100.0/24" ||
		inspection.Lookup.Range.Count != 256 || inspection.Lookup.Intelligence.HTTPBLThreat == nil ||
		inspection.Provider != "ip.net.coffee" {
		t.Fatalf("inspection = %#v", inspection)
	}
	if !inspection.CheckedAt.After(fetchedAt) {
		t.Fatalf("checked timestamp = %s", inspection.CheckedAt)
	}
}

func TestIPInspectorRejectsPrivateCandidate(t *testing.T) {
	_, err := NewIPInspector().Inspect(context.Background(), model.VPNGateCandidate{IP: "10.0.0.1"})
	if err == nil {
		t.Fatal("private candidate was accepted")
	}
}
