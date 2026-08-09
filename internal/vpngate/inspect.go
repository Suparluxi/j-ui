package vpngate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Suparluxi/j-ui/internal/model"
)

// IPInspection keeps VPNGate's reported values separate from the external IP
// lookup. Neither set of fields is a guarantee that a target website will
// accept the address for registration.
type IPInspection struct {
	CandidateHostName string        `json:"candidateHostName"`
	CandidateIP       string        `json:"candidateIp"`
	VPNGate           VPNGateReport `json:"vpngate"`
	Lookup            IPLookup      `json:"lookup"`
	Provider          string        `json:"provider"`
	CheckedAt         time.Time     `json:"checkedAt"`
}

type VPNGateReport struct {
	Score              int64     `json:"score"`
	Ping               int       `json:"pingMs"`
	SpeedBitsPerSecond int64     `json:"speedBitsPerSecond"`
	NumSessions        int       `json:"numVpnSessions"`
	Uptime             int64     `json:"uptimeSeconds"`
	FetchedAt          time.Time `json:"fetchedAt"`
}

type IPConnection struct {
	ASN         string `json:"asn,omitempty"`
	ASName      string `json:"asName,omitempty"`
	Org         string `json:"org,omitempty"`
	ISP         string `json:"isp,omitempty"`
	CompanyName string `json:"companyName,omitempty"`
}

type IPRange struct {
	First string `json:"first,omitempty"`
	Last  string `json:"last,omitempty"`
	Count int64  `json:"count,omitempty"`
}

type IPThreat struct {
	Label    string `json:"label"`
	Severity string `json:"severity,omitempty"`
}

type IPIntelligence struct {
	Threats        []IPThreat `json:"threats,omitempty"`
	AbuserLevel    string     `json:"abuserLevel,omitempty"`
	AbuserScoreRaw string     `json:"abuserScoreRaw,omitempty"`
	HTTPBLThreat   *float64   `json:"httpblThreat,omitempty"`
}

type IPLookup struct {
	IP                    string         `json:"ip"`
	Country               string         `json:"country,omitempty"`
	CountryCode           string         `json:"countryCode,omitempty"`
	Region                string         `json:"region,omitempty"`
	City                  string         `json:"city,omitempty"`
	RegisteredCountry     string         `json:"registeredCountry,omitempty"`
	RegisteredCountryCode string         `json:"registeredCountryCode,omitempty"`
	TrustScore            int            `json:"trustScore,omitempty"`
	IsResidential         bool           `json:"isResidential"`
	IsDatacenter          bool           `json:"isDatacenter"`
	IsPublicService       bool           `json:"isPublicService"`
	IsMobile              bool           `json:"isMobile"`
	IsVPN                 bool           `json:"isVpn"`
	IsProxy               bool           `json:"isProxy"`
	IsTor                 bool           `json:"isTor"`
	IsAbuser              bool           `json:"isAbuser"`
	IsCrawler             bool           `json:"isCrawler"`
	CompanyType           string         `json:"companyType,omitempty"`
	ASNKind               string         `json:"asnKind,omitempty"`
	CIDR                  string         `json:"cidr,omitempty"`
	Range                 IPRange        `json:"range"`
	ASNIPv4Count          int64          `json:"asnIpv4Count,omitempty"`
	EstimatedBandwidth    string         `json:"estimatedBandwidth,omitempty"`
	ASNAllocated          string         `json:"asnAllocated,omitempty"`
	RPKIStatus            string         `json:"rpkiStatus,omitempty"`
	Intelligence          IPIntelligence `json:"intelligence"`
	Connection            IPConnection   `json:"connection"`
}

type IPInspector struct {
	Endpoint string
	Client   *http.Client
	Timeout  time.Duration
}

func NewIPInspector() *IPInspector {
	return &IPInspector{
		Endpoint: "https://ip.net.coffee/api/ip/lookup",
		Client:   &http.Client{Timeout: 10 * time.Second},
		Timeout:  10 * time.Second,
	}
}

func inspectionForCandidate(candidate model.VPNGateCandidate) IPInspection {
	return IPInspection{
		CandidateHostName: candidate.HostName,
		CandidateIP:       candidate.IP,
		VPNGate: VPNGateReport{
			Score: candidate.Score, Ping: candidate.Ping, SpeedBitsPerSecond: candidate.Speed,
			NumSessions: candidate.NumSessions, Uptime: candidate.Uptime, FetchedAt: candidate.FetchedAt,
		},
	}
}

// MockInspection is used only by the local mock-engine demo so the UI can be
// exercised without making an external lookup request.
func MockInspection(candidate model.VPNGateCandidate) IPInspection {
	inspection := inspectionForCandidate(candidate)
	inspection.Lookup = IPLookup{
		IP: candidate.IP, Country: candidate.CountryLong, CountryCode: candidate.CountryShort,
		TrustScore: 90, IsResidential: true, CompanyType: "isp", ASNKind: "residential",
		Connection: IPConnection{ASN: "AS64500", ASName: "DEMO-NET", ISP: "演示 ISP", Org: "演示组织", CompanyName: "演示组织"},
	}
	inspection.Provider = "本地模拟数据（生产环境使用 ip.net.coffee）"
	inspection.CheckedAt = time.Now().UTC()
	return inspection
}

func (i *IPInspector) Inspect(ctx context.Context, candidate model.VPNGateCandidate) (IPInspection, error) {
	if net.ParseIP(candidate.IP) == nil || !isPublicIP(candidate.IP) {
		return IPInspection{}, errors.New("VPNGate 候选 IP 不是有效的公网地址")
	}
	endpoint := strings.TrimRight(strings.TrimSpace(i.Endpoint), "/")
	if endpoint == "" {
		return IPInspection{}, errors.New("IP 检测服务地址未配置")
	}
	timeout := i.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	requestURL := endpoint + "/" + url.PathEscape(candidate.IP)
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, requestURL, nil)
	if err != nil {
		return IPInspection{}, err
	}
	request.Header.Set("User-Agent", "J-UI/0.2 (+https://github.com/Suparluxi/j-ui)")
	client := i.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	response, err := client.Do(request)
	if err != nil {
		return IPInspection{}, fmt.Errorf("请求 IP 信息服务失败: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return IPInspection{}, fmt.Errorf("IP 信息服务返回 HTTP %d", response.StatusCode)
	}
	var payload netCoffeeResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return IPInspection{}, fmt.Errorf("解析 IP 信息失败: %w", err)
	}
	if strings.TrimSpace(payload.IP) == "" {
		return IPInspection{}, errors.New("IP 信息服务未返回有效结果")
	}
	lookup := IPLookup{
		IP: payload.IP, Country: payload.Country, CountryCode: strings.ToUpper(payload.CountryCode),
		Region: payload.Region, City: payload.City,
		RegisteredCountry: payload.RegisteredCountry, RegisteredCountryCode: strings.ToUpper(payload.RegisteredCountryCode),
		TrustScore: payload.TrustScore, IsResidential: payload.IsResidential,
		IsDatacenter: payload.IsDatacenter, IsPublicService: payload.IsPublicService,
		IsMobile: payload.IsMobile, IsVPN: payload.IsVPN, IsProxy: payload.IsProxy,
		IsTor: payload.IsTor, IsAbuser: payload.IsAbuser, IsCrawler: payload.IsCrawler,
		CompanyType: payload.CompanyType, ASNKind: payload.ASNKind, CIDR: payload.CIDR,
		Range:        IPRange{First: payload.Range.First, Last: payload.Range.Last, Count: payload.Range.Count},
		ASNIPv4Count: payload.ASNIPv4Count, EstimatedBandwidth: payload.ASNTBPS,
		ASNAllocated: payload.ASNAllocated, RPKIStatus: payload.RPKIStatus,
		Intelligence: IPIntelligence{
			Threats: payload.Intelligence.Threats, AbuserLevel: payload.Intelligence.AbuserLevel,
			AbuserScoreRaw: payload.Intelligence.AbuserScoreRaw,
			HTTPBLThreat:   firstThreatValue(payload.Intelligence.RepThreat, payload.Intelligence.HTTPBLThreat),
		},
		Connection: IPConnection{
			ASN: formatASN(payload.ASN), ASName: payload.ASName,
			Org: firstNonEmpty(payload.ASOrganization, payload.CompanyName),
			ISP: payload.ISP, CompanyName: payload.CompanyName,
		},
	}
	if lookup.IP == "" {
		lookup.IP = candidate.IP
	}
	return IPInspection{
		CandidateHostName: candidate.HostName,
		CandidateIP:       candidate.IP,
		VPNGate: VPNGateReport{
			Score: candidate.Score, Ping: candidate.Ping, SpeedBitsPerSecond: candidate.Speed,
			NumSessions: candidate.NumSessions, Uptime: candidate.Uptime,
			FetchedAt: candidate.FetchedAt,
		},
		Lookup: lookup, Provider: "ip.net.coffee", CheckedAt: time.Now().UTC(),
	}, nil
}

type netCoffeeResponse struct {
	IP                    string `json:"ip"`
	Country               string `json:"country"`
	CountryCode           string `json:"countryCode"`
	Region                string `json:"region"`
	City                  string `json:"city"`
	RegisteredCountry     string `json:"registered_country"`
	RegisteredCountryCode string `json:"registered_country_code"`
	TrustScore            int    `json:"trust_score"`
	ASN                   int64  `json:"asn"`
	ASName                string `json:"asname"`
	ASOrganization        string `json:"asOrganization"`
	CompanyName           string `json:"company_name"`
	ISP                   string `json:"isp"`
	ASNKind               string `json:"asn_kind"`
	CompanyType           string `json:"company_type"`
	IsResidential         bool   `json:"isResidential"`
	IsDatacenter          bool   `json:"is_datacenter"`
	IsPublicService       bool   `json:"is_public_service"`
	IsMobile              bool   `json:"is_mobile"`
	IsVPN                 bool   `json:"is_vpn"`
	IsProxy               bool   `json:"is_proxy"`
	IsTor                 bool   `json:"is_tor"`
	IsAbuser              bool   `json:"is_abuser"`
	IsCrawler             bool   `json:"is_crawler"`
	CIDR                  string `json:"cidr"`
	Range                 struct {
		First string `json:"first"`
		Last  string `json:"last"`
		Count int64  `json:"count"`
	} `json:"range"`
	ASNIPv4Count int64  `json:"asn_ipv4_count"`
	ASNTBPS      string `json:"asn_tbps"`
	ASNAllocated string `json:"asn_allocated"`
	RPKIStatus   string `json:"rpki_status"`
	Intelligence struct {
		Threats        []IPThreat `json:"threats"`
		AbuserLevel    string     `json:"abuser_level"`
		AbuserScoreRaw string     `json:"abuser_score_raw"`
		RepThreat      *float64   `json:"rep_threat"`
		HTTPBLThreat   *float64   `json:"httpbl_threat"`
	} `json:"intelligence"`
}

func firstThreatValue(values ...*float64) *float64 {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func formatASN(asn int64) string {
	if asn <= 0 {
		return ""
	}
	return "AS" + strconv.FormatInt(asn, 10)
}

func isPublicIP(value string) bool {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	return true
}
