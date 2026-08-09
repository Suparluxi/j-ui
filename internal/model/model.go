package model

import "time"

type Node struct {
	ID                 int64          `json:"id"`
	Name               string         `json:"name"`
	Protocol           string         `json:"protocol"`
	Listen             string         `json:"listen"`
	Port               int            `json:"port"`
	Enabled            bool           `json:"enabled"`
	PublicHostOverride string         `json:"publicHostOverride,omitempty"`
	ExternalAddress    string         `json:"externalAddress"`
	Transport          string         `json:"transport"`
	CurrentOutbound    string         `json:"currentOutbound"`
	OutboundID         *int64         `json:"outboundId,omitempty"`
	ListenerStatus     string         `json:"listenerStatus"`
	PublicConnectivity string         `json:"publicConnectivity"`
	Settings           map[string]any `json:"settings"`
	Secret             map[string]any `json:"-"`
	Status             string         `json:"status"`
	CreatedAt          time.Time      `json:"createdAt"`
	UpdatedAt          time.Time      `json:"updatedAt"`
}

type Outbound struct {
	ID            int64      `json:"id"`
	Name          string     `json:"name"`
	Type          string     `json:"type"`
	Server        string     `json:"server"`
	Port          int        `json:"port"`
	Enabled       bool       `json:"enabled"`
	Username      string     `json:"-"`
	Password      string     `json:"-"`
	HasCredential bool       `json:"hasCredential"`
	ManagedKind   string     `json:"managedKind"`
	Status        string     `json:"status"`
	ObservedIP    string     `json:"observedIp,omitempty"`
	Country       string     `json:"country,omitempty"`
	ASN           string     `json:"asn,omitempty"`
	LastError     string     `json:"lastError,omitempty"`
	LastCheckedAt *time.Time `json:"lastCheckedAt,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
}

type VPNGateCandidate struct {
	HostName      string    `json:"hostName"`
	IP            string    `json:"ip"`
	Score         int64     `json:"score"`
	Ping          int       `json:"ping"`
	Speed         int64     `json:"speed"`
	CountryLong   string    `json:"countryLong"`
	CountryShort  string    `json:"countryShort"`
	NumSessions   int       `json:"numVpnSessions"`
	Uptime        int64     `json:"uptime"`
	OpenVPNConfig string    `json:"-"`
	HasOpenVPN    bool      `json:"hasOpenVpn"`
	FetchedAt     time.Time `json:"fetchedAt"`
}

type VPNGateExit struct {
	ID                int64      `json:"id"`
	OutboundID        int64      `json:"outboundId"`
	Slot              int        `json:"slot"`
	Name              string     `json:"name"`
	Country           string     `json:"country"`
	CandidateHostName string     `json:"candidateHostName,omitempty"`
	CandidateIP       string     `json:"candidateIp,omitempty"`
	RemoteProtocol    string     `json:"-"`
	RemotePort        int        `json:"-"`
	Namespace         string     `json:"namespace"`
	LocalAddress      string     `json:"localAddress"`
	LocalPort         int        `json:"localPort"`
	Status            string     `json:"status"`
	ObservedIP        string     `json:"observedIp,omitempty"`
	LastError         string     `json:"lastError,omitempty"`
	FailurePolicy     string     `json:"failurePolicy"`
	Permanent         bool       `json:"permanent"`
	ExpiresAt         *time.Time `json:"expiresAt,omitempty"`
	LastCheckedAt     *time.Time `json:"lastCheckedAt,omitempty"`
	CreatedAt         time.Time  `json:"createdAt"`
	UpdatedAt         time.Time  `json:"updatedAt"`
}

const (
	OutboundSOCKS5 = "socks5"
	OutboundHTTP   = "http"
)

func SupportedOutbound(outboundType string) bool {
	return outboundType == OutboundSOCKS5 || outboundType == OutboundHTTP
}

type Client struct {
	ID         int64          `json:"id"`
	NodeID     int64          `json:"nodeId"`
	UserID     int64          `json:"userId"`
	Name       string         `json:"name"`
	Enabled    bool           `json:"enabled"`
	Credential map[string]any `json:"-"`
	CreatedAt  time.Time      `json:"createdAt"`
}

type Session struct {
	TokenHash string
	CSRFToken string
	ExpiresAt time.Time
}

type User struct {
	ID                    int64
	Name                  string
	SubscriptionTokenHash string
	SubscriptionTokenEnc  string
}

type SystemEvent struct {
	ID        int64     `json:"id"`
	Level     string    `json:"level"`
	Code      string    `json:"code"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"createdAt"`
}

const (
	ProtocolVLESSReality     = "vless_reality"
	ProtocolVLESSH2Reality   = "vless_h2_reality"
	ProtocolVLESSGRPCReality = "vless_grpc_reality"
	ProtocolVLESSWSTLS       = "vless_ws_tls"
	ProtocolVLESSArgo        = "vless_argo"
	ProtocolTrojanTLS        = "trojan_tls"
	ProtocolHysteria2        = "hysteria2"
	ProtocolTUIC             = "tuic"
	ProtocolAnyTLS           = "anytls"
	ProtocolAnyTLSReality    = "anytls_reality"
	ProtocolSOCKS5           = "socks5"
)

func SupportedProtocol(protocol string) bool {
	switch protocol {
	case ProtocolVLESSReality, ProtocolVLESSGRPCReality,
		ProtocolVLESSWSTLS, ProtocolVLESSArgo, ProtocolTrojanTLS, ProtocolHysteria2,
		ProtocolTUIC, ProtocolAnyTLS, ProtocolAnyTLSReality:
		return true
	default:
		return false
	}
}

// CloudflareHTTPSPort reports whether Cloudflare's HTTP proxy accepts HTTPS
// traffic on port. VLESS-WS uses this restricted set so a proxied DNS record
// never receives a sequential but unreachable listener port.
func CloudflareHTTPSPort(port int) bool {
	switch port {
	case 443, 2053, 2083, 2087, 2096, 8443:
		return true
	default:
		return false
	}
}

func CloudflareHTTPSPorts() []int {
	return []int{8443, 2053, 2083, 2087, 2096, 443}
}
