package node

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Suparluxi/j-ui/internal/model"
)

func TestSOCKS5OnlyRequiresFixedTCPListener(t *testing.T) {
	connection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	port := connection.LocalAddr().(*net.UDPAddr).Port
	if err := checkPort(model.ProtocolSOCKS5, "127.0.0.1", port); err != nil {
		t.Fatalf("SOCKS5 rejected UDP-only occupied port: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port = listener.Addr().(*net.TCPAddr).Port
	if err := checkPort(model.ProtocolSOCKS5, "127.0.0.1", port); err == nil {
		t.Fatal("SOCKS5 accepted a port already occupied by TCP")
	}
}

func TestSOCKS5InboundIsNoLongerAccepted(t *testing.T) {
	err := validateInput(model.ProtocolSOCKS5, "127.0.0.1", 1080, map[string]any{}, false)
	if err == nil || err.Error() != "unsupported protocol" {
		t.Fatalf("SOCKS5 inbound rejection = %v", err)
	}
}

func TestOutboundEndpointAcceptsAddressWithPort(t *testing.T) {
	outbound, err := validateOutboundInput(OutboundInput{
		Name: "residential", Type: "socks5", Server: "103.11.122.244:443",
		Port: 1080, Enabled: true, CredentialMode: "replace",
	})
	if err != nil {
		t.Fatal(err)
	}
	if outbound.Server != "103.11.122.244" || outbound.Port != 443 {
		t.Fatalf("normalized outbound = %s:%d", outbound.Server, outbound.Port)
	}
	if _, err := validateOutboundInput(OutboundInput{
		Name: "invalid", Type: "socks5", Server: "103.11.122.244:bad", Port: 1080,
	}); err == nil || strings.Contains(err.Error(), "public host override") {
		t.Fatalf("invalid proxy address error = %v", err)
	}
}

func TestCertificateValidationChecksKeyAndPermissions(t *testing.T) {
	root := t.TempDir()
	certificatePath, keyPath := writeCertificatePair(t, root, "node.example.com")
	settings := map[string]any{
		"server_name": "node.example.com", "certificate_path": certificatePath, "key_path": keyPath,
	}
	if err := validateCertificateSettings(settings); err != nil {
		t.Fatalf("valid pair rejected: %v", err)
	}
	if err := os.Chmod(certificatePath, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := validateCertificateSettings(settings); err == nil {
		t.Fatal("group/world-writable certificate was accepted")
	}
	if err := os.Chmod(certificatePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateCertificateSettings(settings); err == nil {
		t.Fatal("group-readable private key was accepted")
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	_, otherKeyPath := writeCertificatePair(t, root, "other.example.com")
	settings["key_path"] = otherKeyPath
	if err := validateCertificateSettings(settings); err == nil {
		t.Fatal("mismatched private key was accepted")
	}
}

func TestAutomaticCertificateGeneratesAndReusesDemoPair(t *testing.T) {
	service := NewService(nil, nil, nil)
	service.ConfigureAutomaticCertificates(t.TempDir(), true)
	settings := map[string]any{"server_name": "[::1]", "certificate_mode": "auto"}
	if err := service.prepareAutomaticCertificate(model.ProtocolHysteria2, settings); err != nil {
		t.Fatalf("generate automatic demo certificate: %v", err)
	}
	if err := validateCertificateSettings(settings); err != nil {
		t.Fatalf("generated certificate rejected: %v", err)
	}
	if mapString(settings, "server_name") != "::1" {
		t.Fatalf("normalized server_name = %q, want ::1", mapString(settings, "server_name"))
	}
	certificatePath := mapString(settings, "certificate_path")
	keyPath := mapString(settings, "key_path")
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("private key permissions = %o, want 600", keyInfo.Mode().Perm())
	}

	second := map[string]any{"server_name": "[::1]", "certificate_mode": "auto"}
	if err := service.prepareAutomaticCertificate(model.ProtocolTUIC, second); err != nil {
		t.Fatalf("reuse automatic demo certificate: %v", err)
	}
	if mapString(second, "certificate_path") != certificatePath || mapString(second, "key_path") != keyPath {
		t.Fatal("automatic certificate pair was not reused for the same domain")
	}
}

func TestAutomaticCertificateDoesNotGenerateOutsideDemoMode(t *testing.T) {
	service := NewService(nil, nil, nil)
	service.ConfigureAutomaticCertificates(t.TempDir(), false)
	settings := map[string]any{"server_name": "missing.example.com", "certificate_mode": "auto"}
	if err := service.prepareAutomaticCertificate(model.ProtocolTUIC, settings); err == nil {
		t.Fatal("production mode generated a self-signed certificate")
	}
	if mapString(settings, "certificate_path") != "" || mapString(settings, "key_path") != "" {
		t.Fatal("production failure populated nonexistent certificate paths")
	}
}

func writeCertificatePair(t *testing.T, root, name string) (string, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	suffix := time.Now().Format("150405.000000000")
	certificatePath := filepath.Join(root, name+"-"+suffix+".crt")
	keyPath := filepath.Join(root, name+"-"+suffix+".key")
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certificatePath, keyPath
}

func TestHostOverrideValidation(t *testing.T) {
	valid, err := validateHostOverride("[2001:db8::1]")
	if err != nil || valid != "2001:db8::1" {
		t.Fatalf("IPv6 validation = %q, %v", valid, err)
	}
	if _, err := validateHostOverride("bad$name.example"); err == nil {
		t.Fatal("invalid hostname was accepted")
	}
}

func TestRealityEndpointAndWebSocketPathValidation(t *testing.T) {
	for _, invalid := range []map[string]any{
		{"handshake_server": "example.com:443"},
		{"handshake_server": "example.com/path"},
		{"server_name": "https://example.com"},
		{"handshake_port": 443.5},
		{"handshake_port": "443"},
	} {
		if err := validateInput(model.ProtocolVLESSReality, "127.0.0.1", 443, invalid, false); err == nil {
			t.Fatalf("invalid Reality settings accepted: %#v", invalid)
		}
	}

	root := t.TempDir()
	certificatePath, keyPath := writeCertificatePair(t, root, "node.example.com")
	base := map[string]any{
		"server_name": "node.example.com", "certificate_path": certificatePath, "key_path": keyPath,
	}
	for _, invalidPath := range []string{"", "ws", "/ws?query=1", "/ws#fragment", "/ws\nnext"} {
		settings := cloneMap(base)
		settings["ws_path"] = invalidPath
		if err := validateInput(model.ProtocolVLESSWSTLS, "127.0.0.1", 443, settings, false); err == nil {
			t.Fatalf("invalid ws_path accepted: %q", invalidPath)
		}
	}
	settings := cloneMap(base)
	settings["ws_path"] = "/jui"
	if err := validateInput(model.ProtocolVLESSWSTLS, "127.0.0.1", 443, settings, false); err != nil {
		t.Fatalf("valid ws_path rejected: %v", err)
	}
}

func TestVLESSArgoRequiresLoopbackAndMatchingDomain(t *testing.T) {
	settings := map[string]any{"server_name": "argo.example.com", "ws_path": "/jui-argo"}
	if err := validateInput(model.ProtocolVLESSArgo, "127.0.0.1", 2080, settings, false); err != nil {
		t.Fatalf("valid VLESS Argo rejected: %v", err)
	}
	if err := validateInput(model.ProtocolVLESSArgo, "0.0.0.0", 2080, settings, false); err == nil {
		t.Fatal("public VLESS Argo listener was accepted")
	}
	host, err := protocolHostOverride(model.ProtocolVLESSArgo, "", settings)
	if err != nil || host != "argo.example.com" {
		t.Fatalf("Argo host default = %q, err=%v", host, err)
	}
	if _, err := protocolHostOverride(model.ProtocolVLESSArgo, "other.example.com", settings); err == nil {
		t.Fatal("mismatched Argo external host was accepted")
	}
}

func TestSupportedRealityTransportValidatesAndDeprecatedH2IsRejected(t *testing.T) {
	base := map[string]any{
		"handshake_server": "www.microsoft.com", "handshake_port": 443,
		"server_name": "www.microsoft.com",
	}
	h2 := cloneMap(base)
	h2["transport_path"] = "/jui-h2"
	if err := validateInput(model.ProtocolVLESSH2Reality, "127.0.0.1", 443, h2, false); err == nil {
		t.Fatal("deprecated H2 Reality protocol was accepted")
	}
	grpc := cloneMap(base)
	grpc["service_name"] = "jui-grpc"
	if err := validateInput(model.ProtocolVLESSGRPCReality, "127.0.0.1", 443, grpc, false); err != nil {
		t.Fatalf("valid gRPC Reality rejected: %v", err)
	}
	credential, err := generatedCredential(model.ProtocolVLESSGRPCReality)
	if err != nil || mapString(credential, "uuid") == "" || mapString(credential, "flow") != "" {
		t.Fatalf("unexpected gRPC Reality credential: %#v, err=%v", credential, err)
	}
}

func TestVLESSWSUsesOnlyCloudflareHTTPSPorts(t *testing.T) {
	used := map[int]bool{8443: true, 2053: true}
	port, err := nextProtocolPort(9888, model.ProtocolVLESSWSTLS, used, func(int) bool { return true })
	if err != nil || port != 2083 {
		t.Fatalf("VLESS-WS port = %d, err=%v, want 2083", port, err)
	}
	settings := map[string]any{
		"server_name": "ws.example.com", "certificate_path": "/tmp/cert", "key_path": "/tmp/key", "ws_path": "/jui",
	}
	if err := validateInput(model.ProtocolVLESSWSTLS, "127.0.0.1", 9897, settings, false); err == nil ||
		!strings.Contains(err.Error(), "Cloudflare-supported HTTPS port") {
		t.Fatalf("unsupported VLESS-WS port error = %v", err)
	}
}

func TestRealityGeneratedValuesUseVisaSingaporeByDefault(t *testing.T) {
	_, settings, _, err := generatedValues(model.ProtocolVLESSReality, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if got := mapString(settings, "handshake_server"); got != "www.visa.com.sg" {
		t.Fatalf("handshake_server = %q, want www.visa.com.sg", got)
	}
	if got := mapString(settings, "server_name"); got != "www.visa.com.sg" {
		t.Fatalf("server_name = %q, want www.visa.com.sg", got)
	}
}

func TestAnyTLSAndNaiveCredentials(t *testing.T) {
	for _, protocol := range []string{model.ProtocolAnyTLS, model.ProtocolAnyTLSReality} {
		credential, err := generatedCredential(protocol)
		if err != nil || mapString(credential, "password") == "" {
			t.Fatalf("unexpected %s credential: %#v, err=%v", protocol, credential, err)
		}
	}
	credential, err := generatedCredential(model.ProtocolNaive)
	if err != nil || mapString(credential, "username") == "" || mapString(credential, "password") == "" {
		t.Fatalf("unexpected Naive credential: %#v, err=%v", credential, err)
	}
}

func TestApplyCustomCredential(t *testing.T) {
	generated := map[string]any{
		"uuid": "00000000-0000-4000-8000-000000000000",
		"flow": "xtls-rprx-vision",
	}
	customUUID := "11111111-1111-4111-8111-111111111111"
	credential, err := applyCustomCredential(model.ProtocolVLESSReality, generated, map[string]any{
		"uuid": customUUID,
	})
	if err != nil {
		t.Fatalf("valid custom credential rejected: %v", err)
	}
	if mapString(credential, "uuid") != customUUID || mapString(credential, "flow") != "xtls-rprx-vision" {
		t.Fatalf("custom credential = %#v", credential)
	}
	if _, err := applyCustomCredential(model.ProtocolVLESSReality, generated, map[string]any{
		"uuid": "not-a-uuid",
	}); err == nil {
		t.Fatal("invalid UUID was accepted")
	}
	if _, err := applyCustomCredential(model.ProtocolHysteria2, map[string]any{"password": "generated-password"}, map[string]any{
		"username": "unexpected",
	}); err == nil {
		t.Fatal("unsupported credential field was accepted")
	}
	if _, err := applyCustomCredential(model.ProtocolNaive, map[string]any{
		"username": "generated-user", "password": "generated-password",
	}, map[string]any{"password": "short"}); err == nil {
		t.Fatal("short password was accepted")
	}
}
