package singbox

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Suparluxi/j-ui/internal/model"
)

func TestGeneratedConfigWithSingBox(t *testing.T) {
	binary := os.Getenv("SINGBOX_TEST_BINARY")
	if binary == "" {
		t.Skip("SINGBOX_TEST_BINARY is not set")
	}
	root := t.TempDir()
	certificatePath, keyPath := testCertificate(t, root)
	realityKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	protocols := []string{
		model.ProtocolVLESSReality, model.ProtocolVLESSH2Reality,
		model.ProtocolVLESSGRPCReality, model.ProtocolVLESSWSTLS,
		model.ProtocolTrojanTLS, model.ProtocolHysteria2,
		model.ProtocolTUIC, model.ProtocolAnyTLS, model.ProtocolAnyTLSReality,
		model.ProtocolNaive, model.ProtocolSOCKS5, model.ProtocolVLESSArgo,
	}
	var items []NodeWithClients
	for index, protocol := range protocols {
		items = append(items, NodeWithClients{
			Node: model.Node{
				ID: int64(index + 1), Protocol: protocol, Listen: "127.0.0.1",
				Port: 20000 + index, Enabled: true,
				Settings: map[string]any{
					"server_name": "example.com", "handshake_server": "example.com",
					"handshake_port": 443, "short_id": "0123456789abcdef",
					"certificate_path": certificatePath, "key_path": keyPath, "ws_path": "/ws",
					"transport_path": "/h2", "service_name": "jui-grpc",
				},
				Secret: map[string]any{
					"private_key": base64.RawURLEncoding.EncodeToString(realityKey.Bytes()),
				},
			},
			Clients: []model.Client{{
				Name: "default", Enabled: true,
				Credential: map[string]any{
					"uuid":     "00000000-0000-4000-8000-000000000000",
					"password": "strong-password", "username": "user",
					"flow": "xtls-rprx-vision",
				},
			}},
		})
	}
	outboundID := int64(99)
	httpOutboundID := int64(100)
	items[0].Node.OutboundID = &outboundID
	items[1].Node.OutboundID = &httpOutboundID
	config, err := GenerateWithOutbounds(items, []model.Outbound{{
		ID: 99, Type: model.OutboundSOCKS5, Server: "127.0.0.1", Port: 10080,
		Enabled: true, Username: "proxy-user", Password: "proxy-password",
	}, {
		ID: 100, Type: model.OutboundHTTP, Server: "127.0.0.1", Port: 18080,
		Enabled: true, Username: "http-user", Password: "http-password",
	}})
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "sing-box.json")
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(context.Background(), binary, "check", "-c", configPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("sing-box check failed: %v\n%s\nConfig:\n%s", err, output, config)
	}
}

func TestGeneratedSOCKS5StartsFixedTCPListener(t *testing.T) {
	binary := os.Getenv("SINGBOX_TEST_BINARY")
	if binary == "" {
		t.Skip("SINGBOX_TEST_BINARY is not set")
	}
	port := freeTCPUDPPort(t)
	fixture := goldenFixture(model.ProtocolSOCKS5, 0)
	fixture.Node.Port = port
	config, err := Generate([]NodeWithClients{fixture})
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "sing-box.json")
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	command := exec.Command(binary, "run", "-c", configPath)
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	running := true
	defer func() {
		if running {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		connection, dialErr := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = command.Process.Kill()
	_ = command.Wait()
	running = false
	t.Fatalf("generated SOCKS5 config did not listen on TCP %s\n%s", address, output.String())
}

func TestBoundOutboundFailureNeverFallsBackToDirect(t *testing.T) {
	binary := os.Getenv("SINGBOX_TEST_BINARY")
	if binary == "" {
		t.Skip("SINGBOX_TEST_BINARY is not set")
	}
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	var directConnections atomic.Int32
	go func() {
		for {
			connection, err := target.Accept()
			if err != nil {
				return
			}
			directConnections.Add(1)
			connection.Close()
		}
	}()
	failingProxy, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer failingProxy.Close()
	go func() {
		for {
			connection, err := failingProxy.Accept()
			if err != nil {
				return
			}
			connection.Close()
		}
	}()
	inboundPort := freeTCPUDPPort(t)
	outboundID := int64(1)
	fixture := goldenFixture(model.ProtocolSOCKS5, 0)
	fixture.Node.Port = inboundPort
	fixture.Node.OutboundID = &outboundID
	config, err := GenerateWithOutbounds([]NodeWithClients{fixture}, []model.Outbound{{
		ID: 1, Type: model.OutboundSOCKS5, Server: "127.0.0.1",
		Port: failingProxy.Addr().(*net.TCPAddr).Port, Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "sing-box.json")
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	command := exec.Command(binary, "run", "-c", configPath)
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	}()
	inboundAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(inboundPort))
	var client net.Conn
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		client, err = net.DialTimeout("tcp", inboundAddress, 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if client == nil {
		t.Fatalf("sing-box inbound did not start:\n%s", output.String())
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil || reply[1] != 2 {
		t.Fatalf("inbound method reply = %v err=%v\n%s", reply, err, output.String())
	}
	username, password := "fixed-user", "fixed-password"
	auth := []byte{1, byte(len(username))}
	auth = append(auth, username...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, password...)
	if _, err := client.Write(auth); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, reply); err != nil || reply[1] != 0 {
		t.Fatalf("inbound auth reply = %v err=%v", reply, err)
	}
	targetPort := target.Addr().(*net.TCPAddr).Port
	request := []byte{5, 1, 0, 1, 127, 0, 0, 1, byte(targetPort >> 8), byte(targetPort)}
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	connectReply := make([]byte, 2)
	_, readErr := io.ReadFull(client, connectReply)
	if readErr == nil && connectReply[1] == 0 {
		t.Fatal("bound connection unexpectedly succeeded after upstream proxy failure")
	}
	time.Sleep(200 * time.Millisecond)
	if directConnections.Load() != 0 {
		t.Fatalf("target received %d direct fallback connections", directConnections.Load())
	}
}

func freeTCPUDPPort(t *testing.T) int {
	t.Helper()
	for attempt := 0; attempt < 20; attempt++ {
		tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := tcpListener.Addr().(*net.TCPAddr).Port
		udpListener, err := net.ListenUDP("udp4", &net.UDPAddr{
			IP: net.ParseIP("127.0.0.1"), Port: port,
		})
		if err == nil {
			udpListener.Close()
			tcpListener.Close()
			return port
		}
		tcpListener.Close()
	}
	t.Fatal("unable to reserve a free TCP/UDP port")
	return 0
}

func testCertificate(t *testing.T, root string) (string, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath, keyPath := filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem")
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certificatePath, keyPath
}
