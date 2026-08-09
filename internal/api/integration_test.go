package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Suparluxi/j-ui/internal/api"
	"github.com/Suparluxi/j-ui/internal/application"
	"github.com/Suparluxi/j-ui/internal/auth"
	"github.com/Suparluxi/j-ui/internal/config"
	"github.com/Suparluxi/j-ui/internal/exitcheck"
	"github.com/Suparluxi/j-ui/internal/model"
	nodeservice "github.com/Suparluxi/j-ui/internal/node"
)

func TestLoginUsesReplacedAdministratorCredentials(t *testing.T) {
	root := t.TempDir()
	cfg := config.Config{
		ListenAddress: "127.0.0.1:8080",
		DataDir:       filepath.Join(root, "data"), ConfigDir: filepath.Join(root, "config"),
		DatabasePath:  filepath.Join(root, "data", "j-ui.db"),
		SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"),
		SessionTTL:    time.Hour, MockEngine: true,
	}
	app, err := application.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	password := "0123456789abcdef0123456789abcdef0123"
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Store.ChangeAdministrator(context.Background(), "jui-test01", hash); err != nil {
		t.Fatal(err)
	}
	handler := api.NewHandler(fstest.MapFS{"index.html": {Data: []byte("J-UI")}}, app.Dependencies)
	oldLogin := performJSON(handler, http.MethodPost, "/api/v1/auth/login",
		map[string]any{"username": "admin", "password": app.Credentials.Password}, "", "")
	if oldLogin.Code != http.StatusUnauthorized {
		t.Fatalf("old credentials status = %d, want 401", oldLogin.Code)
	}
	newLogin := performJSON(handler, http.MethodPost, "/api/v1/auth/login",
		map[string]any{"username": "jui-test01", "password": password}, "", "")
	if newLogin.Code != http.StatusOK || !strings.Contains(newLogin.Body.String(), `"username":"jui-test01"`) {
		t.Fatalf("replacement credentials status = %d body=%s", newLogin.Code, newLogin.Body.String())
	}
}

func TestLoginReportsDefaultCredentialsOnlyForAdminAdmin(t *testing.T) {
	root := t.TempDir()
	cfg := config.Config{
		ListenAddress: "127.0.0.1:8080",
		DataDir:       filepath.Join(root, "data"), ConfigDir: filepath.Join(root, "config"),
		DatabasePath:  filepath.Join(root, "data", "j-ui.db"),
		SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"),
		SessionTTL:    time.Hour, MockEngine: true,
	}
	app, err := application.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	hash, err := auth.HashPassword("admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Store.ChangeAdministrator(context.Background(), "admin", hash); err != nil {
		t.Fatal(err)
	}
	handler := api.NewHandler(fstest.MapFS{"index.html": {Data: []byte("J-UI")}}, app.Dependencies)
	login := performJSON(handler, http.MethodPost, "/api/v1/auth/login",
		map[string]any{"username": "admin", "password": "admin"}, "", "")
	if login.Code != http.StatusOK || !bytes.Contains(login.Body.Bytes(), []byte(`"defaultCredentials":true`)) {
		t.Fatalf("default credential login status=%d body=%s", login.Code, login.Body.String())
	}
}

func TestAuthenticatedLifecycleAndTokenReset(t *testing.T) {
	root := t.TempDir()
	cfg := config.Config{
		ListenAddress: "127.0.0.1:8080",
		DataDir:       filepath.Join(root, "data"), ConfigDir: filepath.Join(root, "config"),
		DatabasePath:  filepath.Join(root, "data", "j-ui.db"),
		SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"),
		SessionTTL:    3600000000000, MockEngine: true,
	}
	app, err := application.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	handler := api.NewHandler(fstest.MapFS{"index.html": {Data: []byte("J-UI")}}, app.Dependencies)

	loginBody := map[string]any{"username": "admin", "password": app.Credentials.Password}
	login := performJSON(handler, http.MethodPost, "/api/v1/auth/login", loginBody, "", "")
	if login.Code != http.StatusOK {
		t.Fatalf("login status = %d body=%s", login.Code, login.Body.String())
	}
	var session struct {
		CSRFToken string `json:"csrfToken"`
	}
	if err := json.NewDecoder(login.Body).Decode(&session); err != nil {
		t.Fatal(err)
	}
	cookie := login.Result().Cookies()[0]
	wrongMethod := performJSON(handler, http.MethodGet, "/api/v1/auth/login", nil, "", "")
	assertAPIError(t, wrongMethod, http.StatusMethodNotAllowed, "method_not_allowed")
	unknownAPI := performJSON(handler, http.MethodGet, "/api/v1/does-not-exist", nil, "", "")
	assertAPIError(t, unknownAPI, http.StatusNotFound, "not_found")
	invalidID := performJSON(handler, http.MethodGet, "/api/v1/nodes/not-an-id", nil, cookie.String(), "")
	assertAPIError(t, invalidID, http.StatusBadRequest, "invalid_id")

	rejected := performJSON(handler, http.MethodPut, "/api/v1/settings/public-host",
		map[string]any{"publicHost": "node.example.com"}, cookie.String(), "")
	if rejected.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status = %d", rejected.Code)
	}
	setup := performJSON(handler, http.MethodPut, "/api/v1/settings/public-host",
		map[string]any{"publicHost": "node.example.com"}, cookie.String(), session.CSRFToken)
	if setup.Code != http.StatusOK {
		t.Fatalf("setup status = %d body=%s", setup.Code, setup.Body.String())
	}
	ipv6PublicHost := performJSON(handler, http.MethodPut, "/api/v1/settings/public-host",
		map[string]any{"publicHost": "[2001:db8::1]"}, cookie.String(), session.CSRFToken)
	assertAPIError(t, ipv6PublicHost, http.StatusBadRequest, "invalid_public_host")
	defaultServerName := performJSON(handler, http.MethodGet, "/api/v1/settings/server-name",
		nil, cookie.String(), "")
	if defaultServerName.Code != http.StatusOK ||
		!bytes.Contains(defaultServerName.Body.Bytes(), []byte(`"serverName":"J-UI"`)) {
		t.Fatalf("default server name status = %d body=%s", defaultServerName.Code, defaultServerName.Body.String())
	}
	serverName := performJSON(handler, http.MethodPut, "/api/v1/settings/server-name",
		map[string]any{"serverName": " 云悠JP "}, cookie.String(), session.CSRFToken)
	if serverName.Code != http.StatusOK ||
		!bytes.Contains(serverName.Body.Bytes(), []byte(`"serverName":"云悠JP"`)) {
		t.Fatalf("server name status = %d body=%s", serverName.Code, serverName.Body.String())
	}
	invalidServerName := performJSON(handler, http.MethodPut, "/api/v1/settings/server-name",
		map[string]any{"serverName": "云悠丨JP"}, cookie.String(), session.CSRFToken)
	assertAPIError(t, invalidServerName, http.StatusBadRequest, "validation_failed")
	country := performJSON(handler, http.MethodPut, "/api/v1/settings/country",
		map[string]any{"countryCode": " jp "}, cookie.String(), session.CSRFToken)
	if country.Code != http.StatusOK ||
		!bytes.Contains(country.Body.Bytes(), []byte(`"countryCode":"JP"`)) {
		t.Fatalf("country status = %d body=%s", country.Code, country.Body.String())
	}
	storedCountry := performJSON(handler, http.MethodGet, "/api/v1/settings/country",
		nil, cookie.String(), "")
	if storedCountry.Code != http.StatusOK ||
		!bytes.Contains(storedCountry.Body.Bytes(), []byte(`"countryCode":"JP"`)) {
		t.Fatalf("stored country status = %d body=%s", storedCountry.Code, storedCountry.Body.String())
	}
	invalidCountry := performJSON(handler, http.MethodPut, "/api/v1/settings/country",
		map[string]any{"countryCode": "Japan"}, cookie.String(), session.CSRFToken)
	assertAPIError(t, invalidCountry, http.StatusBadRequest, "validation_failed")
	systemInfo := performJSON(handler, http.MethodGet, "/api/v1/system/info", nil, cookie.String(), "")
	if systemInfo.Code != http.StatusOK ||
		!bytes.Contains(systemInfo.Body.Bytes(), []byte(`"countryCode":"JP"`)) {
		t.Fatalf("system info country status = %d body=%s", systemInfo.Code, systemInfo.Body.String())
	}
	defaultLanguage := performJSON(handler, http.MethodGet, "/api/v1/settings/language", nil, "", "")
	if defaultLanguage.Code != http.StatusOK ||
		!bytes.Contains(defaultLanguage.Body.Bytes(), []byte(`"language":"zh-CN"`)) {
		t.Fatalf("default language status = %d body=%s", defaultLanguage.Code, defaultLanguage.Body.String())
	}
	updatedLanguage := performJSON(handler, http.MethodPut, "/api/v1/settings/language",
		map[string]any{"language": "en"}, cookie.String(), session.CSRFToken)
	if updatedLanguage.Code != http.StatusOK ||
		!bytes.Contains(updatedLanguage.Body.Bytes(), []byte(`"language":"en"`)) {
		t.Fatalf("language status = %d body=%s", updatedLanguage.Code, updatedLanguage.Body.String())
	}
	invalidLanguage := performJSON(handler, http.MethodPut, "/api/v1/settings/language",
		map[string]any{"language": "fr"}, cookie.String(), session.CSRFToken)
	assertAPIError(t, invalidLanguage, http.StatusBadRequest, "validation_failed")
	portSettings := performJSON(handler, http.MethodGet, "/api/v1/settings/node-start-port",
		nil, cookie.String(), "")
	if portSettings.Code != http.StatusOK ||
		!bytes.Contains(portSettings.Body.Bytes(), []byte(`"startPort":8881`)) {
		t.Fatalf("node port settings status = %d body=%s", portSettings.Code, portSettings.Body.String())
	}
	invalidStartPort := performJSON(handler, http.MethodPut, "/api/v1/settings/node-start-port",
		map[string]any{"startPort": 70000}, cookie.String(), session.CSRFToken)
	assertAPIError(t, invalidStartPort, http.StatusBadRequest, "validation_failed")
	defaultPrerequisites := performJSON(handler, http.MethodGet, "/api/v1/settings/protocol-prerequisites",
		nil, cookie.String(), "")
	if defaultPrerequisites.Code != http.StatusOK ||
		!bytes.Contains(defaultPrerequisites.Body.Bytes(), []byte(`"cloudflareTunnelEnabled":false`)) {
		t.Fatalf("default protocol prerequisites status = %d body=%s", defaultPrerequisites.Code, defaultPrerequisites.Body.String())
	}
	if err := app.Store.SetSetting(context.Background(), "protocol_prerequisites",
		`{"httpsIngressEnabled":true,"httpsIngressDomain":"legacy.example.com"}`); err != nil {
		t.Fatal(err)
	}
	verificationErr := errors.New("certificate missing")
	tunnelPort := availablePort(t)
	strictDependencies := app.Dependencies
	strictDependencies.MockMode = false
	strictDependencies.VerifyHTTPSIngress = func(context.Context, string) error { return verificationErr }
	strictDependencies.VerifyCloudflareTunnel = func(_ context.Context, _ string, requestedPort int) (int, error) {
		if requestedPort != 0 && requestedPort != tunnelPort {
			return 0, errors.New("origin port mismatch")
		}
		return tunnelPort, nil
	}
	strictHandler := api.NewHandler(fstest.MapFS{"index.html": {Data: []byte("J-UI")}}, strictDependencies)
	legacyPrerequisites := performJSON(strictHandler, http.MethodGet, "/api/v1/settings/protocol-prerequisites",
		nil, cookie.String(), "")
	if legacyPrerequisites.Code != http.StatusOK ||
		!bytes.Contains(legacyPrerequisites.Body.Bytes(), []byte(`"httpsIngressEnabled":false`)) {
		t.Fatalf("legacy prerequisite was not downgraded: %s", legacyPrerequisites.Body.String())
	}
	blockedArgo := performJSON(strictHandler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "blocked Argo", "protocol": "vless_argo", "listen": "127.0.0.1",
		"port": 2080, "enabled": true, "settings": map[string]any{
			"server_name": "argo.example.com", "ws_path": "/jui-argo",
		},
	}, cookie.String(), session.CSRFToken)
	assertAPIError(t, blockedArgo, http.StatusConflict, "protocol_prerequisite_missing")
	failedHTTPSVerification := performJSON(strictHandler, http.MethodPut, "/api/v1/settings/protocol-prerequisites",
		map[string]any{"target": "https", "action": "verify", "domain": "ws.example.com"},
		cookie.String(), session.CSRFToken)
	assertAPIError(t, failedHTTPSVerification, http.StatusConflict, "prerequisite_check_failed")
	verificationErr = nil
	verifiedHTTPS := performJSON(strictHandler, http.MethodPut, "/api/v1/settings/protocol-prerequisites",
		map[string]any{"target": "https", "action": "verify", "domain": "ws.example.com"},
		cookie.String(), session.CSRFToken)
	if verifiedHTTPS.Code != http.StatusOK ||
		!bytes.Contains(verifiedHTTPS.Body.Bytes(), []byte(`"httpsIngressEnabled":true`)) ||
		bytes.Contains(verifiedHTTPS.Body.Bytes(), []byte(`"httpsIngressSimulated":true`)) {
		t.Fatalf("strict HTTPS verification status = %d body=%s", verifiedHTTPS.Code, verifiedHTTPS.Body.String())
	}
	var occupiedWS net.Listener
	var occupiedWSPort int
	for _, candidate := range model.CloudflareHTTPSPorts() {
		listener, listenErr := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", candidate))
		if listenErr == nil {
			occupiedWS = listener
			occupiedWSPort = candidate
			break
		}
	}
	if occupiedWS == nil {
		t.Fatal("no Cloudflare HTTPS port available for conflict regression test")
	}
	fallbackWS := performJSON(strictHandler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": fmt.Sprintf("fallback WS_%d", occupiedWSPort), "protocol": "vless_ws_tls", "listen": "127.0.0.1",
		"port": occupiedWSPort, "enabled": true, "settings": map[string]any{
			"server_name": "ws.example.com", "certificate_mode": "auto", "ws_path": "/jui",
		},
	}, cookie.String(), session.CSRFToken)
	_ = occupiedWS.Close()
	if fallbackWS.Code != http.StatusCreated {
		t.Fatalf("VLESS-WS conflict fallback status = %d body=%s", fallbackWS.Code, fallbackWS.Body.String())
	}
	var fallbackNode model.Node
	if err := json.NewDecoder(fallbackWS.Body).Decode(&fallbackNode); err != nil {
		t.Fatal(err)
	}
	if fallbackNode.Port == occupiedWSPort || !model.CloudflareHTTPSPort(fallbackNode.Port) ||
		!strings.HasSuffix(fallbackNode.Name, "_"+strconv.Itoa(fallbackNode.Port)) {
		t.Fatalf("VLESS-WS conflict fallback node = %#v", fallbackNode)
	}
	if err := app.Nodes.Delete(context.Background(), fallbackNode.ID); err != nil {
		t.Fatal(err)
	}
	mismatchedHTTPSNode := performJSON(strictHandler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "wrong WS", "protocol": "vless_ws_tls", "listen": "0.0.0.0",
		"port": 8443, "enabled": true, "settings": map[string]any{
			"server_name": "other.example.com", "certificate_mode": "auto", "ws_path": "/jui",
		},
	}, cookie.String(), session.CSRFToken)
	assertAPIError(t, mismatchedHTTPSNode, http.StatusConflict, "protocol_domain_mismatch")
	unsupportedHTTPSPort := performJSON(strictHandler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "unsupported WS port", "protocol": "vless_ws_tls", "listen": "0.0.0.0",
		"port": 9897, "enabled": true, "settings": map[string]any{
			"server_name": "ws.example.com", "certificate_mode": "auto", "ws_path": "/jui",
		},
	}, cookie.String(), session.CSRFToken)
	assertAPIError(t, unsupportedHTTPSPort, http.StatusConflict, "unsupported_websocket_port")
	verificationErr = errors.New("certificate expired")
	expiredHTTPSNode := performJSON(strictHandler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "expired WS", "protocol": "vless_ws_tls", "listen": "0.0.0.0",
		"port": 8443, "enabled": true, "settings": map[string]any{
			"server_name": "ws.example.com", "certificate_mode": "auto", "ws_path": "/jui",
		},
	}, cookie.String(), session.CSRFToken)
	assertAPIError(t, expiredHTTPSNode, http.StatusConflict, "prerequisite_check_failed")
	invalidatedHTTPS := performJSON(strictHandler, http.MethodGet, "/api/v1/settings/protocol-prerequisites",
		nil, cookie.String(), "")
	if invalidatedHTTPS.Code != http.StatusOK ||
		!bytes.Contains(invalidatedHTTPS.Body.Bytes(), []byte(`"httpsIngressEnabled":false`)) {
		t.Fatalf("expired HTTPS prerequisite remained enabled: %s", invalidatedHTTPS.Body.String())
	}
	verificationErr = nil
	verifiedTunnel := performJSON(strictHandler, http.MethodPut, "/api/v1/settings/protocol-prerequisites",
		map[string]any{"target": "cloudflare", "action": "verify", "domain": "argo.example.com", "originPort": tunnelPort},
		cookie.String(), session.CSRFToken)
	if verifiedTunnel.Code != http.StatusOK ||
		!bytes.Contains(verifiedTunnel.Body.Bytes(), []byte(fmt.Sprintf(`"cloudflareTunnelOriginPort":%d`, tunnelPort))) {
		t.Fatalf("strict Tunnel verification status = %d body=%s", verifiedTunnel.Code, verifiedTunnel.Body.String())
	}
	wrongTunnelPort := performJSON(strictHandler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "wrong Tunnel port", "protocol": "vless_argo", "listen": "127.0.0.1",
		"port": tunnelPort + 1, "enabled": true, "settings": map[string]any{
			"server_name": "argo.example.com", "ws_path": "/jui-argo",
		},
	}, cookie.String(), session.CSRFToken)
	assertAPIError(t, wrongTunnelPort, http.StatusConflict, "tunnel_origin_mismatch")
	activeArgo := performJSON(strictHandler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "active Tunnel", "protocol": "vless_argo", "listen": "127.0.0.1",
		"port": tunnelPort, "enabled": true, "clientName": "primary", "settings": map[string]any{
			"server_name": "argo.example.com", "ws_path": "/jui-argo",
		},
	}, cookie.String(), session.CSRFToken)
	if activeArgo.Code != http.StatusCreated {
		t.Fatalf("create strict Argo status = %d body=%s", activeArgo.Code, activeArgo.Body.String())
	}
	var activeArgoNode struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(activeArgo.Body).Decode(&activeArgoNode); err != nil {
		t.Fatal(err)
	}
	changedInUseTunnel := performJSON(strictHandler, http.MethodPut, "/api/v1/settings/protocol-prerequisites",
		map[string]any{"target": "cloudflare", "action": "verify", "domain": "new-argo.example.com"},
		cookie.String(), session.CSRFToken)
	assertAPIError(t, changedInUseTunnel, http.StatusConflict, "prerequisite_in_use")
	argoResidential := performJSON(strictHandler, http.MethodPost, "/api/v1/residential-nodes/manual", map[string]any{
		"nodeId": activeArgoNode.ID, "type": "socks5", "server": "198.51.100.10",
		"port": 1080, "durationMinutes": 30,
	}, cookie.String(), session.CSRFToken)
	assertAPIError(t, argoResidential, http.StatusConflict, "unsupported_residential_protocol")
	deletedStrictArgo := performJSON(strictHandler, http.MethodDelete,
		fmt.Sprintf("/api/v1/nodes/%d", activeArgoNode.ID), nil, cookie.String(), session.CSRFToken)
	if deletedStrictArgo.Code != http.StatusNoContent {
		t.Fatalf("delete strict Argo status = %d body=%s", deletedStrictArgo.Code, deletedStrictArgo.Body.String())
	}
	forgedPrerequisites := performJSON(strictHandler, http.MethodPut, "/api/v1/settings/protocol-prerequisites",
		map[string]any{
			"target": "https", "action": "verify", "domain": "ws.example.com",
			"httpsIngressEnabled": true,
		}, cookie.String(), session.CSRFToken)
	assertAPIError(t, forgedPrerequisites, http.StatusBadRequest, "invalid_json")
	invalidPrerequisites := performJSON(handler, http.MethodPut, "/api/v1/settings/protocol-prerequisites",
		map[string]any{"action": "verify", "domain": "argo.example.com"}, cookie.String(), session.CSRFToken)
	assertAPIError(t, invalidPrerequisites, http.StatusBadRequest, "invalid_prerequisite_target")
	invalidOriginPort := performJSON(handler, http.MethodPut, "/api/v1/settings/protocol-prerequisites",
		map[string]any{"target": "cloudflare", "action": "verify", "domain": "argo.example.com", "originPort": 70000},
		cookie.String(), session.CSRFToken)
	assertAPIError(t, invalidOriginPort, http.StatusBadRequest, "invalid_origin_port")
	httpsPrerequisites := performJSON(handler, http.MethodPut, "/api/v1/settings/protocol-prerequisites", map[string]any{
		"target": "https", "action": "verify", "domain": "WS.Example.com",
	}, cookie.String(), session.CSRFToken)
	if httpsPrerequisites.Code != http.StatusOK ||
		!bytes.Contains(httpsPrerequisites.Body.Bytes(), []byte(`"httpsIngressEnabled":true`)) ||
		!bytes.Contains(httpsPrerequisites.Body.Bytes(), []byte(`"httpsIngressDomain":"ws.example.com"`)) {
		t.Fatalf("save HTTPS prerequisite status = %d body=%s", httpsPrerequisites.Code, httpsPrerequisites.Body.String())
	}
	savedPrerequisites := performJSON(handler, http.MethodPut, "/api/v1/settings/protocol-prerequisites", map[string]any{
		"target": "cloudflare", "action": "verify", "domain": "Argo.Example.com",
	}, cookie.String(), session.CSRFToken)
	if savedPrerequisites.Code != http.StatusOK ||
		!bytes.Contains(savedPrerequisites.Body.Bytes(), []byte(`"cloudflareTunnelEnabled":true`)) ||
		!bytes.Contains(savedPrerequisites.Body.Bytes(), []byte(`"cloudflareTunnelDomain":"argo.example.com"`)) ||
		!bytes.Contains(savedPrerequisites.Body.Bytes(), []byte(`"cloudflareTunnelVerifiedAt":`)) {
		t.Fatalf("save protocol prerequisites status = %d body=%s", savedPrerequisites.Code, savedPrerequisites.Body.String())
	}
	strictAfterSimulation := performJSON(strictHandler, http.MethodGet, "/api/v1/settings/protocol-prerequisites",
		nil, cookie.String(), "")
	if strictAfterSimulation.Code != http.StatusOK ||
		!bytes.Contains(strictAfterSimulation.Body.Bytes(), []byte(`"cloudflareTunnelEnabled":false`)) {
		t.Fatalf("production accepted simulated prerequisite: %s", strictAfterSimulation.Body.String())
	}
	clearedPrerequisites := performJSON(handler, http.MethodPut, "/api/v1/settings/protocol-prerequisites",
		map[string]any{"target": "cloudflare", "action": "clear"}, cookie.String(), session.CSRFToken)
	if clearedPrerequisites.Code != http.StatusOK ||
		!bytes.Contains(clearedPrerequisites.Body.Bytes(), []byte(`"cloudflareTunnelEnabled":false`)) ||
		bytes.Contains(clearedPrerequisites.Body.Bytes(), []byte("argo.example.com")) {
		t.Fatalf("clear protocol prerequisite status = %d body=%s", clearedPrerequisites.Code, clearedPrerequisites.Body.String())
	}
	openVPNConfig := "client\ndev tun\nproto udp\nremote old.example 1194\n" +
		"<ca>\nCA\n</ca>\n<cert>\nCERT\n</cert>\n<key>\nKEY\n</key>\n"
	if err := app.Store.ReplaceVPNGateCandidates(context.Background(), []model.VPNGateCandidate{
		{
			HostName: "vpn-test", IP: "198.51.100.40", Score: 100, Ping: 20,
			Speed: 10_000_000, CountryLong: "Japan", CountryShort: "JP",
			NumSessions: 1, Uptime: 1000, FetchedAt: time.Now().UTC(), OpenVPNConfig: openVPNConfig,
		},
		{
			HostName: "vpn-no-ping", IP: "198.51.100.41", Score: 90, Ping: 0,
			Speed: 20_000_000, CountryLong: "Japan", CountryShort: "JP",
			NumSessions: 1, Uptime: 1000, FetchedAt: time.Now().UTC(), OpenVPNConfig: openVPNConfig,
		},
	}); err != nil {
		t.Fatal(err)
	}
	filteredRegions := performJSON(handler, http.MethodGet,
		"/api/v1/vpngate/regions?maxPing=1000&minSpeed=1000000&maxSessions=100",
		nil, cookie.String(), "")
	if filteredRegions.Code != http.StatusOK ||
		!bytes.Contains(filteredRegions.Body.Bytes(), []byte(`"availableCount":2`)) ||
		!bytes.Contains(filteredRegions.Body.Bytes(), []byte(`"count":2`)) ||
		!bytes.Contains(filteredRegions.Body.Bytes(), []byte(`"nameZh":"日本"`)) {
		t.Fatalf("VPNGate regions status = %d body=%s", filteredRegions.Code, filteredRegions.Body.String())
	}
	inspection := performJSON(handler, http.MethodPost,
		"/api/v1/vpngate/inspect", map[string]any{"hostName": "vpn-test"}, cookie.String(), session.CSRFToken)
	if inspection.Code != http.StatusOK ||
		!bytes.Contains(inspection.Body.Bytes(), []byte(`"provider":"本地模拟数据（生产环境使用 ip.net.coffee）"`)) ||
		!bytes.Contains(inspection.Body.Bytes(), []byte(`"pingMs":20`)) ||
		!bytes.Contains(inspection.Body.Bytes(), []byte(`"speedBitsPerSecond":10000000`)) ||
		!bytes.Contains(inspection.Body.Bytes(), []byte(`"trustScore":90`)) ||
		bytes.Contains(inspection.Body.Bytes(), []byte(`"verdict"`)) ||
		bytes.Contains(inspection.Body.Bytes(), []byte(`"vps"`)) ||
		bytes.Contains(inspection.Body.Bytes(), []byte(`"speedBytesPerSecond"`)) {
		t.Fatalf("VPNGate inspection status = %d body=%s", inspection.Code, inspection.Body.String())
	}
	createdVPNExit := performJSON(handler, http.MethodPost, "/api/v1/vpngate/outbounds", map[string]any{
		"name": "VPN test", "country": "JP", "durationMinutes": 30,
		"failurePolicy": "block",
	}, cookie.String(), session.CSRFToken)
	if createdVPNExit.Code != http.StatusCreated {
		t.Fatalf("create VPNGate exit status = %d body=%s", createdVPNExit.Code, createdVPNExit.Body.String())
	}
	var vpnExit struct {
		ID         int64  `json:"id"`
		OutboundID int64  `json:"outboundId"`
		Status     string `json:"status"`
	}
	if err := json.NewDecoder(createdVPNExit.Body).Decode(&vpnExit); err != nil {
		t.Fatal(err)
	}
	if vpnExit.Status != "running" || vpnExit.OutboundID == 0 {
		t.Fatalf("VPNGate exit = %#v", vpnExit)
	}
	deletedVPNExit := performJSON(handler, http.MethodDelete,
		fmt.Sprintf("/api/v1/vpngate/outbounds/%d", vpnExit.ID), nil,
		cookie.String(), session.CSRFToken)
	if deletedVPNExit.Code != http.StatusNoContent {
		t.Fatalf("delete VPNGate exit status = %d body=%s", deletedVPNExit.Code, deletedVPNExit.Body.String())
	}
	invalidOutbound := performJSON(handler, http.MethodPost, "/api/v1/outbounds", map[string]any{
		"name": "invalid", "type": "socks5", "server": "bad@host:1080",
		"port": 1080, "enabled": true,
	}, cookie.String(), session.CSRFToken)
	assertAPIError(t, invalidOutbound, http.StatusBadRequest, "validation_failed")

	createdOutbound := performJSON(handler, http.MethodPost, "/api/v1/outbounds", map[string]any{
		"name": "Residential test", "type": "socks5", "server": "proxy.example.com",
		"port": 1080, "enabled": true, "username": "proxy-user", "password": "proxy-secret",
	}, cookie.String(), session.CSRFToken)
	if createdOutbound.Code != http.StatusCreated {
		t.Fatalf("create outbound status = %d body=%s", createdOutbound.Code, createdOutbound.Body.String())
	}
	if bytes.Contains(createdOutbound.Body.Bytes(), []byte("proxy-user")) ||
		bytes.Contains(createdOutbound.Body.Bytes(), []byte("proxy-secret")) {
		t.Fatal("outbound API exposed credentials")
	}
	var outbound struct {
		ID            int64 `json:"id"`
		HasCredential bool  `json:"hasCredential"`
	}
	if err := json.NewDecoder(createdOutbound.Body).Decode(&outbound); err != nil {
		t.Fatal(err)
	}
	if !outbound.HasCredential {
		t.Fatal("outbound response did not report stored credentials")
	}
	updatedOutbound := performJSON(handler, http.MethodPut,
		fmt.Sprintf("/api/v1/outbounds/%d", outbound.ID), map[string]any{
			"name": "Residential edited", "type": "socks5", "server": "proxy.example.com",
			"port": 1081, "enabled": true,
		}, cookie.String(), session.CSRFToken)
	if updatedOutbound.Code != http.StatusOK {
		t.Fatalf("update outbound status = %d body=%s", updatedOutbound.Code, updatedOutbound.Body.String())
	}
	storedOutbound, err := app.Store.Outbound(context.Background(), outbound.ID)
	if err != nil {
		t.Fatal(err)
	}
	if storedOutbound.Username != "proxy-user" || storedOutbound.Password != "proxy-secret" {
		t.Fatal("keep credential mode did not preserve outbound credentials")
	}
	replacedOutbound := performJSON(handler, http.MethodPut,
		fmt.Sprintf("/api/v1/outbounds/%d", outbound.ID), map[string]any{
			"name": "Residential edited", "type": "socks5", "server": "proxy.example.com",
			"port": 1081, "enabled": true, "credentialMode": "replace",
			"username": "replacement-user", "password": "replacement-secret",
		}, cookie.String(), session.CSRFToken)
	if replacedOutbound.Code != http.StatusOK {
		t.Fatalf("replace outbound credentials status = %d body=%s", replacedOutbound.Code, replacedOutbound.Body.String())
	}
	clearedOutbound := performJSON(handler, http.MethodPut,
		fmt.Sprintf("/api/v1/outbounds/%d", outbound.ID), map[string]any{
			"name": "Residential edited", "type": "socks5", "server": "proxy.example.com",
			"port": 1081, "enabled": true, "credentialMode": "clear",
		}, cookie.String(), session.CSRFToken)
	if clearedOutbound.Code != http.StatusOK {
		t.Fatalf("clear outbound credentials status = %d body=%s", clearedOutbound.Code, clearedOutbound.Body.String())
	}
	storedOutbound, err = app.Store.Outbound(context.Background(), outbound.ID)
	if err != nil {
		t.Fatal(err)
	}
	if storedOutbound.Username != "" || storedOutbound.Password != "" || storedOutbound.HasCredential {
		t.Fatal("clear credential mode retained outbound credentials")
	}
	deletedOutbound := performJSON(handler, http.MethodDelete,
		fmt.Sprintf("/api/v1/outbounds/%d", outbound.ID), nil, cookie.String(), session.CSRFToken)
	if deletedOutbound.Code != http.StatusNoContent {
		t.Fatalf("delete outbound status = %d body=%s", deletedOutbound.Code, deletedOutbound.Body.String())
	}

	port := availablePort(t)
	customUUID := "11111111-1111-4111-8111-111111111111"
	invalidNode := performJSON(handler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "invalid", "protocol": "vless_reality", "listen": "127.0.0.1",
		"port": availablePort(t), "enabled": false,
		"settings": map[string]any{"handshake_server": "example.com:443"},
	}, cookie.String(), session.CSRFToken)
	assertAPIError(t, invalidNode, http.StatusBadRequest, "validation_failed")

	created := performJSON(handler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "Reality", "protocol": "vless_reality", "listen": "127.0.0.1",
		"port": port, "enabled": true, "clientName": "primary", "settings": map[string]any{},
		"credential": map[string]any{"uuid": customUUID},
	}, cookie.String(), session.CSRFToken)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", created.Code, created.Body.String())
	}
	var createdNode struct {
		ID              int64  `json:"id"`
		ExternalAddress string `json:"externalAddress"`
		CurrentOutbound string `json:"currentOutbound"`
	}
	if err := json.NewDecoder(created.Body).Decode(&createdNode); err != nil {
		t.Fatal(err)
	}
	if createdNode.ExternalAddress != "node.example.com" || createdNode.CurrentOutbound != "native" {
		t.Fatalf("created node metadata = %#v", createdNode)
	}
	manualResidential := performJSON(handler, http.MethodPost, "/api/v1/residential-nodes/manual", map[string]any{
		"nodeId": createdNode.ID, "type": "socks5", "server": "proxy.example.com:1443",
		"port": 1080, "username": "proxy-user", "password": "proxy-secret",
	}, cookie.String(), session.CSRFToken)
	if manualResidential.Code != http.StatusCreated {
		t.Fatalf("create manual residential node status = %d body=%s", manualResidential.Code, manualResidential.Body.String())
	}
	var manualTemporary struct {
		Node model.Node `json:"node"`
		URI  string     `json:"uri"`
	}
	if err := json.NewDecoder(manualResidential.Body).Decode(&manualTemporary); err != nil {
		t.Fatal(err)
	}
	if !manualTemporary.Node.Enabled || manualTemporary.Node.OutboundID == nil || manualTemporary.URI == "" ||
		!strings.Contains(manualTemporary.Node.Name, "丨S丨XTLS-Reality_") ||
		manualTemporary.Node.Settings["jui_temporary_source"] != "manual" ||
		manualTemporary.Node.Settings["jui_temporary_expires_at"] != nil {
		t.Fatalf("manual temporary node = %#v uri=%q", manualTemporary.Node, manualTemporary.URI)
	}
	manualOutbound, err := app.Store.Outbound(context.Background(), *manualTemporary.Node.OutboundID)
	if err != nil {
		t.Fatal(err)
	}
	if manualOutbound.Server != "proxy.example.com" || manualOutbound.Port != 1443 {
		t.Fatalf("normalized manual outbound = %s:%d", manualOutbound.Server, manualOutbound.Port)
	}
	vpnGateExitsAfterManual, err := app.Store.ListVPNGateExits(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(vpnGateExitsAfterManual) != 0 {
		t.Fatalf("manual upstream consumed VPNGate tunnel slots: %#v", vpnGateExitsAfterManual)
	}
	beforeRejected, err := app.Store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	app.Nodes.ConfigureOutboundChecker(nodeservice.OutboundCheckFunc(
		func(context.Context, model.Outbound) (exitcheck.Result, error) {
			return exitcheck.Result{}, errors.New("proxy refused connection")
		},
	))
	rejectedManual := performJSON(handler, http.MethodPost, "/api/v1/residential-nodes/manual", map[string]any{
		"nodeId": createdNode.ID, "type": "socks5", "server": "unreachable.example.com", "port": 1080,
	}, cookie.String(), session.CSRFToken)
	assertAPIError(t, rejectedManual, http.StatusBadGateway, "outbound_check_failed")
	afterRejected, err := app.Store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(afterRejected) != len(beforeRejected) {
		t.Fatalf("failed manual proxy left an outbound behind: before=%d after=%d", len(beforeRejected), len(afterRejected))
	}
	app.Nodes.ConfigureOutboundChecker(nodeservice.OutboundCheckFunc(
		func(context.Context, model.Outbound) (exitcheck.Result, error) {
			return exitcheck.Result{IP: "203.0.113.10", Country: "ZZ", ASN: "AS0 test"}, nil
		},
	))

	vpnResidential := performJSON(handler, http.MethodPost, "/api/v1/residential-nodes/vpngate", map[string]any{
		"nodeId": createdNode.ID, "country": "JP", "candidateHostName": "vpn-test",
		"durationMinutes": 30, "failurePolicy": "block", "maxPing": 1000,
		"minSpeedMbps": 1, "maxSessions": 100,
	}, cookie.String(), session.CSRFToken)
	if vpnResidential.Code != http.StatusCreated {
		t.Fatalf("create VPNGate residential node status = %d body=%s", vpnResidential.Code, vpnResidential.Body.String())
	}
	var vpnTemporary struct {
		Node   model.Node `json:"node"`
		URI    string     `json:"uri"`
		ExitID int64      `json:"exitId"`
	}
	if err := json.NewDecoder(vpnResidential.Body).Decode(&vpnTemporary); err != nil {
		t.Fatal(err)
	}
	if !vpnTemporary.Node.Enabled || vpnTemporary.Node.OutboundID == nil || vpnTemporary.URI == "" ||
		vpnTemporary.ExitID == 0 || !strings.Contains(vpnTemporary.Node.Name, "丨S-JP丨XTLS-Reality_") ||
		vpnTemporary.Node.Settings["jui_temporary_country"] != "JP" {
		t.Fatalf("VPNGate temporary node = %#v uri=%q exit=%d", vpnTemporary.Node, vpnTemporary.URI, vpnTemporary.ExitID)
	}
	if vpnTemporary.Node.Port == manualTemporary.Node.Port {
		t.Fatalf("temporary nodes reused active port %d", vpnTemporary.Node.Port)
	}
	sharedVPNResidential := performJSON(handler, http.MethodPost, "/api/v1/residential-nodes/vpngate", map[string]any{
		"nodeId": createdNode.ID, "country": "JP", "candidateHostName": "vpn-test",
		"durationMinutes": 30, "failurePolicy": "block",
	}, cookie.String(), session.CSRFToken)
	if sharedVPNResidential.Code != http.StatusCreated {
		t.Fatalf("create second node on VPNGate tunnel status = %d body=%s", sharedVPNResidential.Code, sharedVPNResidential.Body.String())
	}
	var sharedVPN struct {
		Node       model.Node `json:"node"`
		ExitID     int64      `json:"exitId"`
		ReusedExit bool       `json:"reusedExit"`
	}
	if err := json.NewDecoder(sharedVPNResidential.Body).Decode(&sharedVPN); err != nil {
		t.Fatal(err)
	}
	if !sharedVPN.ReusedExit || sharedVPN.ExitID != vpnTemporary.ExitID ||
		sharedVPN.Node.OutboundID == nil || *sharedVPN.Node.OutboundID != *vpnTemporary.Node.OutboundID ||
		sharedVPN.Node.Port == vpnTemporary.Node.Port {
		t.Fatalf("shared VPNGate node = %#v", sharedVPN)
	}
	expiringNode, err := app.Store.Node(context.Background(), vpnTemporary.Node.ID)
	if err != nil {
		t.Fatal(err)
	}
	expiredAt := time.Now().UTC().Add(-time.Second)
	expiringNode.Settings["jui_temporary_expires_at"] = expiredAt.Format(time.RFC3339)
	if err := app.Store.UpdateNode(context.Background(), expiringNode); err != nil {
		t.Fatal(err)
	}
	sharedExpiringNode, err := app.Store.Node(context.Background(), sharedVPN.Node.ID)
	if err != nil {
		t.Fatal(err)
	}
	sharedExpiringNode.Settings["jui_temporary_expires_at"] = expiredAt.Format(time.RFC3339)
	if err := app.Store.UpdateNode(context.Background(), sharedExpiringNode); err != nil {
		t.Fatal(err)
	}
	expiringExit, err := app.Store.VPNGateExit(context.Background(), vpnTemporary.ExitID)
	if err != nil {
		t.Fatal(err)
	}
	expiringExit.ExpiresAt = &expiredAt
	if err := app.Store.UpdateVPNGateExit(context.Background(), expiringExit); err != nil {
		t.Fatal(err)
	}
	if err := app.Nodes.ExpireTemporary(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Nodes.Get(context.Background(), expiringNode.ID); err == nil {
		t.Fatal("expired VPNGate node record still exists")
	}
	if _, err := app.Nodes.Get(context.Background(), sharedExpiringNode.ID); err == nil {
		t.Fatal("second expired VPNGate node record still exists")
	}
	if err := app.VPNGate.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Store.Outbound(context.Background(), *expiringNode.OutboundID); err == nil {
		t.Fatal("expired VPNGate outbound record still exists")
	}
	remainingExits, err := app.VPNGate.Exits(context.Background())
	if err != nil || len(remainingExits) != 0 {
		t.Fatalf("VPNGate exits after expiry cleanup = %#v err=%v", remainingExits, err)
	}
	if _, err := app.Nodes.Get(context.Background(), manualTemporary.Node.ID); err != nil {
		t.Fatalf("permanent manual residential node was removed: %v", err)
	}

	permanentVPNResidential := performJSON(handler, http.MethodPost, "/api/v1/residential-nodes/vpngate", map[string]any{
		"nodeId": createdNode.ID, "country": "JP", "candidateHostName": "vpn-test",
		"durationMinutes": 0, "permanent": true, "failurePolicy": "block", "maxPing": 1000,
		"minSpeedMbps": 1, "maxSessions": 100,
	}, cookie.String(), session.CSRFToken)
	if permanentVPNResidential.Code != http.StatusCreated {
		t.Fatalf("create permanent VPNGate node status = %d body=%s", permanentVPNResidential.Code, permanentVPNResidential.Body.String())
	}
	var permanentVPN struct {
		Node model.Node `json:"node"`
	}
	if err := json.NewDecoder(permanentVPNResidential.Body).Decode(&permanentVPN); err != nil {
		t.Fatal(err)
	}
	if permanentVPN.Node.Settings["jui_temporary_expires_at"] != nil {
		t.Fatalf("permanent VPNGate node has expiry: %#v", permanentVPN.Node.Settings)
	}
	wrongResidentialDelete := performJSON(handler, http.MethodDelete,
		fmt.Sprintf("/api/v1/residential-nodes/%d", createdNode.ID), nil,
		cookie.String(), session.CSRFToken)
	assertAPIError(t, wrongResidentialDelete, http.StatusConflict, "not_temporary_node")
	for _, temporaryID := range []int64{manualTemporary.Node.ID, permanentVPN.Node.ID} {
		deleted := performJSON(handler, http.MethodDelete,
			fmt.Sprintf("/api/v1/residential-nodes/%d", temporaryID), nil,
			cookie.String(), session.CSRFToken)
		if deleted.Code != http.StatusNoContent {
			t.Fatalf("delete residential node %d status = %d body=%s", temporaryID, deleted.Code, deleted.Body.String())
		}
	}
	remainingExits, err = app.VPNGate.Exits(context.Background())
	if err != nil || len(remainingExits) != 0 {
		t.Fatalf("VPNGate exits after residential cleanup = %#v err=%v", remainingExits, err)
	}
	argoCreated := performJSON(handler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "Argo", "protocol": "vless_argo", "listen": "127.0.0.1",
		"port": availablePort(t), "enabled": false, "clientName": "primary",
		"publicHostOverride": "argo.example.com",
		"settings":           map[string]any{"server_name": "argo.example.com", "ws_path": "/jui-argo"},
	}, cookie.String(), session.CSRFToken)
	if argoCreated.Code != http.StatusCreated {
		t.Fatalf("create Argo status = %d body=%s", argoCreated.Code, argoCreated.Body.String())
	}
	var argoNode struct {
		ID              int64  `json:"id"`
		ExternalAddress string `json:"externalAddress"`
	}
	if err := json.NewDecoder(argoCreated.Body).Decode(&argoNode); err != nil {
		t.Fatal(err)
	}
	if argoNode.ExternalAddress != "argo.example.com" {
		t.Fatalf("Argo external address = %q", argoNode.ExternalAddress)
	}
	argoExport := performJSON(handler, http.MethodGet,
		fmt.Sprintf("/api/v1/nodes/%d/export", argoNode.ID), nil, cookie.String(), "")
	if argoExport.Code != http.StatusOK || !bytes.Contains(argoExport.Body.Bytes(), []byte("argo.example.com:443")) {
		t.Fatalf("Argo export status = %d body=%s", argoExport.Code, argoExport.Body.String())
	}
	argoDeleted := performJSON(handler, http.MethodDelete,
		fmt.Sprintf("/api/v1/nodes/%d", argoNode.ID), nil, cookie.String(), session.CSRFToken)
	if argoDeleted.Code != http.StatusNoContent {
		t.Fatalf("delete Argo status = %d body=%s", argoDeleted.Code, argoDeleted.Body.String())
	}
	duplicatePort := performJSON(handler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "duplicate", "protocol": "vless_reality", "listen": "127.0.0.1",
		"port": port, "enabled": false, "settings": map[string]any{},
	}, cookie.String(), session.CSRFToken)
	assertAPIError(t, duplicatePort, http.StatusConflict, "resource_conflict")
	beforeEdit := performJSON(handler, http.MethodGet,
		fmt.Sprintf("/api/v1/nodes/%d", createdNode.ID), nil, cookie.String(), "")
	var beforeEditNode struct {
		Settings map[string]any `json:"settings"`
	}
	if err := json.NewDecoder(beforeEdit.Body).Decode(&beforeEditNode); err != nil {
		t.Fatal(err)
	}
	edited := performJSON(handler, http.MethodPut, fmt.Sprintf("/api/v1/nodes/%d", createdNode.ID),
		map[string]any{
			"name": "Reality edited", "listen": "127.0.0.1", "port": port, "enabled": true,
			"settings": map[string]any{
				"handshake_server": "www.microsoft.com", "handshake_port": 443,
				"server_name": "www.microsoft.com",
			},
		}, cookie.String(), session.CSRFToken)
	if edited.Code != http.StatusOK {
		t.Fatalf("edit status = %d body=%s", edited.Code, edited.Body.String())
	}
	var editedNode struct {
		Settings map[string]any `json:"settings"`
	}
	if err := json.NewDecoder(edited.Body).Decode(&editedNode); err != nil {
		t.Fatal(err)
	}
	if editedNode.Settings["public_key"] != beforeEditNode.Settings["public_key"] ||
		editedNode.Settings["short_id"] != beforeEditNode.Settings["short_id"] {
		t.Fatal("Reality edit discarded generated public key or short ID")
	}
	bindableOutbound := performJSON(handler, http.MethodPost, "/api/v1/outbounds", map[string]any{
		"name": "Bound exit", "type": "http", "server": "proxy.example.com",
		"port": 8080, "enabled": true, "username": "proxy-user", "password": "proxy-secret",
	}, cookie.String(), session.CSRFToken)
	if bindableOutbound.Code != http.StatusCreated {
		t.Fatalf("create bound outbound status = %d body=%s", bindableOutbound.Code, bindableOutbound.Body.String())
	}
	var boundOutbound struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(bindableOutbound.Body).Decode(&boundOutbound); err != nil {
		t.Fatal(err)
	}
	boundNode := performJSON(handler, http.MethodPut, fmt.Sprintf("/api/v1/nodes/%d", createdNode.ID),
		map[string]any{
			"name": "Reality edited", "listen": "127.0.0.1", "port": port, "enabled": true,
			"outboundId": boundOutbound.ID,
			"settings": map[string]any{
				"handshake_server": "www.microsoft.com", "handshake_port": 443,
				"server_name": "www.microsoft.com",
			},
		}, cookie.String(), session.CSRFToken)
	if boundNode.Code != http.StatusOK || !bytes.Contains(boundNode.Body.Bytes(), []byte(`"currentOutbound":"outbound-`)) {
		t.Fatalf("bind node status = %d body=%s", boundNode.Code, boundNode.Body.String())
	}
	deleteBoundOutbound := performJSON(handler, http.MethodDelete,
		fmt.Sprintf("/api/v1/outbounds/%d", boundOutbound.ID), nil, cookie.String(), session.CSRFToken)
	assertAPIError(t, deleteBoundOutbound, http.StatusConflict, "resource_conflict")
	unboundNode := performJSON(handler, http.MethodPut, fmt.Sprintf("/api/v1/nodes/%d", createdNode.ID),
		map[string]any{
			"name": "Reality edited", "listen": "127.0.0.1", "port": port, "enabled": true,
			"outboundId": nil,
			"settings": map[string]any{
				"handshake_server": "www.microsoft.com", "handshake_port": 443,
				"server_name": "www.microsoft.com",
			},
		}, cookie.String(), session.CSRFToken)
	if unboundNode.Code != http.StatusOK {
		t.Fatalf("unbind node status = %d body=%s", unboundNode.Code, unboundNode.Body.String())
	}
	deletedBoundOutbound := performJSON(handler, http.MethodDelete,
		fmt.Sprintf("/api/v1/outbounds/%d", boundOutbound.ID), nil, cookie.String(), session.CSRFToken)
	if deletedBoundOutbound.Code != http.StatusNoContent {
		t.Fatalf("delete unbound outbound status = %d body=%s", deletedBoundOutbound.Code, deletedBoundOutbound.Body.String())
	}
	listedClients := performJSON(handler, http.MethodGet,
		fmt.Sprintf("/api/v1/nodes/%d/clients", createdNode.ID), nil, cookie.String(), "")
	if listedClients.Code != http.StatusOK {
		t.Fatalf("list clients status = %d body=%s", listedClients.Code, listedClients.Body.String())
	}
	var clients []struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(listedClients.Body).Decode(&clients); err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 || clients[0].Name != "primary" {
		t.Fatalf("created clients = %#v", clients)
	}
	missingClient := performJSON(handler, http.MethodGet,
		fmt.Sprintf("/api/v1/nodes/%d/clients/999999/export", createdNode.ID),
		nil, cookie.String(), "")
	assertAPIError(t, missingClient, http.StatusNotFound, "not_found")

	addedClient := performJSON(handler, http.MethodPost,
		fmt.Sprintf("/api/v1/nodes/%d/clients", createdNode.ID),
		map[string]any{"name": "secondary"}, cookie.String(), session.CSRFToken)
	if addedClient.Code != http.StatusCreated {
		t.Fatalf("add client status = %d body=%s", addedClient.Code, addedClient.Body.String())
	}
	var secondary struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(addedClient.Body).Decode(&secondary); err != nil {
		t.Fatal(err)
	}
	toggledClient := performJSON(handler, http.MethodPut,
		fmt.Sprintf("/api/v1/nodes/%d/clients/%d", createdNode.ID, secondary.ID),
		map[string]any{"name": "secondary", "enabled": false}, cookie.String(), session.CSRFToken)
	if toggledClient.Code != http.StatusNoContent {
		t.Fatalf("toggle client status = %d body=%s", toggledClient.Code, toggledClient.Body.String())
	}
	deletedClient := performJSON(handler, http.MethodDelete,
		fmt.Sprintf("/api/v1/nodes/%d/clients/%d", createdNode.ID, secondary.ID),
		nil, cookie.String(), session.CSRFToken)
	if deletedClient.Code != http.StatusNoContent {
		t.Fatalf("delete client status = %d body=%s", deletedClient.Code, deletedClient.Body.String())
	}
	deleteLastClient := performJSON(handler, http.MethodDelete,
		fmt.Sprintf("/api/v1/nodes/%d/clients/%d", createdNode.ID, clients[0].ID),
		nil, cookie.String(), session.CSRFToken)
	assertAPIError(t, deleteLastClient, http.StatusConflict, "last_client")
	exportPath := fmt.Sprintf("/api/v1/nodes/%d/clients/%d/export", createdNode.ID, clients[0].ID)
	exported := performJSON(handler, http.MethodGet, exportPath, nil, cookie.String(), "")
	if exported.Code != http.StatusOK {
		t.Fatalf("export client status = %d body=%s", exported.Code, exported.Body.String())
	}
	var oldCredential struct {
		URI string `json:"uri"`
	}
	if err := json.NewDecoder(exported.Body).Decode(&oldCredential); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(oldCredential.URI, customUUID) {
		t.Fatalf("exported URI did not use custom UUID: %s", oldCredential.URI)
	}
	resetCredential := performJSON(handler, http.MethodPost,
		fmt.Sprintf("/api/v1/nodes/%d/clients/%d/reset", createdNode.ID, clients[0].ID),
		map[string]any{}, cookie.String(), session.CSRFToken)
	if resetCredential.Code != http.StatusOK {
		t.Fatalf("reset client status = %d body=%s", resetCredential.Code, resetCredential.Body.String())
	}
	var newCredential struct {
		URI string `json:"uri"`
	}
	if err := json.NewDecoder(resetCredential.Body).Decode(&newCredential); err != nil {
		t.Fatal(err)
	}
	if oldCredential.URI == "" || newCredential.URI == "" || oldCredential.URI == newCredential.URI {
		t.Fatalf("credential reset did not return a changed URI")
	}
	subscriptionInfo := performJSON(handler, http.MethodGet,
		"/api/v1/subscription", nil, cookie.String(), "")
	if subscriptionInfo.Code != http.StatusOK {
		t.Fatalf("subscription info status = %d body=%s", subscriptionInfo.Code, subscriptionInfo.Body.String())
	}
	var subscriptionPaths map[string]string
	if err := json.NewDecoder(subscriptionInfo.Body).Decode(&subscriptionPaths); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"base64Path", "v2rayNPath", "shadowrocketPath", "clashPath", "singBoxPath"} {
		if subscriptionPaths[key] == "" {
			t.Fatalf("subscription info missing %s: %#v", key, subscriptionPaths)
		}
	}
	formats := map[string]string{
		"base64":       "text/plain; charset=utf-8",
		"v2rayn":       "text/plain; charset=utf-8",
		"shadowrocket": "text/plain; charset=utf-8",
		"clash":        "application/yaml; charset=utf-8",
		"singbox":      "application/json; charset=utf-8",
	}
	for format, expectedContentType := range formats {
		rendered := performJSON(handler, http.MethodGet,
			"/sub/"+subscriptionPaths["token"]+"?format="+format, nil, "", "")
		if rendered.Code != http.StatusOK || rendered.Header().Get("Content-Type") != expectedContentType ||
			strings.Contains(strings.ToLower(rendered.Body.String()), "<!doctype html") {
			t.Fatalf("%s subscription status = %d content-type=%q body=%s", format,
				rendered.Code, rendered.Header().Get("Content-Type"), rendered.Body.String())
		}
	}
	invalidSubscription := performJSON(handler, http.MethodGet,
		"/sub/not-the-current-token?format=clash", nil, "", "")
	if invalidSubscription.Code != http.StatusNotFound ||
		!strings.HasPrefix(invalidSubscription.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("invalid subscription status = %d body=%s",
			invalidSubscription.Code, invalidSubscription.Body.String())
	}
	preview := performJSON(handler, http.MethodGet,
		"/api/v1/subscription/preview?format=base64", nil, cookie.String(), "")
	if preview.Code != http.StatusOK {
		t.Fatalf("subscription preview status = %d body=%s", preview.Code, preview.Body.String())
	}
	var previewBody struct {
		Valid bool `json:"valid"`
		Items int  `json:"items"`
	}
	if err := json.NewDecoder(preview.Body).Decode(&previewBody); err != nil {
		t.Fatal(err)
	}
	if !previewBody.Valid || previewBody.Items != 1 {
		t.Fatalf("subscription preview = %#v", previewBody)
	}
	singBoxPreview := performJSON(handler, http.MethodGet,
		"/api/v1/subscription/preview?format=singbox", nil, cookie.String(), "")
	if singBoxPreview.Code != http.StatusOK {
		t.Fatalf("sing-box preview status = %d body=%s", singBoxPreview.Code, singBoxPreview.Body.String())
	}
	previewBody = struct {
		Valid bool `json:"valid"`
		Items int  `json:"items"`
	}{}
	if err := json.NewDecoder(singBoxPreview.Body).Decode(&previewBody); err != nil {
		t.Fatal(err)
	}
	if !previewBody.Valid || previewBody.Items != 1 {
		t.Fatalf("sing-box preview = %#v", previewBody)
	}
	unsupportedPreview := performJSON(handler, http.MethodGet,
		"/api/v1/subscription/preview?format=invalid", nil, cookie.String(), "")
	assertAPIError(t, unsupportedPreview, http.StatusBadRequest, "unsupported_format")

	cloned := performJSON(handler, http.MethodPost,
		fmt.Sprintf("/api/v1/nodes/%d/clone", createdNode.ID), map[string]any{},
		cookie.String(), session.CSRFToken)
	if cloned.Code != http.StatusCreated {
		t.Fatalf("clone status = %d body=%s", cloned.Code, cloned.Body.String())
	}
	var clonedNode struct {
		ID      int64 `json:"id"`
		Enabled bool  `json:"enabled"`
	}
	if err := json.NewDecoder(cloned.Body).Decode(&clonedNode); err != nil {
		t.Fatal(err)
	}
	if clonedNode.Enabled {
		t.Fatal("cloned node must be disabled")
	}
	enabledClone := performJSON(handler, http.MethodPost,
		fmt.Sprintf("/api/v1/nodes/%d/enable", clonedNode.ID), map[string]any{},
		cookie.String(), session.CSRFToken)
	if enabledClone.Code != http.StatusOK {
		t.Fatalf("enable clone status = %d body=%s", enabledClone.Code, enabledClone.Body.String())
	}
	disabledClone := performJSON(handler, http.MethodPost,
		fmt.Sprintf("/api/v1/nodes/%d/disable", clonedNode.ID), map[string]any{},
		cookie.String(), session.CSRFToken)
	if disabledClone.Code != http.StatusOK {
		t.Fatalf("disable clone status = %d body=%s", disabledClone.Code, disabledClone.Body.String())
	}
	deletedClone := performJSON(handler, http.MethodDelete,
		fmt.Sprintf("/api/v1/nodes/%d", clonedNode.ID), nil,
		cookie.String(), session.CSRFToken)
	if deletedClone.Code != http.StatusNoContent {
		t.Fatalf("delete clone status = %d body=%s", deletedClone.Code, deletedClone.Body.String())
	}

	webBackup := performJSON(handler, http.MethodPost, "/api/v1/system/backup",
		map[string]any{}, cookie.String(), session.CSRFToken)
	if webBackup.Code != http.StatusOK || webBackup.Header().Get("Content-Type") != "application/gzip" {
		t.Fatalf("web backup status = %d content-type=%q body=%s",
			webBackup.Code, webBackup.Header().Get("Content-Type"), webBackup.Body.String())
	}
	restart := performJSON(handler, http.MethodPost, "/api/v1/system/restart",
		map[string]any{}, cookie.String(), session.CSRFToken)
	if restart.Code != http.StatusConflict {
		t.Fatalf("mock restart status = %d, want 409", restart.Code)
	}

	oldToken := app.Credentials.SubscriptionToken
	reset := performJSON(handler, http.MethodPost, "/api/v1/subscription/reset",
		map[string]any{}, cookie.String(), session.CSRFToken)
	if reset.Code != http.StatusOK {
		t.Fatalf("reset status = %d", reset.Code)
	}
	oldRequest := httptest.NewRequest(http.MethodGet, "/sub/"+oldToken, nil)
	oldResponse := httptest.NewRecorder()
	handler.ServeHTTP(oldResponse, oldRequest)
	if oldResponse.Code != http.StatusNotFound {
		t.Fatalf("old token status = %d, want 404", oldResponse.Code)
	}
	if oldResponse.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("old token content type = %q, want JSON", oldResponse.Header().Get("Content-Type"))
	}

	var limited *httptest.ResponseRecorder
	for attempt := 0; attempt < 6; attempt++ {
		limited = performJSON(handler, http.MethodPost, "/api/v1/auth/login",
			map[string]any{"username": "admin", "password": "wrong-password"}, "", "")
	}
	if limited == nil {
		t.Fatal("login limiter did not produce a response")
	}
	if limited.Code != http.StatusTooManyRequests {
		t.Fatalf("limited login status = %d, want 429", limited.Code)
	}

	passwordChanged := performJSON(handler, http.MethodPost, "/api/v1/auth/password",
		map[string]any{
			"currentPassword": app.Credentials.Password,
			"newPassword":     "replacement-password-123",
		}, cookie.String(), session.CSRFToken)
	if passwordChanged.Code != http.StatusNoContent {
		t.Fatalf("change password status = %d body=%s", passwordChanged.Code, passwordChanged.Body.String())
	}
	expiredSession := performJSON(handler, http.MethodGet, "/api/v1/auth/session",
		nil, cookie.String(), "")
	if expiredSession.Code != http.StatusUnauthorized {
		t.Fatalf("old session status = %d after password change, want 401", expiredSession.Code)
	}
}

func TestLoginLimiterSeparatesClientsBehindLoopbackProxy(t *testing.T) {
	root := t.TempDir()
	cfg := config.Config{
		ListenAddress: "127.0.0.1:8080",
		DataDir:       filepath.Join(root, "data"), ConfigDir: filepath.Join(root, "config"),
		DatabasePath:  filepath.Join(root, "data", "j-ui.db"),
		SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"),
		SessionTTL:    3600000000000, MockEngine: true,
	}
	app, err := application.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	handler := api.NewHandler(fstest.MapFS{"index.html": {Data: []byte("J-UI")}}, app.Dependencies)
	var blocked *httptest.ResponseRecorder
	for attempt := 0; attempt < 5; attempt++ {
		blocked = performProxyJSON(handler, "198.51.100.1", map[string]any{
			"username": "admin", "password": "wrong",
		})
	}
	if blocked == nil || blocked.Code != http.StatusTooManyRequests {
		t.Fatalf("client A final status = %v", blocked)
	}
	clientB := performProxyJSON(handler, "198.51.100.2", map[string]any{
		"username": "admin", "password": app.Credentials.Password,
	})
	if clientB.Code != http.StatusOK {
		t.Fatalf("client B status = %d body=%s", clientB.Code, clientB.Body.String())
	}
}

func assertAPIError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("API status = %d, want %d; body=%s", response.Code, status, response.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode API error: %v; body=%s", err, response.Body.String())
	}
	if body.Code != code {
		t.Fatalf("API error code = %q, want %q", body.Code, code)
	}
}

func performJSON(handler http.Handler, method, path string, value any, cookie, csrf string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(value)
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if cookie != "" {
		request.Header.Set("Cookie", cookie)
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func performProxyJSON(handler http.Handler, clientIP string, value any) *httptest.ResponseRecorder {
	body, _ := json.Marshal(value)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-For", clientIP)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func availablePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}
