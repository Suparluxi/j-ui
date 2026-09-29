package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Suparluxi/j-ui/internal/api"
	"github.com/Suparluxi/j-ui/internal/application"
	"github.com/Suparluxi/j-ui/internal/config"
	"github.com/Suparluxi/j-ui/internal/model"
	nodeservice "github.com/Suparluxi/j-ui/internal/node"
)

func TestLandingAPIAcceptsOnlyDetailsAndLimitsRouting(t *testing.T) {
	root := t.TempDir()
	app, err := application.New(context.Background(), config.Config{
		ListenAddress: "127.0.0.1:8080", DataDir: filepath.Join(root, "data"),
		ConfigDir: filepath.Join(root, "config"), DatabasePath: filepath.Join(root, "data", "j-ui.db"),
		SecretKeyPath: filepath.Join(root, "config", "secret.key"),
		SingBoxConfig: filepath.Join(root, "config", "sing-box.json"), SessionTTL: time.Hour, MockEngine: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	node, err := app.Nodes.Create(context.Background(), nodeservice.CreateInput{
		Name: "Hong Kong", Protocol: model.ProtocolVLESSReality, Listen: "127.0.0.1",
		Port: availablePort(t), Enabled: true, ClientName: "default",
		Settings: map[string]any{"handshake_server": "www.example.com", "handshake_port": 443, "server_name": "www.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := api.NewHandler(fstest.MapFS{"index.html": {Data: []byte("J-UI")}}, app.Dependencies)
	login := performJSON(handler, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"username": app.Credentials.Username, "password": app.Credentials.Password,
	}, "", "")
	if login.Code != http.StatusOK {
		t.Fatalf("login: %s", login.Body.String())
	}
	var session struct {
		CSRFToken string `json:"csrfToken"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	cookie := login.Result().Cookies()[0].String()
	unauthorizedScript := performJSON(handler, http.MethodGet, "/api/v1/landing/script", nil, "", "")
	if unauthorizedScript.Code == http.StatusOK {
		t.Fatal("landing script must require authentication")
	}
	unauthorizedRefresh := performJSON(handler, http.MethodPost, "/api/v1/landing/rules/refresh", map[string]string{
		"sourceUrl": "https://raw.githubusercontent.com/a/b/main/rules.json",
	}, "", "")
	if unauthorizedRefresh.Code == http.StatusOK {
		t.Fatal("rule refresh must require authentication")
	}
	script := performJSON(handler, http.MethodGet, "/api/v1/landing/script", nil, cookie, "")
	if script.Code != http.StatusOK || !bytes.Contains(script.Body.Bytes(), []byte("j-ui-landing.service")) ||
		!bytes.Contains(script.Body.Bytes(), []byte("sha256sum")) {
		t.Fatalf("landing script unavailable: %d", script.Code)
	}
	details := "ADDR=landing.example.net\nPORT=14443\nUUID=11111111-1111-4111-8111-111111111111\n" +
		"PUB=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nSID=1234abcd\nSNI=www.microsoft.com"
	legacyDetails := "JP_ADDR=legacy.example.net\nJP_PORT=14443\nJP_UUID=11111111-1111-4111-8111-111111111111\n" +
		"JP_PUB=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nJP_SID=1234abcd\nJP_SNI=www.microsoft.com"
	for _, oldURI := range []string{"hysteria2://secret@jp.example.com:443",
		"vless://00000000-0000-4000-8000-000000000000@legacy.example.com:443?security=reality&type=tcp&encryption=none&sni=www.example.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd&flow=xtls-rprx-vision"} {
		rejected := performJSON(handler, http.MethodPut, "/api/v1/landing", map[string]any{
			"enabled": true, "uri": oldURI,
		}, cookie, session.CSRFToken)
		assertAPIError(t, rejected, http.StatusBadRequest, "invalid_json")
	}
	staleClient := performJSON(handler, http.MethodPut, "/api/v1/landing", map[string]any{
		"enabled": true, "inboundId": node.ID, "details": details,
	}, cookie, session.CSRFToken)
	assertAPIError(t, staleClient, http.StatusBadRequest, "validation_failed")
	saved := performJSON(handler, http.MethodPut, "/api/v1/landing", map[string]any{
		"enabled": true, "details": details,
	}, cookie, session.CSRFToken)
	if saved.Code != http.StatusOK || bytes.Contains(saved.Body.Bytes(), []byte("11111111-1111")) {
		t.Fatalf("saved landing status=%d body=%s", saved.Code, saved.Body.String())
	}
	legacy := performJSON(handler, http.MethodPut, "/api/v1/landing", map[string]any{
		"enabled": true, "details": legacyDetails,
	}, cookie, session.CSRFToken)
	if legacy.Code != http.StatusOK || bytes.Contains(legacy.Body.Bytes(), []byte("11111111-1111")) {
		t.Fatalf("legacy details status=%d body=%s", legacy.Code, legacy.Body.String())
	}
	mixed := performJSON(handler, http.MethodPut, "/api/v1/landing", map[string]any{
		"enabled": true, "details": strings.Replace(legacyDetails, "JP_ADDR=legacy.example.net", "ADDR=legacy.example.net", 1),
	}, cookie, session.CSRFToken)
	assertAPIError(t, mixed, http.StatusBadRequest, "validation_failed")
	stored, err := app.Store.Setting(context.Background(), "ai_landing_v1")
	if err != nil || strings.Contains(stored, "11111111-1111") {
		t.Fatal("landing connection details persisted in plaintext")
	}
	view := performJSON(handler, http.MethodGet, "/api/v1/landing", nil, cookie, "")
	if view.Code != http.StatusOK || !bytes.Contains(view.Body.Bytes(), []byte(`"configured":true`)) ||
		bytes.Contains(view.Body.Bytes(), []byte("11111111-1111")) || bytes.Contains(view.Body.Bytes(), []byte("landing.example.net")) {
		t.Fatalf("landing view: %s", view.Body.String())
	}
	imported := performJSON(handler, http.MethodPut, "/api/v1/landing", map[string]any{
		"enabled": true, "details": strings.Replace(details, "PORT=14443", "PORT=10086", 1),
	}, cookie, session.CSRFToken)
	if imported.Code != http.StatusOK || bytes.Contains(imported.Body.Bytes(), []byte("10086")) ||
		bytes.Contains(imported.Body.Bytes(), []byte("landing.example.net")) || bytes.Contains(imported.Body.Bytes(), []byte("11111111-1111")) {
		t.Fatalf("import result status=%d body=%s", imported.Code, imported.Body.String())
	}
	stored, err = app.Store.Setting(context.Background(), "ai_landing_v1")
	if err != nil || strings.Contains(stored, "11111111-1111") {
		t.Fatal("landing details persisted in plaintext")
	}
	for _, bad := range []string{details + "\nADDR=other.example.com", strings.Replace(details, "PORT=14443", "PORT=invalid", 1),
		strings.Replace(details, "ADDR=landing.example.net", "ADDR=本机公网IP", 1)} {
		rejected := performJSON(handler, http.MethodPut, "/api/v1/landing", map[string]any{
			"enabled": true, "details": bad,
		}, cookie, session.CSRFToken)
		assertAPIError(t, rejected, http.StatusBadRequest, "validation_failed")
	}
	rules := performJSON(handler, http.MethodPut, "/api/v1/landing/rules", map[string]any{
		"include": []string{"new-ai.example"}, "exclude": []string{"chatgpt.com"},
	}, cookie, session.CSRFToken)
	if rules.Code != http.StatusOK || !bytes.Contains(rules.Body.Bytes(), []byte("new-ai.example")) {
		t.Fatalf("rules status=%d body=%s", rules.Code, rules.Body.String())
	}
	rejected := performJSON(handler, http.MethodPut, "/api/v1/landing/rules", map[string]any{
		"include": []string{"*.example.com"}, "exclude": []string{},
	}, cookie, session.CSRFToken)
	assertAPIError(t, rejected, http.StatusBadRequest, "validation_failed")
	current := performJSON(handler, http.MethodGet, "/api/v1/landing/rules", nil, cookie, "")
	if !bytes.Contains(current.Body.Bytes(), []byte("new-ai.example")) {
		t.Fatal("rejected edit changed saved rules")
	}
	badSource := performJSON(handler, http.MethodPost, "/api/v1/landing/rules/refresh", map[string]string{
		"sourceUrl": "https://127.0.0.1/rules.json",
	}, cookie, session.CSRFToken)
	assertAPIError(t, badSource, http.StatusBadRequest, "validation_failed")
	unchanged := performJSON(handler, http.MethodGet, "/api/v1/landing/rules", nil, cookie, "")
	if !bytes.Contains(unchanged.Body.Bytes(), []byte("new-ai.example")) || bytes.Contains(unchanged.Body.Bytes(), []byte("127.0.0.1")) {
		t.Fatal("rejected source changed effective rules")
	}
	restored := performJSON(handler, http.MethodPost, "/api/v1/landing/rules/refresh", map[string]string{
		"sourceUrl": "",
	}, cookie, session.CSRFToken)
	if restored.Code != http.StatusOK || !bytes.Contains(restored.Body.Bytes(), []byte(`"sourceUrl":""`)) ||
		!bytes.Contains(restored.Body.Bytes(), []byte("new-ai.example")) {
		t.Fatalf("restore bundled rules status=%d body=%s", restored.Code, restored.Body.String())
	}
}
