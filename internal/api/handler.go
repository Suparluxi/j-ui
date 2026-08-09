package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Suparluxi/j-ui/internal/auth"
	"github.com/Suparluxi/j-ui/internal/database"
	"github.com/Suparluxi/j-ui/internal/model"
	"github.com/Suparluxi/j-ui/internal/monitor"
	nodeservice "github.com/Suparluxi/j-ui/internal/node"
	"github.com/Suparluxi/j-ui/internal/problem"
	"github.com/Suparluxi/j-ui/internal/subscription"
	"github.com/Suparluxi/j-ui/internal/vpngate"
)

var Version = "0.4.39"

const countryLookupBaseURL = "https://ip.net.coffee/api/ip/lookup/"

type Dependencies struct {
	Store                  *database.Store
	Auth                   *auth.Service
	Nodes                  *nodeservice.Service
	VPNGate                *vpngate.Service
	Subscriptions          *subscription.Service
	Monitor                *monitor.Service
	MockMode               bool
	LiveMockIPInspection   bool
	VerifyHTTPSIngress     func(context.Context, string) error
	VerifyCloudflareTunnel func(context.Context, string, int) (int, error)
	Backup                 func(context.Context, string) error
	Restart                func(context.Context) error
	Update                 func(context.Context) error
}

type Handler struct {
	frontend fs.FS
	deps     Dependencies
	mux      *http.ServeMux
	settings sync.Mutex
}

type healthResponse struct {
	Status    string    `json:"status"`
	Version   string    `json:"version"`
	StartedAt time.Time `json:"startedAt"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

type sessionContextKey struct{}

type authenticatedSession struct {
	Token string
	CSRF  string
}

func NewHandler(frontend fs.FS, dependencies ...Dependencies) http.Handler {
	var deps Dependencies
	if len(dependencies) != 0 {
		deps = dependencies[0]
	}
	handler := &Handler{frontend: frontend, deps: deps, mux: http.NewServeMux()}
	handler.routes()
	return securityHeaders(validateAPIPathIDs(jsonMethodErrors(handler.mux)))
}

func (h *Handler) routes() {
	startedAt := time.Now().UTC()
	h.mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, healthResponse{Status: "ok", Version: Version, StartedAt: startedAt})
	})
	if h.deps.Store == nil {
		h.mux.Handle("/", http.FileServerFS(h.frontend))
		return
	}

	h.mux.HandleFunc("POST /api/v1/auth/login", h.login)
	h.mux.Handle("GET /api/v1/auth/session", h.requireAuth(http.HandlerFunc(h.session)))
	h.mux.Handle("POST /api/v1/auth/logout", h.requireAuth(http.HandlerFunc(h.logout)))
	h.mux.Handle("POST /api/v1/auth/password", h.requireAuth(http.HandlerFunc(h.changePassword)))

	h.mux.Handle("GET /api/v1/settings/public-host", h.requireAuth(http.HandlerFunc(h.getPublicHost)))
	h.mux.Handle("PUT /api/v1/settings/public-host", h.requireAuth(http.HandlerFunc(h.setPublicHost)))
	h.mux.Handle("GET /api/v1/settings/server-name", h.requireAuth(http.HandlerFunc(h.getServerName)))
	h.mux.Handle("PUT /api/v1/settings/server-name", h.requireAuth(http.HandlerFunc(h.setServerName)))
	h.mux.Handle("GET /api/v1/settings/country", h.requireAuth(http.HandlerFunc(h.getCountry)))
	h.mux.Handle("PUT /api/v1/settings/country", h.requireAuth(http.HandlerFunc(h.setCountry)))
	h.mux.HandleFunc("GET /api/v1/settings/language", h.getLanguage)
	h.mux.Handle("PUT /api/v1/settings/language", h.requireAuth(http.HandlerFunc(h.setLanguage)))
	h.mux.Handle("GET /api/v1/settings/node-start-port", h.requireAuth(http.HandlerFunc(h.getNodeStartPort)))
	h.mux.Handle("PUT /api/v1/settings/node-start-port", h.requireAuth(http.HandlerFunc(h.setNodeStartPort)))
	h.mux.Handle("GET /api/v1/settings/protocol-prerequisites", h.requireAuth(http.HandlerFunc(h.getProtocolPrerequisites)))
	h.mux.Handle("PUT /api/v1/settings/protocol-prerequisites", h.requireAuth(http.HandlerFunc(h.setProtocolPrerequisites)))
	h.mux.Handle("GET /api/v1/nodes", h.requireAuth(http.HandlerFunc(h.listNodes)))
	h.mux.Handle("POST /api/v1/nodes", h.requireAuth(http.HandlerFunc(h.createNode)))
	h.mux.Handle("GET /api/v1/nodes/{id}", h.requireAuth(http.HandlerFunc(h.getNode)))
	h.mux.Handle("PUT /api/v1/nodes/{id}", h.requireAuth(http.HandlerFunc(h.updateNode)))
	h.mux.Handle("DELETE /api/v1/nodes/{id}", h.requireAuth(http.HandlerFunc(h.deleteNode)))
	h.mux.Handle("POST /api/v1/nodes/{id}/enable", h.requireAuth(http.HandlerFunc(h.enableNode)))
	h.mux.Handle("POST /api/v1/nodes/{id}/disable", h.requireAuth(http.HandlerFunc(h.disableNode)))
	h.mux.Handle("POST /api/v1/nodes/{id}/clone", h.requireAuth(http.HandlerFunc(h.cloneNode)))
	h.mux.Handle("GET /api/v1/nodes/{id}/export", h.requireAuth(http.HandlerFunc(h.exportNode)))
	h.mux.Handle("GET /api/v1/nodes/{id}/clients", h.requireAuth(http.HandlerFunc(h.listClients)))
	h.mux.Handle("POST /api/v1/nodes/{id}/clients", h.requireAuth(http.HandlerFunc(h.createClient)))
	h.mux.Handle("PUT /api/v1/nodes/{id}/clients/{clientId}", h.requireAuth(http.HandlerFunc(h.updateClient)))
	h.mux.Handle("DELETE /api/v1/nodes/{id}/clients/{clientId}", h.requireAuth(http.HandlerFunc(h.deleteClient)))
	h.mux.Handle("POST /api/v1/nodes/{id}/clients/{clientId}/reset", h.requireAuth(http.HandlerFunc(h.resetClient)))
	h.mux.Handle("GET /api/v1/nodes/{id}/clients/{clientId}/export", h.requireAuth(http.HandlerFunc(h.exportClient)))
	h.mux.Handle("GET /api/v1/outbounds", h.requireAuth(http.HandlerFunc(h.listOutbounds)))
	h.mux.Handle("POST /api/v1/outbounds", h.requireAuth(http.HandlerFunc(h.createOutbound)))
	h.mux.Handle("PUT /api/v1/outbounds/{id}", h.requireAuth(http.HandlerFunc(h.updateOutbound)))
	h.mux.Handle("DELETE /api/v1/outbounds/{id}", h.requireAuth(http.HandlerFunc(h.deleteOutbound)))
	h.mux.Handle("POST /api/v1/outbounds/{id}/check", h.requireAuth(http.HandlerFunc(h.checkOutbound)))
	h.mux.Handle("GET /api/v1/vpngate/regions", h.requireAuth(http.HandlerFunc(h.vpnGateRegions)))
	h.mux.Handle("GET /api/v1/vpngate/nodes", h.requireAuth(http.HandlerFunc(h.vpnGateNodes)))
	h.mux.Handle("POST /api/v1/vpngate/inspect", h.requireAuth(http.HandlerFunc(h.inspectVPNGateIP)))
	h.mux.Handle("POST /api/v1/vpngate/refresh", h.requireAuth(http.HandlerFunc(h.refreshVPNGate)))
	h.mux.Handle("GET /api/v1/vpngate/outbounds", h.requireAuth(http.HandlerFunc(h.listVPNGateExits)))
	h.mux.Handle("POST /api/v1/vpngate/outbounds", h.requireAuth(http.HandlerFunc(h.createVPNGateExit)))
	h.mux.Handle("POST /api/v1/vpngate/outbounds/{id}/swap", h.requireAuth(http.HandlerFunc(h.swapVPNGateExit)))
	h.mux.Handle("POST /api/v1/vpngate/outbounds/{id}/extend", h.requireAuth(http.HandlerFunc(h.extendVPNGateExit)))
	h.mux.Handle("DELETE /api/v1/vpngate/outbounds/{id}", h.requireAuth(http.HandlerFunc(h.deleteVPNGateExit)))
	h.mux.Handle("POST /api/v1/residential-nodes/vpngate", h.requireAuth(http.HandlerFunc(h.createVPNGateResidentialNode)))
	h.mux.Handle("POST /api/v1/residential-nodes/manual", h.requireAuth(http.HandlerFunc(h.createManualResidentialNode)))
	h.mux.Handle("DELETE /api/v1/residential-nodes/{id}", h.requireAuth(http.HandlerFunc(h.deleteResidentialNode)))

	h.mux.Handle("GET /api/v1/subscription", h.requireAuth(http.HandlerFunc(h.subscriptionInfo)))
	h.mux.Handle("GET /api/v1/subscription/preview", h.requireAuth(http.HandlerFunc(h.subscriptionPreview)))
	h.mux.Handle("POST /api/v1/subscription/reset", h.requireAuth(http.HandlerFunc(h.resetSubscription)))
	// Use an explicit subtree route and parse the single token segment in the
	// handler. This keeps public subscriptions reachable on deployed systems
	// where wildcard ServeMux routes may otherwise fall through to the SPA.
	h.mux.HandleFunc("GET /sub/", h.renderSubscription)

	h.mux.Handle("GET /api/v1/system/status", h.requireAuth(http.HandlerFunc(h.systemStatus)))
	h.mux.Handle("GET /api/v1/system/info", h.requireAuth(http.HandlerFunc(h.systemInfo)))
	h.mux.Handle("GET /api/v1/system/logs", h.requireAuth(http.HandlerFunc(h.systemLogs)))
	h.mux.Handle("POST /api/v1/system/backup", h.requireAuth(http.HandlerFunc(h.systemBackup)))
	h.mux.Handle("POST /api/v1/system/update", h.requireAuth(http.HandlerFunc(h.update)))
	h.mux.Handle("GET /api/v1/events", h.requireAuth(http.HandlerFunc(h.events)))
	h.mux.Handle("POST /api/v1/system/restart", h.requireAuth(http.HandlerFunc(h.restart)))

	h.mux.HandleFunc("GET /", h.frontendFile)
}

func validateAPIPathIDs(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		residentialNodePath := strings.HasPrefix(r.URL.Path, "/api/v1/residential-nodes/") &&
			r.URL.Path != "/api/v1/residential-nodes/vpngate" &&
			r.URL.Path != "/api/v1/residential-nodes/manual"
		if strings.HasPrefix(r.URL.Path, "/api/v1/nodes/") ||
			strings.HasPrefix(r.URL.Path, "/api/v1/outbounds/") ||
			strings.HasPrefix(r.URL.Path, "/api/v1/vpngate/outbounds/") ||
			residentialNodePath {
			parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			indices := []int{3}
			if len(parts) > 3 && parts[2] == "vpngate" {
				indices = []int{4}
			}
			if len(parts) > 4 && parts[4] == "clients" && len(parts) > 5 {
				indices = append(indices, 5)
			}
			for _, index := range indices {
				if index >= len(parts) {
					continue
				}
				id, err := strconv.ParseInt(parts[index], 10, 64)
				if err != nil || id < 1 {
					writeError(w, http.StatusBadRequest, "invalid_id", "资源 ID 必须是正整数", nil)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

type methodErrorWriter struct {
	http.ResponseWriter
	replaced bool
}

func (w *methodErrorWriter) WriteHeader(status int) {
	if status != http.StatusMethodNotAllowed && status != http.StatusNotFound {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	w.replaced = true
	value := apiError{Code: "not_found", Message: "接口不存在"}
	if status == http.StatusMethodNotAllowed {
		value = apiError{Code: "method_not_allowed", Message: "请求方法不受支持"}
	}
	writeJSON(w.ResponseWriter, status, value)
}

func (w *methodErrorWriter) Write(content []byte) (int, error) {
	if w.replaced {
		return len(content), nil
	}
	return w.ResponseWriter.Write(content)
}

func (w *methodErrorWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func jsonMethodErrors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") &&
			!strings.HasPrefix(r.URL.Path, "/sub/") {
			next.ServeHTTP(w, r)
			return
		}
		if methods, known := apiAllowedMethods(r.URL.Path); known {
			allowed := false
			for _, method := range methods {
				if r.Method == method || (r.Method == http.MethodHead && method == http.MethodGet) {
					allowed = true
					break
				}
			}
			if !allowed {
				writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "请求方法不受支持", nil)
				return
			}
		}
		next.ServeHTTP(&methodErrorWriter{ResponseWriter: w}, r)
	})
}

func apiAllowedMethods(path string) ([]string, bool) {
	if strings.HasPrefix(path, "/sub/") {
		return []string{http.MethodGet}, true
	}
	static := map[string][]string{
		"/api/v1/health":                          {http.MethodGet},
		"/api/v1/auth/login":                      {http.MethodPost},
		"/api/v1/auth/session":                    {http.MethodGet},
		"/api/v1/auth/logout":                     {http.MethodPost},
		"/api/v1/auth/password":                   {http.MethodPost},
		"/api/v1/settings/public-host":            {http.MethodGet, http.MethodPut},
		"/api/v1/settings/server-name":            {http.MethodGet, http.MethodPut},
		"/api/v1/settings/country":                {http.MethodGet, http.MethodPut},
		"/api/v1/settings/language":               {http.MethodGet, http.MethodPut},
		"/api/v1/settings/node-start-port":        {http.MethodGet, http.MethodPut},
		"/api/v1/settings/protocol-prerequisites": {http.MethodGet, http.MethodPut},
		"/api/v1/subscription":                    {http.MethodGet},
		"/api/v1/subscription/preview":            {http.MethodGet},
		"/api/v1/subscription/reset":              {http.MethodPost},
		"/api/v1/system/status":                   {http.MethodGet},
		"/api/v1/system/info":                     {http.MethodGet},
		"/api/v1/system/logs":                     {http.MethodGet},
		"/api/v1/system/backup":                   {http.MethodPost},
		"/api/v1/system/update":                   {http.MethodPost},
		"/api/v1/system/restart":                  {http.MethodPost},
		"/api/v1/events":                          {http.MethodGet},
		"/api/v1/residential-nodes/vpngate":       {http.MethodPost},
		"/api/v1/residential-nodes/manual":        {http.MethodPost},
	}
	if methods, ok := static[path]; ok {
		return methods, true
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 4 && parts[0] == "api" && parts[1] == "v1" &&
		parts[2] == "residential-nodes" {
		return []string{http.MethodDelete}, true
	}
	if len(parts) >= 3 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "vpngate" {
		switch {
		case len(parts) == 4 && (parts[3] == "regions" || parts[3] == "nodes"):
			return []string{http.MethodGet}, true
		case len(parts) == 4 && parts[3] == "inspect":
			return []string{http.MethodPost}, true
		case len(parts) == 4 && parts[3] == "refresh":
			return []string{http.MethodPost}, true
		case len(parts) == 4 && parts[3] == "outbounds":
			return []string{http.MethodGet, http.MethodPost}, true
		case len(parts) == 5 && parts[3] == "outbounds":
			return []string{http.MethodDelete}, true
		case len(parts) == 6 && parts[3] == "outbounds" &&
			(parts[5] == "swap" || parts[5] == "extend"):
			return []string{http.MethodPost}, true
		}
		return nil, false
	}
	if len(parts) >= 3 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "outbounds" {
		if len(parts) == 3 {
			return []string{http.MethodGet, http.MethodPost}, true
		}
		if len(parts) == 4 {
			return []string{http.MethodPut, http.MethodDelete}, true
		}
		if len(parts) == 5 && parts[4] == "check" {
			return []string{http.MethodPost}, true
		}
		return nil, false
	}
	if len(parts) < 3 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "nodes" {
		return nil, false
	}
	switch len(parts) {
	case 3:
		return []string{http.MethodGet, http.MethodPost}, true
	case 4:
		return []string{http.MethodGet, http.MethodPut, http.MethodDelete}, true
	case 5:
		switch parts[4] {
		case "enable", "disable", "clone":
			return []string{http.MethodPost}, true
		case "export":
			return []string{http.MethodGet}, true
		case "clients":
			return []string{http.MethodGet, http.MethodPost}, true
		}
	case 6:
		if parts[4] == "clients" {
			return []string{http.MethodPut, http.MethodDelete}, true
		}
	case 7:
		if parts[4] == "clients" {
			switch parts[6] {
			case "reset":
				return []string{http.MethodPost}, true
			case "export":
				return []string{http.MethodGet}, true
			}
		}
	}
	return nil, false
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "origin_rejected", "请求来源不受信任", nil)
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	token, session, err := h.deps.Auth.Login(r.Context(), input.Username, input.Password, sourceIP(r))
	if err != nil {
		status := http.StatusUnauthorized
		code := "invalid_credentials"
		if errors.Is(err, auth.ErrLoginLimited) || h.deps.Auth.Limited(sourceIP(r)) {
			status, code = http.StatusTooManyRequests, "login_limited"
		}
		writeError(w, status, code, "用户名或密码错误", nil)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "jui_session", Value: token, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Expires: session.ExpiresAt, Secure: r.TLS != nil,
	})
	adminPath, _ := h.deps.Store.Setting(r.Context(), "admin_path")
	publicHost, _ := h.deps.Store.Setting(r.Context(), "public_host")
	username, _ := h.deps.Store.AdministratorUsername(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"username": username, "csrfToken": session.CSRFToken,
		"expiresAt": session.ExpiresAt, "adminPath": adminPath,
		"setupRequired":      publicHost == "",
		"defaultCredentials": h.defaultCredentials(r.Context()),
	})
}

func (h *Handler) session(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value(sessionContextKey{}).(authenticatedSession)
	adminPath, _ := h.deps.Store.Setting(r.Context(), "admin_path")
	publicHost, _ := h.deps.Store.Setting(r.Context(), "public_host")
	username, _ := h.deps.Store.AdministratorUsername(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"username": username, "csrfToken": session.CSRF,
		"adminPath": adminPath, "setupRequired": publicHost == "",
		"defaultCredentials": h.defaultCredentials(r.Context()),
	})
}

func (h *Handler) defaultCredentials(ctx context.Context) bool {
	username, err := h.deps.Store.AdministratorUsername(ctx)
	if err != nil || username != "admin" {
		return false
	}
	hash, err := h.deps.Store.PasswordHash(ctx, username)
	return err == nil && auth.VerifyPassword(hash, "admin")
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value(sessionContextKey{}).(authenticatedSession)
	_ = h.deps.Auth.Logout(r.Context(), session.Token)
	http.SetCookie(w, &http.Cookie{
		Name: "jui_session", Value: "", Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: -1, Secure: r.TLS != nil,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if err := h.deps.Auth.ChangePassword(r.Context(), input.CurrentPassword, input.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, "password_rejected", err.Error(), nil)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "jui_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) getPublicHost(w http.ResponseWriter, r *http.Request) {
	value, _ := h.deps.Store.Setting(r.Context(), "public_host")
	writeJSON(w, http.StatusOK, map[string]string{"publicHost": value})
}

func (h *Handler) setPublicHost(w http.ResponseWriter, r *http.Request) {
	var input struct {
		PublicHost string `json:"publicHost"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	host, err := normalizeHost(input.PublicHost)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_public_host", err.Error(), nil)
		return
	}
	if err := h.deps.Store.SetSetting(r.Context(), "public_host", host); err != nil {
		writeError(w, http.StatusInternalServerError, "setting_failed", "保存公网地址失败", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"publicHost": host})
}

func (h *Handler) getServerName(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"serverName": h.serverName(r.Context())})
}

func (h *Handler) setServerName(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ServerName string `json:"serverName"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	name, err := normalizeServerName(input.ServerName)
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", err.Error(), nil)
		return
	}
	if err := h.deps.Store.SetSetting(r.Context(), "server_name", name); err != nil {
		writeError(w, http.StatusInternalServerError, "setting_failed", "保存服务器名称失败", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"serverName": name})
}

func (h *Handler) serverName(ctx context.Context) string {
	if name, err := h.deps.Store.Setting(ctx, "server_name"); err == nil && strings.TrimSpace(name) != "" {
		return strings.TrimSpace(name)
	}
	return "J-UI"
}

func (h *Handler) getCountry(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"countryCode": h.countryCode(r.Context())})
}

func (h *Handler) setCountry(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CountryCode string `json:"countryCode"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	code, err := normalizeCountryCode(input.CountryCode)
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", err.Error(), nil)
		return
	}
	if err := h.deps.Store.SetSetting(r.Context(), "country_code", code); err != nil {
		writeError(w, http.StatusInternalServerError, "setting_failed", "保存国家失败", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"countryCode": code})
}

func (h *Handler) countryCode(ctx context.Context) string {
	if saved, err := h.deps.Store.Setting(ctx, "country_code"); err == nil {
		if code, normalizeErr := normalizeCountryCode(saved); normalizeErr == nil {
			return code
		}
	}
	if code, err := normalizeCountryCode(monitor.SystemInfo().CountryCode); err == nil {
		return code
	}
	if h.deps.MockMode {
		return ""
	}
	ip := h.countryLookupIP(ctx)
	if ip == nil {
		return ""
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, countryLookupBaseURL+ip.String(), nil)
	if err != nil {
		return ""
	}
	client := &http.Client{Timeout: 8 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return ""
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ""
	}
	var result struct {
		CountryCode string `json:"countryCode"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result); err != nil {
		return ""
	}
	code, err := normalizeCountryCode(result.CountryCode)
	if err != nil {
		return ""
	}
	_ = h.deps.Store.SetSetting(ctx, "country_code", code)
	return code
}

func (h *Handler) countryLookupIP(ctx context.Context) net.IP {
	if value, err := h.deps.Store.Setting(ctx, "public_host"); err == nil {
		if ip := net.ParseIP(strings.Trim(strings.TrimSpace(value), "[]")); ip != nil {
			return ip
		}
	}
	info := monitor.SystemInfo()
	if ip := net.ParseIP(info.IPv4); ip != nil && !ip.IsPrivate() {
		return ip
	}
	return nil
}

func normalizeCountryCode(value string) (string, error) {
	code := strings.ToUpper(strings.TrimSpace(value))
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return "", errors.New("国家必须使用两位 ISO 代码，例如 JP 或 SG")
	}
	return code, nil
}

func normalizeServerName(value string) (string, error) {
	name := strings.TrimSpace(value)
	if name == "" {
		return "", errors.New("服务器名称不能为空")
	}
	if len([]rune(name)) > 64 {
		return "", errors.New("服务器名称不能超过 64 个字符")
	}
	if strings.Contains(name, "丨") {
		return "", errors.New("服务器名称不能包含节点名称分隔符“丨”")
	}
	for _, character := range name {
		if unicode.IsControl(character) {
			return "", errors.New("服务器名称不能包含控制字符")
		}
	}
	return name, nil
}

func (h *Handler) getLanguage(w http.ResponseWriter, r *http.Request) {
	language, err := h.deps.Store.Setting(r.Context(), "ui_language")
	if err != nil || (language != "zh-CN" && language != "en") {
		language = "zh-CN"
	}
	writeJSON(w, http.StatusOK, map[string]string{"language": language})
}

func (h *Handler) setLanguage(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Language string `json:"language"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Language != "zh-CN" && input.Language != "en" {
		writeError(w, http.StatusBadRequest, "validation_failed", "界面语言只能是 zh-CN 或 en", nil)
		return
	}
	if err := h.deps.Store.SetSetting(r.Context(), "ui_language", input.Language); err != nil {
		writeError(w, http.StatusInternalServerError, "setting_failed", "保存界面语言失败", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"language": input.Language})
}

func (h *Handler) getNodeStartPort(w http.ResponseWriter, r *http.Request) {
	settings, err := h.deps.Nodes.PortSettings(r.Context())
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (h *Handler) setNodeStartPort(w http.ResponseWriter, r *http.Request) {
	var input struct {
		StartPort int `json:"startPort"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	settings, err := h.deps.Nodes.SetStartPort(r.Context(), input.StartPort)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

type protocolPrerequisites struct {
	HTTPSIngressEnabled     bool   `json:"httpsIngressEnabled"`
	HTTPSIngressDomain      string `json:"httpsIngressDomain"`
	HTTPSIngressVerifiedAt  string `json:"httpsIngressVerifiedAt,omitempty"`
	HTTPSIngressSimulated   bool   `json:"httpsIngressSimulated,omitempty"`
	CloudflareTunnelEnabled bool   `json:"cloudflareTunnelEnabled"`
	CloudflareTunnelDomain  string `json:"cloudflareTunnelDomain"`
	CloudflareOriginPort    int    `json:"cloudflareTunnelOriginPort,omitempty"`
	CloudflareVerifiedAt    string `json:"cloudflareTunnelVerifiedAt,omitempty"`
	CloudflareSimulated     bool   `json:"cloudflareTunnelSimulated,omitempty"`
	CertificateMode         string `json:"certificateMode"`
	CertificatePath         string `json:"certificatePath,omitempty"`
	CertificateKeyPath      string `json:"certificateKeyPath,omitempty"`
	CertificateReady        bool   `json:"certificateReady"`
	CertificateServerName   string `json:"certificateServerName,omitempty"`
}

type protocolPrerequisiteUpdate struct {
	Target     string `json:"target"`
	Action     string `json:"action"`
	Domain     string `json:"domain"`
	OriginPort int    `json:"originPort,omitempty"`
}

func (h *Handler) getProtocolPrerequisites(w http.ResponseWriter, r *http.Request) {
	settings, err := h.protocolPrerequisites(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "setting_failed", "读取协议前置配置失败", nil)
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (h *Handler) setProtocolPrerequisites(w http.ResponseWriter, r *http.Request) {
	h.settings.Lock()
	defer h.settings.Unlock()

	var input protocolPrerequisiteUpdate
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Target != "https" && input.Target != "cloudflare" {
		writeError(w, http.StatusBadRequest, "invalid_prerequisite_target", "请选择要配置的入口类型", nil)
		return
	}
	settings, err := h.protocolPrerequisites(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "setting_failed", "读取协议前置配置失败", nil)
		return
	}
	if input.Action == "clear" {
		inUse, inUseErr := h.protocolPrerequisiteInUse(r.Context(), input.Target)
		if inUseErr != nil {
			writeServiceError(w, inUseErr)
			return
		}
		if inUse {
			writeError(w, http.StatusConflict, "prerequisite_in_use", "请先停用依赖该配置的节点", nil)
			return
		}
		if input.Target == "https" {
			settings.HTTPSIngressEnabled = false
			settings.HTTPSIngressDomain = ""
			settings.HTTPSIngressVerifiedAt = ""
			settings.HTTPSIngressSimulated = false
		} else {
			settings.CloudflareTunnelEnabled = false
			settings.CloudflareTunnelDomain = ""
			settings.CloudflareOriginPort = 0
			settings.CloudflareVerifiedAt = ""
			settings.CloudflareSimulated = false
		}
	} else if input.Action == "verify" {
		domain, domainErr := normalizeHost(input.Domain)
		if domainErr != nil || net.ParseIP(domain) != nil || !strings.Contains(domain, ".") {
			writeError(w, http.StatusBadRequest, "invalid_prerequisite_domain", "必须填写有效的公网域名", nil)
			return
		}
		if input.Target == "cloudflare" && input.OriginPort != 0 &&
			(input.OriginPort < 1 || input.OriginPort > 65535) {
			writeError(w, http.StatusBadRequest, "invalid_origin_port", "Tunnel 本机入口端口必须在 1 到 65535 之间", nil)
			return
		}
		currentDomain := settings.CloudflareTunnelDomain
		if input.Target == "https" {
			currentDomain = settings.HTTPSIngressDomain
		}
		if currentDomain != "" && !strings.EqualFold(currentDomain, domain) {
			inUse, inUseErr := h.protocolPrerequisiteInUse(r.Context(), input.Target)
			if inUseErr != nil {
				writeServiceError(w, inUseErr)
				return
			}
			if inUse {
				writeError(w, http.StatusConflict, "prerequisite_in_use", "请先停用依赖旧域名的节点", nil)
				return
			}
		}
		cloudflareOriginPort := input.OriginPort
		if !h.deps.MockMode {
			var verifyErr error
			if input.Target == "https" {
				if h.deps.VerifyHTTPSIngress == nil {
					writeError(w, http.StatusInternalServerError, "prerequisite_check_unavailable", "当前安装未提供 HTTPS 入口检测器", nil)
					return
				}
				verifyErr = h.deps.VerifyHTTPSIngress(r.Context(), domain)
			} else {
				if h.deps.VerifyCloudflareTunnel == nil {
					writeError(w, http.StatusInternalServerError, "prerequisite_check_unavailable", "当前安装未提供 Tunnel 检测器", nil)
					return
				}
				cloudflareOriginPort, verifyErr = h.deps.VerifyCloudflareTunnel(r.Context(), domain, input.OriginPort)
			}
			if verifyErr != nil {
				writeError(w, http.StatusConflict, "prerequisite_check_failed", "配置尚未通过检测："+verifyErr.Error(), nil)
				return
			}
		}
		verifiedAt := time.Now().UTC().Format(time.RFC3339)
		if input.Target == "https" {
			settings.HTTPSIngressEnabled = true
			settings.HTTPSIngressDomain = domain
			settings.HTTPSIngressVerifiedAt = verifiedAt
			settings.HTTPSIngressSimulated = h.deps.MockMode
		} else {
			settings.CloudflareTunnelEnabled = true
			settings.CloudflareTunnelDomain = domain
			settings.CloudflareOriginPort = cloudflareOriginPort
			settings.CloudflareVerifiedAt = verifiedAt
			settings.CloudflareSimulated = h.deps.MockMode
		}
	} else {
		writeError(w, http.StatusBadRequest, "invalid_prerequisite_action", "配置动作必须是 verify 或 clear", nil)
		return
	}
	encoded, err := json.Marshal(settings)
	if err != nil || h.deps.Store.SetSetting(r.Context(), "protocol_prerequisites", string(encoded)) != nil {
		writeError(w, http.StatusInternalServerError, "setting_failed", "保存协议前置配置失败", nil)
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (h *Handler) protocolPrerequisites(ctx context.Context) (protocolPrerequisites, error) {
	var settings protocolPrerequisites
	value, err := h.deps.Store.Setting(ctx, "protocol_prerequisites")
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return settings, err
	}
	if value != "" {
		if err := json.Unmarshal([]byte(value), &settings); err != nil {
			return settings, err
		}
	}
	var certificateDefaults struct {
		Mode        string `json:"mode"`
		Certificate string `json:"certificatePath"`
		PrivateKey  string `json:"keyPath"`
	}
	if defaults, defaultsErr := h.deps.Store.Setting(ctx, "certificate_defaults"); defaultsErr == nil {
		if json.Unmarshal([]byte(defaults), &certificateDefaults) == nil {
			settings.CertificateMode = certificateDefaults.Mode
			settings.CertificatePath = certificateDefaults.Certificate
			settings.CertificateKeyPath = certificateDefaults.PrivateKey
		}
	}
	if settings.CertificateMode != "manual" {
		settings.CertificateMode = "auto"
		settings.CertificatePath = ""
		settings.CertificateKeyPath = ""
	}
	certificateHost, _ := h.deps.Store.Setting(ctx, "management_host")
	if certificateHost == "" {
		certificateHost = settings.HTTPSIngressDomain
	}
	if certificateHost == "" {
		certificateHost, _ = h.deps.Store.Setting(ctx, "public_host")
	}
	if certificateHost != "" {
		if settings.CertificateMode == "auto" {
			settings.CertificateReady = h.deps.Nodes.VerifyAutomaticCertificate(certificateHost) == nil
		} else {
			settings.CertificateReady = h.deps.Nodes.VerifyCertificate(certificateHost, settings.CertificatePath, settings.CertificateKeyPath) == nil
		}
		if settings.CertificateReady {
			settings.CertificateServerName = certificateHost
		}
	}
	// Legacy checkbox-only records were never verified and must not unlock protocols.
	if settings.HTTPSIngressVerifiedAt == "" || (!h.deps.MockMode && settings.HTTPSIngressSimulated) {
		settings.HTTPSIngressEnabled = false
	}
	if settings.CloudflareVerifiedAt == "" || (!h.deps.MockMode && settings.CloudflareSimulated) {
		settings.CloudflareTunnelEnabled = false
	}
	return settings, nil
}

func (h *Handler) requireProtocolPrerequisite(
	w http.ResponseWriter,
	ctx context.Context,
	protocol string,
	serverName string,
	nodePort int,
) bool {
	if h.deps.MockMode || (protocol != model.ProtocolVLESSWSTLS && protocol != model.ProtocolVLESSArgo) {
		return true
	}
	if protocol == model.ProtocolVLESSWSTLS && !model.CloudflareHTTPSPort(nodePort) {
		writeError(w, http.StatusConflict, "unsupported_websocket_port", "VLESS-WS 必须使用 Cloudflare 支持的 HTTPS 端口：443、2053、2083、2087、2096 或 8443", nil)
		return false
	}
	settings, err := h.protocolPrerequisites(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "setting_failed", "读取协议前置配置失败", nil)
		return false
	}
	expectedDomain := settings.HTTPSIngressDomain
	missingMessage := "VLESS-WS 需要先验证 HTTPS 入口域名"
	if protocol == model.ProtocolVLESSArgo {
		expectedDomain = settings.CloudflareTunnelDomain
		missingMessage = "Argo 需要先验证 Cloudflare Tunnel 域名"
	}
	enabled := settings.HTTPSIngressEnabled
	if protocol == model.ProtocolVLESSArgo {
		enabled = settings.CloudflareTunnelEnabled
	}
	if !enabled || expectedDomain == "" {
		writeError(w, http.StatusConflict, "protocol_prerequisite_missing", missingMessage, nil)
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(serverName), expectedDomain) {
		writeError(w, http.StatusConflict, "protocol_domain_mismatch", "节点域名必须与已验证的前置配置域名一致", nil)
		return false
	}
	var verifyErr error
	if protocol == model.ProtocolVLESSArgo {
		if h.deps.VerifyCloudflareTunnel == nil {
			writeError(w, http.StatusInternalServerError, "prerequisite_check_unavailable", "当前安装未提供 Tunnel 检测器", nil)
			return false
		}
		var originPort int
		originPort, verifyErr = h.deps.VerifyCloudflareTunnel(ctx, expectedDomain, settings.CloudflareOriginPort)
		if verifyErr == nil && originPort != nodePort {
			writeError(w, http.StatusConflict, "tunnel_origin_mismatch", fmt.Sprintf("Argo 监听端口必须与 Tunnel 本机入口端口 %d 一致", originPort), nil)
			return false
		}
	} else {
		if h.deps.VerifyHTTPSIngress == nil {
			writeError(w, http.StatusInternalServerError, "prerequisite_check_unavailable", "当前安装未提供 HTTPS 入口检测器", nil)
			return false
		}
		verifyErr = h.deps.VerifyHTTPSIngress(ctx, expectedDomain)
	}
	if verifyErr != nil {
		if protocol == model.ProtocolVLESSArgo {
			settings.CloudflareTunnelEnabled = false
			settings.CloudflareOriginPort = 0
			settings.CloudflareVerifiedAt = ""
		} else {
			settings.HTTPSIngressEnabled = false
			settings.HTTPSIngressVerifiedAt = ""
		}
		if encoded, marshalErr := json.Marshal(settings); marshalErr == nil {
			_ = h.deps.Store.SetSetting(context.WithoutCancel(ctx), "protocol_prerequisites", string(encoded))
		}
		writeError(w, http.StatusConflict, "prerequisite_check_failed", "前置配置已失效，请重新检测："+verifyErr.Error(), nil)
		return false
	}
	return true
}

func (h *Handler) protocolPrerequisiteInUse(ctx context.Context, target string) (bool, error) {
	protocol := model.ProtocolVLESSArgo
	if target == "https" {
		protocol = model.ProtocolVLESSWSTLS
	}
	nodes, err := h.deps.Nodes.List(ctx)
	if err != nil {
		return false, err
	}
	for _, node := range nodes {
		if node.Enabled && node.Protocol == protocol {
			return true, nil
		}
	}
	return false, nil
}

func nodeServerName(settings map[string]any) string {
	value, _ := settings["server_name"].(string)
	return strings.TrimSpace(value)
}

func (h *Handler) listNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := h.deps.Nodes.List(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nodes)
}

func (h *Handler) listOutbounds(w http.ResponseWriter, r *http.Request) {
	outbounds, err := h.deps.Nodes.ListOutbounds(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, outbounds)
}

func (h *Handler) createOutbound(w http.ResponseWriter, r *http.Request) {
	var input nodeservice.OutboundInput
	if !decodeJSON(w, r, &input) {
		return
	}
	outbound, err := h.deps.Nodes.CreateOutbound(r.Context(), input)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, outbound)
}

func (h *Handler) updateOutbound(w http.ResponseWriter, r *http.Request) {
	var input nodeservice.OutboundInput
	if !decodeJSON(w, r, &input) {
		return
	}
	outbound, err := h.deps.Nodes.UpdateOutbound(r.Context(), pathID(r, "id"), input)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, outbound)
}

func (h *Handler) deleteOutbound(w http.ResponseWriter, r *http.Request) {
	if err := h.deps.Nodes.DeleteOutbound(r.Context(), pathID(r, "id")); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) checkOutbound(w http.ResponseWriter, r *http.Request) {
	outbound, err := h.deps.Nodes.CheckOutbound(r.Context(), pathID(r, "id"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, outbound)
}

func (h *Handler) vpnGateRegions(w http.ResponseWriter, r *http.Request) {
	regions, err := h.deps.VPNGate.Regions(r.Context(), vpngate.Filter{})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, regions)
}

func (h *Handler) vpnGateNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := h.deps.VPNGate.Candidates(r.Context(), vpngate.Filter{
		Country: r.URL.Query().Get("country"),
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nodes)
}

func (h *Handler) inspectVPNGateIP(w http.ResponseWriter, r *http.Request) {
	var input struct {
		HostName string `json:"hostName"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	hostName := strings.TrimSpace(input.HostName)
	if hostName == "" {
		writeError(w, http.StatusBadRequest, "validation_failed", "请选择 VPNGate IP 后再检测", nil)
		return
	}
	// The local mock engine must remain usable when the development machine has
	// no outbound access to the public IP information provider. Production mode
	// always performs the real lookup through the VPNGate service inspector.
	if h.deps.MockMode && !h.deps.LiveMockIPInspection {
		candidate, err := h.deps.Store.VPNGateCandidate(r.Context(), hostName)
		if err != nil {
			writeServiceError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, vpngate.MockInspection(candidate))
		return
	}
	inspection, err := h.deps.VPNGate.Inspect(r.Context(), hostName)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, inspection)
}

func (h *Handler) refreshVPNGate(w http.ResponseWriter, r *http.Request) {
	candidates, err := h.deps.VPNGate.Refresh(r.Context())
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(candidates)})
}

func (h *Handler) listVPNGateExits(w http.ResponseWriter, r *http.Request) {
	exits, err := h.deps.VPNGate.Exits(r.Context())
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, exits)
}

func (h *Handler) createVPNGateExit(w http.ResponseWriter, r *http.Request) {
	var input vpngate.CreateInput
	if !decodeJSON(w, r, &input) {
		return
	}
	exit, err := h.deps.VPNGate.Create(r.Context(), input)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, exit)
}

func (h *Handler) swapVPNGateExit(w http.ResponseWriter, r *http.Request) {
	exit, err := h.deps.VPNGate.Swap(r.Context(), pathID(r, "id"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, exit)
}

func (h *Handler) extendVPNGateExit(w http.ResponseWriter, r *http.Request) {
	var input vpngate.ExtendInput
	if !decodeJSON(w, r, &input) {
		return
	}
	exit, err := h.deps.VPNGate.Extend(r.Context(), pathID(r, "id"), input)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, exit)
}

func (h *Handler) deleteVPNGateExit(w http.ResponseWriter, r *http.Request) {
	if err := h.deps.VPNGate.Delete(r.Context(), pathID(r, "id")); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type residentialVPNGateInput struct {
	NodeID            int64  `json:"nodeId"`
	Country           string `json:"country"`
	CandidateHostName string `json:"candidateHostName"`
	DurationMinutes   int    `json:"durationMinutes"`
	Permanent         bool   `json:"permanent"`
	FailurePolicy     string `json:"failurePolicy"`
	// Deprecated: retained for API compatibility; candidate filtering is no longer applied.
	MaxPing      int `json:"maxPing,omitempty"`
	MinSpeedMbps int `json:"minSpeedMbps,omitempty"`
	MaxSessions  int `json:"maxSessions,omitempty"`
}

type residentialManualInput struct {
	NodeID          int64  `json:"nodeId"`
	Type            string `json:"type"`
	Server          string `json:"server"`
	Port            int    `json:"port"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	DurationMinutes int    `json:"durationMinutes"` // Accepted for compatibility; manual nodes are permanent.
}

func (h *Handler) createVPNGateResidentialNode(w http.ResponseWriter, r *http.Request) {
	var input residentialVPNGateInput
	if !decodeJSON(w, r, &input) {
		return
	}
	h.settings.Lock()
	defer h.settings.Unlock()
	sourceNode, err := h.deps.Nodes.Get(r.Context(), input.NodeID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if sourceNode.Protocol == model.ProtocolVLESSArgo {
		writeError(w, http.StatusConflict, "unsupported_residential_protocol", "Argo 绑定固定 Tunnel 端口，不能作为临时住宅节点模板", nil)
		return
	}
	if !h.requireProtocolPrerequisite(w, r.Context(), sourceNode.Protocol, nodeServerName(sourceNode.Settings), sourceNode.Port) {
		return
	}
	exit, reused, err := h.runningVPNGateExit(r.Context(), input.CandidateHostName)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if !reused {
		exitName := "住宅节点-" + sourceNode.Name
		exit, err = h.deps.VPNGate.Create(r.Context(), vpngate.CreateInput{
			Name: exitName, Country: input.Country, CandidateHostName: input.CandidateHostName,
			DurationMinutes: input.DurationMinutes, Permanent: input.Permanent, FailurePolicy: input.FailurePolicy,
		})
		if err != nil {
			if exit.ID != 0 {
				_ = h.deps.VPNGate.Delete(context.WithoutCancel(r.Context()), exit.ID)
			}
			writeServiceError(w, err)
			return
		}
	}
	name := residentialNodeName(h.serverName(r.Context()), sourceNode.Protocol, "vpngate", exit.Country)
	node, err := h.deps.Nodes.CloneTemporary(
		r.Context(), sourceNode.ID, name, exit.OutboundID, exit.ExpiresAt, "vpngate", exit.Country,
	)
	if err != nil {
		if !reused {
			_ = h.deps.VPNGate.Delete(context.WithoutCancel(r.Context()), exit.ID)
		}
		writeServiceError(w, err)
		return
	}
	uri, err := h.deps.Subscriptions.NodeURI(r.Context(), node.ID)
	if err != nil {
		_ = h.deps.Nodes.Delete(context.WithoutCancel(r.Context()), node.ID)
		if !reused {
			_ = h.deps.VPNGate.Delete(context.WithoutCancel(r.Context()), exit.ID)
		}
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"node": node, "uri": uri, "source": "vpngate", "country": exit.Country,
		"exitId": exit.ID, "expiresAt": exit.ExpiresAt, "reusedExit": reused,
	})
}

func (h *Handler) runningVPNGateExit(ctx context.Context, candidateHostName string) (model.VPNGateExit, bool, error) {
	candidateHostName = strings.TrimSpace(candidateHostName)
	if candidateHostName == "" {
		return model.VPNGateExit{}, false, nil
	}
	exits, err := h.deps.VPNGate.Exits(ctx)
	if err != nil {
		return model.VPNGateExit{}, false, err
	}
	for _, exit := range exits {
		if exit.CandidateHostName == candidateHostName && exit.Status == "running" &&
			(exit.ExpiresAt == nil || exit.ExpiresAt.After(time.Now().UTC())) {
			return exit, true, nil
		}
	}
	return model.VPNGateExit{}, false, nil
}

func (h *Handler) createManualResidentialNode(w http.ResponseWriter, r *http.Request) {
	var input residentialManualInput
	if !decodeJSON(w, r, &input) {
		return
	}
	h.settings.Lock()
	defer h.settings.Unlock()
	sourceNode, err := h.deps.Nodes.Get(r.Context(), input.NodeID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if sourceNode.Protocol == model.ProtocolVLESSArgo {
		writeError(w, http.StatusConflict, "unsupported_residential_protocol", "Argo 绑定固定 Tunnel 端口，不能作为临时住宅节点模板", nil)
		return
	}
	if !h.requireProtocolPrerequisite(w, r.Context(), sourceNode.Protocol, nodeServerName(sourceNode.Settings), sourceNode.Port) {
		return
	}
	outbound, err := h.deps.Nodes.CreateOutbound(r.Context(), nodeservice.OutboundInput{
		Name: "住宅节点-" + sourceNode.Name, Type: input.Type, Server: input.Server,
		Port: input.Port, Enabled: true, Username: input.Username, Password: input.Password,
		CredentialMode: "replace",
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if _, err := h.deps.Nodes.CheckOutbound(r.Context(), outbound.ID); err != nil {
		_ = h.deps.Nodes.DeleteOutbound(context.WithoutCancel(r.Context()), outbound.ID)
		writeServiceError(w, err)
		return
	}
	node, err := h.deps.Nodes.CloneTemporary(
		r.Context(), sourceNode.ID, residentialNodeName(h.serverName(r.Context()), sourceNode.Protocol, "manual", ""),
		outbound.ID, nil, "manual", "",
	)
	if err != nil {
		_ = h.deps.Nodes.DeleteOutbound(context.WithoutCancel(r.Context()), outbound.ID)
		writeServiceError(w, err)
		return
	}
	uri, err := h.deps.Subscriptions.NodeURI(r.Context(), node.ID)
	if err != nil {
		_ = h.deps.Nodes.Delete(context.WithoutCancel(r.Context()), node.ID)
		_ = h.deps.Nodes.DeleteOutbound(context.WithoutCancel(r.Context()), outbound.ID)
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"node": node, "uri": uri, "source": "manual", "permanent": true,
	})
}

func (h *Handler) deleteResidentialNode(w http.ResponseWriter, r *http.Request) {
	node, err := h.deps.Nodes.Get(r.Context(), pathID(r, "id"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	source := nodeservice.TemporarySource(node)
	if source == "" || node.OutboundID == nil {
		writeError(w, http.StatusConflict, "not_temporary_node", "该节点不是住宅 IP 临时节点", nil)
		return
	}
	var exitID int64
	if source == "vpngate" {
		exits, listErr := h.deps.VPNGate.Exits(r.Context())
		if listErr != nil {
			writeServiceError(w, listErr)
			return
		}
		for _, exit := range exits {
			if exit.OutboundID == *node.OutboundID {
				exitID = exit.ID
				break
			}
		}
	}
	if err := h.deps.Nodes.Delete(r.Context(), node.ID); err != nil {
		writeServiceError(w, err)
		return
	}
	remaining, listErr := h.deps.Nodes.List(context.WithoutCancel(r.Context()))
	if listErr != nil {
		writeServiceError(w, listErr)
		return
	}
	stillUsed := false
	for _, current := range remaining {
		if current.OutboundID != nil && *current.OutboundID == *node.OutboundID {
			stillUsed = true
			break
		}
	}
	if !stillUsed {
		if source == "vpngate" && exitID != 0 {
			err = h.deps.VPNGate.Delete(context.WithoutCancel(r.Context()), exitID)
		} else {
			err = h.deps.Nodes.DeleteOutbound(context.WithoutCancel(r.Context()), *node.OutboundID)
		}
	}
	if err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func residentialNodeName(serverName, protocol, source, country string) string {
	prefix := strings.TrimSpace(serverName) + "丨S"
	if source == "vpngate" {
		prefix += "-" + strings.ToUpper(strings.TrimSpace(country))
	}
	return prefix + "丨" + residentialProtocolLabel(protocol) + "_0"
}

func residentialProtocolLabel(protocol string) string {
	labels := map[string]string{
		"vless_reality":      "XTLS-Reality",
		"vless_grpc_reality": "gRPC-Reality", "vless_ws_tls": "VLESS-WS",
		"vless_argo": "Argo", "trojan_tls": "Trojan", "hysteria2": "Hysteria2",
		"tuic": "TUIC", "anytls": "AnyTLS", "anytls_reality": "AnyTLS-Reality",
		"naive": "Naive",
	}
	if label := labels[protocol]; label != "" {
		return label
	}
	return protocol
}

func (h *Handler) createNode(w http.ResponseWriter, r *http.Request) {
	var input nodeservice.CreateInput
	if !decodeJSON(w, r, &input) {
		return
	}
	h.settings.Lock()
	defer h.settings.Unlock()
	if !h.requireProtocolPrerequisite(w, r.Context(), input.Protocol, nodeServerName(input.Settings), input.Port) {
		return
	}
	node, err := h.deps.Nodes.Create(r.Context(), input)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, node)
}

func (h *Handler) getNode(w http.ResponseWriter, r *http.Request) {
	node, err := h.deps.Nodes.Get(r.Context(), pathID(r, "id"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, node)
}

func (h *Handler) updateNode(w http.ResponseWriter, r *http.Request) {
	var input nodeservice.UpdateInput
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Enabled {
		h.settings.Lock()
		defer h.settings.Unlock()
		current, err := h.deps.Nodes.Get(r.Context(), pathID(r, "id"))
		if err != nil {
			writeServiceError(w, err)
			return
		}
		if !h.requireProtocolPrerequisite(w, r.Context(), current.Protocol, nodeServerName(input.Settings), input.Port) {
			return
		}
	}
	node, err := h.deps.Nodes.Update(r.Context(), pathID(r, "id"), input)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, node)
}

func (h *Handler) deleteNode(w http.ResponseWriter, r *http.Request) {
	if err := h.deps.Nodes.Delete(r.Context(), pathID(r, "id")); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) enableNode(w http.ResponseWriter, r *http.Request) {
	h.setNodeEnabled(w, r, true)
}

func (h *Handler) disableNode(w http.ResponseWriter, r *http.Request) {
	h.setNodeEnabled(w, r, false)
}

func (h *Handler) setNodeEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	if enabled {
		h.settings.Lock()
		defer h.settings.Unlock()
		current, err := h.deps.Nodes.Get(r.Context(), pathID(r, "id"))
		if err != nil {
			writeServiceError(w, err)
			return
		}
		if !h.requireProtocolPrerequisite(w, r.Context(), current.Protocol, nodeServerName(current.Settings), current.Port) {
			return
		}
	}
	node, err := h.deps.Nodes.SetEnabled(r.Context(), pathID(r, "id"), enabled)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, node)
}

func (h *Handler) cloneNode(w http.ResponseWriter, r *http.Request) {
	node, err := h.deps.Nodes.Clone(r.Context(), pathID(r, "id"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, node)
}

func (h *Handler) exportNode(w http.ResponseWriter, r *http.Request) {
	uri, err := h.deps.Subscriptions.NodeURI(r.Context(), pathID(r, "id"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"uri": uri})
}

func (h *Handler) exportClient(w http.ResponseWriter, r *http.Request) {
	uri, err := h.deps.Subscriptions.ClientURI(
		r.Context(), pathID(r, "id"), pathID(r, "clientId"),
	)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"uri": uri})
}

func (h *Handler) listClients(w http.ResponseWriter, r *http.Request) {
	clients, err := h.deps.Nodes.Clients(r.Context(), pathID(r, "id"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, clients)
}

func (h *Handler) createClient(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	client, err := h.deps.Nodes.AddClient(r.Context(), pathID(r, "id"), input.Name)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, client)
}

func (h *Handler) updateClient(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	err := h.deps.Nodes.UpdateClient(
		r.Context(), pathID(r, "id"), pathID(r, "clientId"), input.Name, input.Enabled, false,
	)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) resetClient(w http.ResponseWriter, r *http.Request) {
	clients, err := h.deps.Nodes.Clients(r.Context(), pathID(r, "id"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	clientID := pathID(r, "clientId")
	for _, client := range clients {
		if client.ID == clientID {
			err = h.deps.Nodes.UpdateClient(r.Context(), client.NodeID, client.ID, client.Name, client.Enabled, true)
			if err != nil {
				writeServiceError(w, err)
				return
			}
			uri, err := h.deps.Subscriptions.ClientURI(r.Context(), client.NodeID, client.ID)
			if err != nil {
				writeServiceError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"uri": uri})
			return
		}
	}
	writeError(w, http.StatusNotFound, "not_found", "客户端不存在", nil)
}

func (h *Handler) deleteClient(w http.ResponseWriter, r *http.Request) {
	err := h.deps.Nodes.DeleteClient(r.Context(), pathID(r, "id"), pathID(r, "clientId"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) subscriptionInfo(w http.ResponseWriter, r *http.Request) {
	token, err := h.deps.Subscriptions.CurrentToken(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"token": token, "base64Path": "/sub/" + token + "?format=base64",
		"v2rayNPath":       "/sub/" + token + "?format=v2rayn",
		"shadowrocketPath": "/sub/" + token + "?format=shadowrocket",
		"clashPath":        "/sub/" + token + "?format=clash",
		"singBoxPath":      "/sub/" + token + "?format=singbox",
	})
}

func (h *Handler) resetSubscription(w http.ResponseWriter, r *http.Request) {
	token, err := h.deps.Subscriptions.ResetToken(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (h *Handler) subscriptionPreview(w http.ResponseWriter, r *http.Request) {
	preview, err := h.deps.Subscriptions.Preview(r.Context(), r.URL.Query().Get("format"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (h *Handler) renderSubscription(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/sub/")
	if token == "" || strings.Contains(token, "/") {
		writeError(w, http.StatusNotFound, "not_found", "订阅不存在", nil)
		return
	}
	body, contentType, err := h.deps.Subscriptions.Render(r.Context(), token, r.URL.Query().Get("format"))
	if err != nil {
		if database.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "订阅不存在", nil)
			return
		}
		writeServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", contentType)
	filename := "j-ui-subscription.txt"
	if r.URL.Query().Get("format") == "clash" {
		filename = "j-ui-subscription.yaml"
	} else if r.URL.Query().Get("format") == "singbox" {
		filename = "j-ui-subscription.json"
	} else if format := r.URL.Query().Get("format"); format == "v2rayn" || format == "shadowrocket" {
		filename = "j-ui-" + format + ".txt"
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Profile-Update-Interval", "24")
	_, _ = w.Write(body)
}

func (h *Handler) systemStatus(w http.ResponseWriter, r *http.Request) {
	status, err := h.deps.Monitor.Snapshot(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (h *Handler) systemInfo(w http.ResponseWriter, r *http.Request) {
	info := monitor.SystemInfo()
	if code := h.countryCode(r.Context()); code != "" {
		info.CountryCode = code
	}
	info.MockMode = h.deps.MockMode
	writeJSON(w, http.StatusOK, info)
}

func (h *Handler) systemLogs(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if requested, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && requested >= 1 && requested <= 500 {
		limit = requested
	}
	output, err := exec.CommandContext(
		r.Context(), "journalctl", "-u", "j-ui.service", "-u", "j-ui-sing-box.service",
		"-u", "jui-vpngate-*",
		"--no-pager", "-n", strconv.Itoa(limit), "-o", "short-iso",
	).CombinedOutput()
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"logs": string(output)})
}

func (h *Handler) systemBackup(w http.ResponseWriter, r *http.Request) {
	if h.deps.Backup == nil {
		writeError(w, http.StatusConflict, "operation_unavailable", "当前运行模式不支持备份", nil)
		return
	}
	directory, err := os.MkdirTemp("", "j-ui-web-backup-*")
	if err != nil {
		writeInternal(w, err)
		return
	}
	defer os.RemoveAll(directory)
	path := filepath.Join(directory, "j-ui-backup.tar.gz")
	if err := h.deps.Backup(r.Context(), path); err != nil {
		_ = h.deps.Store.RecordEvent(r.Context(), "error", "backup_failed", "备份生成失败，未提供不完整文件")
		writeInternal(w, fmt.Errorf("backup failed: %w", err))
		return
	}
	_ = h.deps.Store.RecordEvent(r.Context(), "info", "backup_created", "数据库、配置和实例密钥备份已生成")
	file, err := os.Open(path)
	if err != nil {
		writeInternal(w, err)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		writeInternal(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="j-ui-backup.tar.gz"`)
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, "j-ui-backup.tar.gz", info.ModTime(), file)
}

func (h *Handler) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "stream_unsupported", "服务器不支持事件流", nil)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	authenticated := r.Context().Value(sessionContextKey{}).(authenticatedSession)
	for {
		if _, err := h.deps.Auth.Authenticate(r.Context(), authenticated.Token); err != nil {
			return
		}
		snapshot, err := h.deps.Monitor.Snapshot(r.Context())
		if err == nil {
			payload, _ := json.Marshal(snapshot)
			_, _ = fmt.Fprintf(w, "event: status\ndata: %s\n\n", payload)
			flusher.Flush()
		}
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

func (h *Handler) restart(w http.ResponseWriter, r *http.Request) {
	if h.deps.Restart == nil {
		writeError(w, http.StatusConflict, "operation_unavailable", "当前运行模式不支持重启", nil)
		return
	}
	if err := h.deps.Restart(r.Context()); err != nil {
		_ = h.deps.Store.RecordEvent(r.Context(), "warning", "restart_failed", "J-UI 重启任务提交失败")
		writeError(w, http.StatusConflict, "operation_failed", "无法提交重启任务", err.Error())
		return
	}
	_ = h.deps.Store.RecordEvent(r.Context(), "info", "restart_queued", "J-UI 重启任务已提交")
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	if h.deps.Update == nil {
		writeError(w, http.StatusConflict, "operation_unavailable", "当前运行模式不支持更新", nil)
		return
	}
	if err := h.deps.Update(r.Context()); err != nil {
		_ = h.deps.Store.RecordEvent(r.Context(), "warning", "update_failed", "在线更新任务提交失败")
		writeError(w, http.StatusConflict, "operation_failed", "无法提交更新任务", err.Error())
		return
	}
	_ = h.deps.Store.RecordEvent(r.Context(), "info", "update_queued", "在线更新任务已提交，更新前将自动备份")
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

func (h *Handler) frontendFile(w http.ResponseWriter, r *http.Request) {
	adminPath, err := h.deps.Store.Setting(r.Context(), "admin_path")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	prefix := "/" + adminPath
	if r.URL.Path == prefix {
		http.Redirect(w, r, prefix+"/", http.StatusTemporaryRedirect)
		return
	}
	if !strings.HasPrefix(r.URL.Path, prefix+"/") {
		http.NotFound(w, r)
		return
	}
	http.StripPrefix(prefix, http.FileServerFS(h.frontend)).ServeHTTP(w, r)
}

func (h *Handler) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("jui_session")
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "请先登录", nil)
			return
		}
		session, err := h.deps.Auth.Authenticate(r.Context(), cookie.Value)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "会话无效或已过期", nil)
			return
		}
		if unsafeMethod(r.Method) && r.Header.Get("X-CSRF-Token") != session.CSRFToken {
			writeError(w, http.StatusForbidden, "csrf_rejected", "CSRF 校验失败", nil)
			return
		}
		ctx := context.WithValue(r.Context(), sessionContextKey{}, authenticatedSession{
			Token: cookie.Value, CSRF: session.CSRFToken,
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "请求内容无效", err.Error())
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_json", "请求内容只能包含一个 JSON 对象", nil)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string, details any) {
	writeJSON(w, status, apiError{Code: code, Message: message, Details: details})
}

func writeInternal(w http.ResponseWriter, _ error) {
	writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误", nil)
}

func writeServiceError(w http.ResponseWriter, err error) {
	if value, ok := problem.As(err); ok {
		switch value.Kind {
		case problem.Validation:
			writeError(w, http.StatusBadRequest, value.Code, value.Message, nil)
		case problem.NotFound:
			writeError(w, http.StatusNotFound, value.Code, value.Message, nil)
		case problem.Conflict:
			writeError(w, http.StatusConflict, value.Code, value.Message, nil)
		case problem.Unavailable:
			writeError(w, http.StatusBadGateway, value.Code, value.Message, nil)
		default:
			writeInternal(w, err)
		}
		return
	}
	switch {
	case database.IsConflict(err):
		writeError(w, http.StatusConflict, "resource_conflict", "资源冲突", nil)
	case database.IsNotFound(err), errors.Is(err, sql.ErrNoRows):
		writeError(w, http.StatusNotFound, "not_found", "资源不存在", nil)
	default:
		writeInternal(w, err)
	}
}

func pathID(r *http.Request, name string) int64 {
	value, _ := strconv.ParseInt(r.PathValue(name), 10, 64)
	return value
}

func sourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(strings.TrimSpace(host))
	if peer == nil || !peer.IsLoopback() {
		return host
	}
	if candidate := xForwardedForIP(r.Header.Get("X-Forwarded-For")); candidate != "" {
		return candidate
	}
	return host
}

func xForwardedForIP(value string) string {
	parts := strings.Split(value, ",")
	for index := len(parts) - 1; index >= 0; index-- {
		if candidate := normalizedForwardedIP(parts[index]); candidate != "" &&
			!net.ParseIP(candidate).IsLoopback() {
			return candidate
		}
	}
	return ""
}

func normalizedForwardedIP(value string) string {
	value = strings.Trim(strings.TrimSpace(value), `"`)
	if value == "" || strings.EqualFold(value, "unknown") || strings.HasPrefix(value, "_") {
		return ""
	}
	if strings.HasPrefix(value, "[") {
		closeBracket := strings.IndexByte(value, ']')
		if closeBracket < 0 {
			return ""
		}
		value = value[1:closeBracket]
	} else if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return ""
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	return origin == "http://"+r.Host || origin == "https://"+r.Host
}

func unsafeMethod(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func normalizeHost(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "://") || strings.ContainsAny(value, "/?#@") {
		return "", errors.New("公网地址必须是域名或 IP，不能包含协议和路径")
	}
	value = strings.TrimPrefix(strings.TrimSuffix(value, "]"), "[")
	if ip := net.ParseIP(value); ip != nil {
		if ip.To4() == nil {
			return "", errors.New("公网地址只允许使用 IPv4 或域名，不支持 IPv6")
		}
		return ip.String(), nil
	}
	if len(value) > 253 || strings.Contains(value, ":") {
		return "", errors.New("公网地址格式无效")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("域名格式无效")
		}
		for _, character := range label {
			if !((character >= 'a' && character <= 'z') ||
				(character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') || character == '-') {
				return "", errors.New("域名只能包含字母、数字、点和连字符")
			}
		}
	}
	return strings.ToLower(value), nil
}
