package api

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestHealth(t *testing.T) {
	handler := NewHandler(fstest.MapFS{
		"index.html": {Data: []byte("J-UI")},
	})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}

	var body healthResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Status != "ok" || body.Version == "" || body.StartedAt.IsZero() {
		t.Fatalf("unexpected response: %+v", body)
	}
}

func TestSourceIPOnlyTrustsForwardingHeadersFromLoopback(t *testing.T) {
	direct := httptest.NewRequest(http.MethodGet, "/", nil)
	direct.RemoteAddr = "198.51.100.10:1234"
	direct.Header.Set("X-Forwarded-For", "203.0.113.99")
	if got := sourceIP(direct); got != "198.51.100.10" {
		t.Fatalf("direct source = %q", got)
	}
	proxied := httptest.NewRequest(http.MethodGet, "/", nil)
	proxied.RemoteAddr = "127.0.0.1:1234"
	proxied.Header.Set("X-Forwarded-For", "203.0.113.99, 198.51.100.20")
	if got := sourceIP(proxied); got != "198.51.100.20" {
		t.Fatalf("proxied XFF source = %q", got)
	}
	proxied.Header.Set("Forwarded", `for=203.0.113.30`)
	if got := sourceIP(proxied); got != "198.51.100.20" {
		t.Fatalf("spoofed Forwarded header overrode proxy XFF: %q", got)
	}
}

func TestFrontend(t *testing.T) {
	var frontend fs.FS = fstest.MapFS{
		"index.html": {Data: []byte("J-UI")},
	}
	response := httptest.NewRecorder()

	NewHandler(frontend).ServeHTTP(
		response,
		httptest.NewRequest(http.MethodGet, "/", nil),
	)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestSubscriptionRouteErrorsUseJSONContract(t *testing.T) {
	var frontend fs.FS = fstest.MapFS{
		"index.html": {Data: []byte("J-UI")},
	}
	for _, testCase := range []struct {
		method string
		path   string
		status int
		code   string
	}{
		{http.MethodPost, "/sub/not-a-token", http.StatusMethodNotAllowed, "method_not_allowed"},
		{http.MethodGet, "/sub/", http.StatusNotFound, "not_found"},
	} {
		response := httptest.NewRecorder()
		NewHandler(frontend).ServeHTTP(
			response, httptest.NewRequest(testCase.method, testCase.path, nil),
		)
		if response.Code != testCase.status ||
			!strings.HasPrefix(response.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("%s %s status=%d type=%q body=%s",
				testCase.method, testCase.path, response.Code,
				response.Header().Get("Content-Type"), response.Body.String())
		}
		var body apiError
		if err := json.NewDecoder(response.Body).Decode(&body); err != nil || body.Code != testCase.code {
			t.Fatalf("%s %s error=%#v decode=%v", testCase.method, testCase.path, body, err)
		}
	}
}
