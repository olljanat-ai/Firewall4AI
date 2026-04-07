package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/auth"
	"github.com/olljanat-ai/firewall4ai/internal/certgen"
	"github.com/olljanat-ai/firewall4ai/internal/credentials"
	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
)

// testRedirectTransport wraps an http.RoundTripper and rewrites every
// request URL so that it is sent to the given target host (e.g. the
// httptest.Server address) instead of the host the proxy handler set.
type testRedirectTransport struct {
	inner      http.RoundTripper
	targetHost string // host:port of the test backend
}

func (t *testRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Host = t.targetHost
	return t.inner.RoundTrip(req)
}

func setupProxy(t *testing.T) (*Proxy, *auth.SkillStore, *approval.Manager) {
	t.Helper()
	skills := auth.NewSkillStore()
	approvals := approval.NewManager()
	creds := credentials.NewManager()
	logger := proxylog.NewLogger(100)
	p := New(skills, approvals, creds, logger, nil)
	p.ApprovalTimeout = 50 * time.Millisecond // short timeout for tests
	return p, skills, approvals
}

func setupProxyWithCA(t *testing.T) (*Proxy, *auth.SkillStore, *approval.Manager, *certgen.CA) {
	t.Helper()
	skills := auth.NewSkillStore()
	approvals := approval.NewManager()
	creds := credentials.NewManager()
	logger := proxylog.NewLogger(100)
	ca, err := certgen.LoadOrGenerateCA(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrGenerateCA() error: %v", err)
	}
	p := New(skills, approvals, creds, logger, ca)
	p.ApprovalTimeout = 50 * time.Millisecond // short timeout for tests
	return p, skills, approvals, ca
}

// Alias for use in test files.
var StatusApproved = approval.StatusApproved

func TestExtractHost(t *testing.T) {
	tests := []struct {
		host    string
		urlHost string
		want    string
	}{
		{"example.com:443", "", "example.com"},
		{"example.com", "", "example.com"},
		{"", "api.example.com:8080", "api.example.com"},
	}
	for _, tt := range tests {
		r := &http.Request{Host: tt.host}
		r.URL = &url.URL{Host: tt.urlHost}
		got := extractHost(r)
		if got != tt.want {
			t.Errorf("extractHost(host=%q, urlHost=%q) = %q, want %q", tt.host, tt.urlHost, got, tt.want)
		}
	}
}

func TestExtractSourceIP(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"10.255.255.10:12345", "10.255.255.10"},
		{"192.168.1.1:80", "192.168.1.1"},
		{"127.0.0.1", "127.0.0.1"},
	}
	for _, tt := range tests {
		got := extractSourceIP(tt.input)
		if got != tt.want {
			t.Errorf("extractSourceIP(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestGetSkillID(t *testing.T) {
	if got := getSkillID(nil); got != "" {
		t.Errorf("getSkillID(nil) = %q, want empty", got)
	}
	skill := &auth.Skill{ID: "test-id"}
	if got := getSkillID(skill); got != "test-id" {
		t.Errorf("getSkillID(skill) = %q, want %q", got, "test-id")
	}
}

func TestProxy_Anonymous_Unapproved(t *testing.T) {
	p, _, _ := setupProxy(t)
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	// No approval exists, so it times out waiting for admin approval (407).
	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("expected 407 for anonymous unapproved host, got %d", w.Code)
	}
}

func TestProxy_HostNotApproved(t *testing.T) {
	p, _, _ := setupProxy(t)

	req := httptest.NewRequest("GET", "http://blocked.com/test", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	// No approval exists, times out waiting → 407.
	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("expected 407, got %d", w.Code)
	}
}

func TestProxy_ApprovedHost(t *testing.T) {
	p, _, approvals := setupProxy(t)
	approvals.Decide("target.example.com", "", "", "", approval.StatusApproved, "ok")

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	req := httptest.NewRequest("GET", backend.URL+"/data", nil)
	req.Host = "target.example.com"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestProxy_GlobalApproval(t *testing.T) {
	p, _, approvals := setupProxy(t)

	// Globally approve a host (empty skillID, empty sourceIP).
	approvals.Decide("global.example.com", "", "", "", approval.StatusApproved, "global")

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Anonymous request should pass via global approval.
	req := httptest.NewRequest("GET", backend.URL+"/test", nil)
	req.Host = "global.example.com"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for globally approved host, got %d", w.Code)
	}
}

func TestProxy_VMSpecificApproval(t *testing.T) {
	p, _, approvals := setupProxy(t)

	// Approve for a specific VM IP.
	approvals.Decide("vm.example.com", "", "10.255.255.10", "", approval.StatusApproved, "vm ok")

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Request from the approved VM IP should pass.
	req := httptest.NewRequest("GET", backend.URL+"/test", nil)
	req.Host = "vm.example.com"
	req.RemoteAddr = "10.255.255.10:12345"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for VM-approved host, got %d", w.Code)
	}
}

func TestProxy_WildcardGlobalApproval(t *testing.T) {
	p, _, approvals := setupProxy(t)

	// Approve wildcard globally.
	approvals.Decide("*.example.com", "", "", "", approval.StatusApproved, "wildcard")

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Request to a subdomain should match the wildcard.
	req := httptest.NewRequest("GET", backend.URL+"/test", nil)
	req.Host = "api.example.com"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for wildcard-approved host, got %d", w.Code)
	}
}

// --- Path prefix tests ---

func TestProxy_PathPrefixApproval_Allowed(t *testing.T) {
	p, _, approvals := setupProxy(t)

	// Approve only a specific path prefix.
	approvals.Decide("github.com", "", "", "/olljanat-ai/", StatusApproved, "repo access")

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	req := httptest.NewRequest("GET", backend.URL+"/olljanat-ai/Firewall4AI/pull/1", nil)
	req.Host = "github.com"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for path-prefix-approved request, got %d", w.Code)
	}
}

func TestProxy_PathPrefixApproval_Denied(t *testing.T) {
	p, _, approvals := setupProxy(t)

	// Approve only a specific path prefix.
	approvals.Decide("github.com", "", "", "/olljanat-ai/", StatusApproved, "repo access")

	req := httptest.NewRequest("GET", "http://github.com/evil-org/malware", nil)
	req.Host = "github.com"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	// Non-matching path should time out waiting for approval → 407.
	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("expected 407 for non-matching path, got %d", w.Code)
	}
}

func TestProxy_HostApproval_CoversAllPaths(t *testing.T) {
	p, _, approvals := setupProxy(t)

	// Host-only approval (no path prefix) covers all paths.
	approvals.Decide("example.com", "", "", "", StatusApproved, "all paths")

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	req := httptest.NewRequest("GET", backend.URL+"/any/path/here", nil)
	req.Host = "example.com"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for host-approved request with any path, got %d", w.Code)
	}
}

// --- Learning mode tests ---

func TestProxy_LearningMode(t *testing.T) {
	p, _, approvals := setupProxy(t)
	p.LearningMode = true

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("learning mode ok"))
	}))
	defer backend.Close()

	req := httptest.NewRequest("GET", backend.URL+"/test", nil)
	req.Host = "unapproved.example.com"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("learning mode: expected 200, got %d", w.Code)
	}

	// The host should be registered as pending in the approval system.
	pending := approvals.ListPending()
	found := false
	for _, a := range pending {
		if a.Host == "unapproved.example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("learning mode: expected pending approval entry for unapproved.example.com")
	}
}

func TestProxy_LearningModeDisabled(t *testing.T) {
	p, _, _ := setupProxy(t)
	p.LearningMode = false // default-deny

	req := httptest.NewRequest("GET", "http://blocked.com/test", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	// No approval, times out waiting → 407.
	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("default-deny: expected 407, got %d", w.Code)
	}
}
