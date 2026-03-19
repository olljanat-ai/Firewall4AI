package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/olljanat-ai/squid4claw/internal/approval"
	"github.com/olljanat-ai/squid4claw/internal/auth"
	"github.com/olljanat-ai/squid4claw/internal/credentials"
	proxylog "github.com/olljanat-ai/squid4claw/internal/logging"
)

func setupProxy(t *testing.T) (*Proxy, *auth.SkillStore, *approval.Manager) {
	t.Helper()
	skills := auth.NewSkillStore()
	approvals := approval.NewManager()
	creds := credentials.NewManager()
	logger := proxylog.NewLogger(100)
	p := New(skills, approvals, creds, logger)
	p.ApprovalTimeout = 50 * time.Millisecond // short timeout for tests
	return p, skills, approvals
}

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

func TestProxy_NoAuthHeader(t *testing.T) {
	p, _, _ := setupProxy(t)
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	w := httptest.NewRecorder()
	p.handleHTTP(w, req)

	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("expected 407, got %d", w.Code)
	}
}

func TestProxy_InvalidToken(t *testing.T) {
	p, _, _ := setupProxy(t)
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set(AuthHeader, "bad-token")
	w := httptest.NewRecorder()
	p.handleHTTP(w, req)

	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("expected 407, got %d", w.Code)
	}
}

func TestProxy_HostNotApproved(t *testing.T) {
	p, skills, _ := setupProxy(t)
	skills.AddSkill(auth.Skill{ID: "s1", Token: "tok-1", Active: true})

	req := httptest.NewRequest("GET", "http://blocked.com/test", nil)
	req.Header.Set(AuthHeader, "tok-1")
	w := httptest.NewRecorder()
	p.handleHTTP(w, req)

	// Host is not approved and not pre-approved => pending => denied (no waiter approves).
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestProxy_PreApprovedHost(t *testing.T) {
	p, skills, _ := setupProxy(t)
	skills.AddSkill(auth.Skill{
		ID: "s1", Token: "tok-1", Active: true,
		AllowedHost: []string{"target.example.com"},
	})

	// Create a backend that the proxy will forward to.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello from backend"))
	}))
	defer backend.Close()

	req := httptest.NewRequest("GET", backend.URL+"/test", nil)
	req.Host = "target.example.com"
	req.Header.Set(AuthHeader, "tok-1")
	w := httptest.NewRecorder()
	p.handleHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestProxy_ApprovedHost(t *testing.T) {
	p, skills, approvals := setupProxy(t)
	skills.AddSkill(auth.Skill{ID: "s1", Token: "tok-1", Active: true})
	approvals.Decide("target.example.com", "s1", approval.StatusApproved, "ok")

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	req := httptest.NewRequest("GET", backend.URL+"/data", nil)
	req.Host = "target.example.com"
	req.Header.Set(AuthHeader, "tok-1")
	w := httptest.NewRecorder()
	p.handleHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestProxy_AuthHeaderStripped(t *testing.T) {
	p, skills, _ := setupProxy(t)
	skills.AddSkill(auth.Skill{
		ID: "s1", Token: "tok-1", Active: true,
		AllowedHost: []string{"target.example.com"},
	})

	var gotHeader string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get(AuthHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	req := httptest.NewRequest("GET", backend.URL+"/test", nil)
	req.Host = "target.example.com"
	req.Header.Set(AuthHeader, "tok-1")
	w := httptest.NewRecorder()
	p.handleHTTP(w, req)

	if gotHeader != "" {
		t.Error("auth header should be stripped before forwarding")
	}
}

func TestProxy_CONNECT_NoAuth(t *testing.T) {
	p, _, _ := setupProxy(t)
	req := httptest.NewRequest("CONNECT", "example.com:443", nil)
	req.Host = "example.com:443"
	w := httptest.NewRecorder()
	p.handleConnect(w, req)

	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("expected 407, got %d", w.Code)
	}
}

func TestProxy_CONNECT_HostNotApproved(t *testing.T) {
	p, skills, _ := setupProxy(t)
	skills.AddSkill(auth.Skill{ID: "s1", Token: "tok-1", Active: true})

	req := httptest.NewRequest("CONNECT", "blocked.com:443", nil)
	req.Host = "blocked.com:443"
	req.Header.Set(AuthHeader, "tok-1")
	w := httptest.NewRecorder()
	p.handleConnect(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}
