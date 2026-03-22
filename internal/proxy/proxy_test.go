package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
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

func setupProxyWithCA(t *testing.T) (*Proxy, *auth.SkillStore, *approval.Manager, *certgen.CA) {
	t.Helper()
	p, skills, approvals := setupProxy(t)
	ca, err := certgen.LoadOrGenerateCA(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrGenerateCA() error: %v", err)
	}
	p.CA = ca
	return p, skills, approvals, ca
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

func TestProxy_NoAuthHeader_Anonymous(t *testing.T) {
	p, _, _ := setupProxy(t)
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	w := httptest.NewRecorder()
	p.handleHTTP(w, req)

	// Without token, request is anonymous. No approval exists, so it times
	// out and gets denied (403).
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for anonymous unapproved host, got %d", w.Code)
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
	approvals.Decide("target.example.com", "s1", "", "", approval.StatusApproved, "ok")

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

func TestProxy_GlobalApproval(t *testing.T) {
	p, _, approvals := setupProxy(t)

	// Globally approve a host (empty skillID, empty sourceIP).
	approvals.Decide("global.example.com", "", "", "", approval.StatusApproved, "global")

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Anonymous request (no token) should pass via global approval.
	req := httptest.NewRequest("GET", backend.URL+"/test", nil)
	req.Host = "global.example.com"
	w := httptest.NewRecorder()
	p.handleHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for globally approved host (anonymous), got %d", w.Code)
	}
}

func TestProxy_GlobalApproval_WithSkill(t *testing.T) {
	p, skills, approvals := setupProxy(t)
	skills.AddSkill(auth.Skill{ID: "s1", Token: "tok-1", Active: true})

	// Globally approve a host.
	approvals.Decide("global.example.com", "", "", "", approval.StatusApproved, "global")

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Authenticated request should also pass via global approval.
	req := httptest.NewRequest("GET", backend.URL+"/test", nil)
	req.Host = "global.example.com"
	req.Header.Set(AuthHeader, "tok-1")
	w := httptest.NewRecorder()
	p.handleHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for globally approved host (with skill), got %d", w.Code)
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
	p.handleHTTP(w, req)

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
	p.handleHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for wildcard-approved host, got %d", w.Code)
	}
}

func TestProxy_WildcardPreApprovedHost(t *testing.T) {
	p, skills, _ := setupProxy(t)
	skills.AddSkill(auth.Skill{
		ID: "s1", Token: "tok-1", Active: true,
		AllowedHost: []string{"*.example.com"},
	})

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	req := httptest.NewRequest("GET", backend.URL+"/test", nil)
	req.Host = "api.example.com"
	req.Header.Set(AuthHeader, "tok-1")
	w := httptest.NewRecorder()
	p.handleHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for wildcard pre-approved host, got %d", w.Code)
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

func TestProxy_CONNECT_NoAuth_Anonymous(t *testing.T) {
	p, _, _ := setupProxy(t)
	req := httptest.NewRequest("CONNECT", "example.com:443", nil)
	req.Host = "example.com:443"
	w := httptest.NewRecorder()
	p.handleConnect(w, req)

	// Without token, CONNECT is anonymous. No approval -> timeout -> 403.
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for anonymous unapproved CONNECT, got %d", w.Code)
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

// TestProxy_MITM_InspectsHTTPS verifies end-to-end MITM: the proxy terminates
// the client TLS, reads the inner HTTP request, injects credentials, and
// forwards to the real HTTPS backend.
func TestProxy_MITM_InspectsHTTPS(t *testing.T) {
	p, skills, _, ca := setupProxyWithCA(t)

	var receivedAuth string
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("secure response"))
	}))
	defer backend.Close()

	// Parse backend address.
	backendURL, _ := url.Parse(backend.URL)
	backendHost, backendPort, _ := net.SplitHostPort(backendURL.Host)
	_ = backendHost

	skills.AddSkill(auth.Skill{
		ID: "s1", Token: "tok-1", Active: true,
		AllowedHost: []string{"127.0.0.1"},
	})

	// Add credential injection for the backend host.
	p.Credentials.Add(credentials.Credential{
		ID:            "cred-1",
		HostPattern:   "127.0.0.1",
		InjectionType: credentials.InjectBearer,
		Token:         "injected-secret",
		Active:        true,
	})

	// Use the backend's TLS client config so the proxy can connect to it.
	p.Transport = backend.Client().Transport

	// Start the proxy server.
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer proxyListener.Close()

	proxySrv := &http.Server{Handler: p}
	go proxySrv.Serve(proxyListener)
	defer proxySrv.Close()

	// Connect as a client through the proxy.
	proxyConn, err := net.Dial("tcp", proxyListener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer proxyConn.Close()

	// Send CONNECT request.
	connectReq := fmt.Sprintf("CONNECT 127.0.0.1:%s HTTP/1.1\r\nHost: 127.0.0.1:%s\r\n%s: tok-1\r\n\r\n",
		backendPort, backendPort, AuthHeader)
	proxyConn.Write([]byte(connectReq))

	// Read the 200 response.
	br := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected CONNECT 200, got %d", resp.StatusCode)
	}

	// Upgrade to TLS using the CA as trust anchor.
	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Certificate)
	tlsConn := tls.Client(proxyConn, &tls.Config{
		RootCAs:    caPool,
		ServerName: "127.0.0.1",
	})
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake with proxy: %v", err)
	}

	// Send an HTTPS request through the MITM'd connection.
	httpReq, _ := http.NewRequest("GET", fmt.Sprintf("https://127.0.0.1:%s/api/data", backendPort), nil)
	httpReq.Write(tlsConn)

	// Read response.
	tlsReader := bufio.NewReader(tlsConn)
	httpResp, err := http.ReadResponse(tlsReader, httpReq)
	if err != nil {
		t.Fatalf("read HTTPS response: %v", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", httpResp.StatusCode)
	}

	// Verify credential injection worked through TLS MITM.
	if receivedAuth != "Bearer injected-secret" {
		t.Errorf("expected injected bearer token, got %q", receivedAuth)
	}
}

// TestProxy_MITM_HostCertVerifiable checks that the MITM'd connection
// presents a valid certificate for the target host.
func TestProxy_MITM_HostCertVerifiable(t *testing.T) {
	p, skills, _, ca := setupProxyWithCA(t)
	skills.AddSkill(auth.Skill{
		ID: "s1", Token: "tok-1", Active: true,
		AllowedHost: []string{"test.example.com"},
	})

	// Start the proxy.
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer proxyListener.Close()

	proxySrv := &http.Server{Handler: p}
	go proxySrv.Serve(proxyListener)
	defer proxySrv.Close()

	// Connect and send CONNECT.
	proxyConn, err := net.Dial("tcp", proxyListener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer proxyConn.Close()

	connectReq := fmt.Sprintf("CONNECT test.example.com:443 HTTP/1.1\r\nHost: test.example.com:443\r\n%s: tok-1\r\n\r\n", AuthHeader)
	proxyConn.Write([]byte(connectReq))

	br := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// TLS handshake: the cert should be valid for test.example.com, signed by our CA.
	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Certificate)
	tlsConn := tls.Client(proxyConn, &tls.Config{
		RootCAs:    caPool,
		ServerName: "test.example.com",
	})

	err = tlsConn.Handshake()
	if err != nil {
		t.Fatalf("TLS handshake should succeed with CA trust: %v", err)
	}
	tlsConn.Close()

	// Verify the presented cert has the right CN.
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("expected peer certificates")
	}
	cn := state.PeerCertificates[0].Subject.CommonName
	if cn != "test.example.com" {
		t.Errorf("expected CN test.example.com, got %q", cn)
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

// --- Path prefix proxy tests ---

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
	p.handleHTTP(w, req)

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
	p.handleHTTP(w, req)

	// Non-matching path should time out and be denied.
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-matching path, got %d", w.Code)
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
	p.handleHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for host-approved request with any path, got %d", w.Code)
	}
}

// Alias for use in test file.
var StatusApproved = approval.StatusApproved
