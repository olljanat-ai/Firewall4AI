package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/auth"
	"github.com/olljanat-ai/firewall4ai/internal/certgen"
	"github.com/olljanat-ai/firewall4ai/internal/config"
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
	// out waiting for admin approval (407).
	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("expected 407 for anonymous unapproved host, got %d", w.Code)
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

	// No approval exists, times out waiting → 407.
	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("expected 407, got %d", w.Code)
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

	// Without token, CONNECT is anonymous. No approval -> timeout -> 407.
	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("expected 407 for anonymous unapproved CONNECT, got %d", w.Code)
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

	// No approval exists, times out waiting → 407.
	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("expected 407, got %d", w.Code)
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
	p.handleHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for host-approved request with any path, got %d", w.Code)
	}
}

func TestProxy_HTTPPackageRepoDetection(t *testing.T) {
	p, _, _ := setupProxy(t)
	p.PackageApprovals = approval.NewManager()
	p.OSPackages = []config.PackageRepoConfig{
		{Name: "Debian", Type: "debian", Hosts: []string{"deb.debian.org"}},
	}

	// Pre-approve the package so the request goes through.
	p.PackageApprovals.Check("debian:curl", "", "", "")
	p.PackageApprovals.Decide("debian:curl", "", "", "", approval.StatusApproved, "ok")

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Request a Debian package .deb file via plain HTTP.
	req := httptest.NewRequest("GET", backend.URL+"/debian/pool/main/c/curl/curl_7.88.1-10_amd64.deb", nil)
	req.Host = "deb.debian.org"
	w := httptest.NewRecorder()
	p.handleHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for approved Debian package via HTTP, got %d", w.Code)
	}
}

func TestProxy_HTTPPackageRepoDetection_Unapproved(t *testing.T) {
	p, _, _ := setupProxy(t)
	p.PackageApprovals = approval.NewManager()
	p.OSPackages = []config.PackageRepoConfig{
		{Name: "Debian", Type: "debian", Hosts: []string{"deb.debian.org"}},
	}

	// Request a Debian package without approval — times out waiting → 407.
	req := httptest.NewRequest("GET", "http://deb.debian.org/debian/pool/main/c/curl/curl_7.88.1-10_amd64.deb", nil)
	w := httptest.NewRecorder()
	p.handleHTTP(w, req)

	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("expected 407 for unapproved Debian package via HTTP, got %d", w.Code)
	}
}

func TestProxy_HTTPPackageRepoMetadata_AutoApproved(t *testing.T) {
	p, _, _ := setupProxy(t)
	p.PackageApprovals = approval.NewManager()
	p.OSPackages = []config.PackageRepoConfig{
		{Name: "Debian", Type: "debian", Hosts: []string{"deb.debian.org"}},
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Metadata request (InRelease) — should be auto-approved without package approval.
	req := httptest.NewRequest("GET", backend.URL+"/debian/dists/bookworm/InRelease", nil)
	req.Host = "deb.debian.org"
	w := httptest.NewRecorder()
	p.handleHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for auto-approved Debian metadata via HTTP, got %d", w.Code)
	}
}

func TestProxy_LearningMode(t *testing.T) {
	p, skills, approvals := setupProxy(t)
	skills.AddSkill(auth.Skill{ID: "s1", Token: "tok-1", Active: true})
	p.LearningMode = true

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("learning mode ok"))
	}))
	defer backend.Close()

	req := httptest.NewRequest("GET", backend.URL+"/test", nil)
	req.Host = "unapproved.example.com"
	req.Header.Set(AuthHeader, "tok-1")
	w := httptest.NewRecorder()
	p.handleHTTP(w, req)

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
	p, skills, _ := setupProxy(t)
	skills.AddSkill(auth.Skill{ID: "s1", Token: "tok-1", Active: true})
	p.LearningMode = false // default-deny

	req := httptest.NewRequest("GET", "http://blocked.com/test", nil)
	req.Header.Set(AuthHeader, "tok-1")
	w := httptest.NewRecorder()
	p.handleHTTP(w, req)

	// No approval, times out waiting → 407.
	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("default-deny: expected 407, got %d", w.Code)
	}
}

func TestProxy_LearningMode_Package(t *testing.T) {
	p, _, _ := setupProxy(t)
	p.PackageApprovals = approval.NewManager()
	p.OSPackages = []config.PackageRepoConfig{
		{Name: "Debian", Type: "debian", Hosts: []string{"deb.debian.org"}},
	}
	p.LearningMode = true

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Request a Debian package without explicit approval — learning mode should allow it.
	req := httptest.NewRequest("GET", backend.URL+"/debian/pool/main/c/curl/curl_7.88.1-10_amd64.deb", nil)
	req.Host = "deb.debian.org"
	w := httptest.NewRecorder()
	p.handleHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("learning mode package: expected 200, got %d", w.Code)
	}

	// Verify the package shows as pending.
	pending := p.PackageApprovals.ListPending()
	found := false
	for _, a := range pending {
		if a.Host == "debian:curl" {
			found = true
			break
		}
	}
	if !found {
		t.Error("learning mode: expected pending approval for debian:curl")
	}
}

func TestProxy_LearningMode_Library(t *testing.T) {
	p, _, _ := setupProxy(t)
	p.LibraryApprovals = approval.NewManager()
	p.CodeLibraries = []config.PackageRepoConfig{
		{Name: "Go Proxy", Type: "golang", Hosts: []string{"proxy.golang.org"}},
	}
	p.LearningMode = true

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Request a Go module without explicit approval — learning mode should allow it.
	req := httptest.NewRequest("GET", backend.URL+"/github.com/gorilla/mux/@v/v1.8.0.mod", nil)
	req.Host = "proxy.golang.org"
	w := httptest.NewRecorder()
	p.handleHTTP(w, req)

	// Go proxy uses HTTPS normally, but this tests the HTTP handler path.
	// The request will go through handlePackageRepoHTTPRequest since the host matches.
	if w.Code != http.StatusOK {
		t.Errorf("learning mode library: expected 200, got %d", w.Code)
	}

	// Verify the library shows as pending.
	pending := p.LibraryApprovals.ListPending()
	found := false
	for _, a := range pending {
		if a.Host == "golang:github.com/gorilla/mux" {
			found = true
			break
		}
	}
	if !found {
		t.Error("learning mode: expected pending approval for golang:github.com/gorilla/mux")
	}
}

func TestProxy_LearningMode_RegistryBlob(t *testing.T) {
	// Set up a mock registry backend.
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("blob data"))
	}))
	defer backend.Close()

	p, _, _ := setupProxy(t)
	p.ImageApprovals = approval.NewManager()
	p.Registries = []config.RegistryConfig{
		{Name: "test-registry", Hosts: []string{"registry.example.com"}},
	}
	p.LearningMode = true
	// Use the test backend's TLS-accepting transport.
	p.Transport = backend.Client().Transport

	// Build a blob request as if it came through MITM.
	blobReq, _ := http.NewRequest("GET", "https://registry.example.com:443/v2/myapp/blobs/sha256:abc123", nil)
	blobReq.Host = "registry.example.com"

	// Use net.Pipe to simulate the MITM'd client connection.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	reg := &p.Registries[0]

	// Run the handler in a goroutine (it writes to serverConn).
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.handleRegistryTLSRequest(serverConn, blobReq, "registry.example.com", "10.0.0.1", nil, reg, time.Now())
		serverConn.Close()
	}()

	// Read the response from the client side.
	reader := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(reader, blobReq)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	// Drain the body so the writer goroutine can finish.
	io.ReadAll(resp.Body)
	resp.Body.Close()

	<-done

	if resp.StatusCode == http.StatusForbidden {
		t.Error("learning mode: blob request should not be denied (got 403)")
	}

	// Verify a pending image approval was created.
	pending := p.ImageApprovals.ListPending()
	found := false
	for _, a := range pending {
		if a.Host == "test-registry/myapp" {
			found = true
			break
		}
	}
	if !found {
		t.Error("learning mode: expected pending image approval for test-registry/myapp")
	}
}

func TestProxy_LearningMode_RegistryBlob_DeniedWhenOff(t *testing.T) {
	p, _, _ := setupProxy(t)
	p.ImageApprovals = approval.NewManager()
	p.Registries = []config.RegistryConfig{
		{Name: "test-registry", Hosts: []string{"registry.example.com"}},
	}
	p.LearningMode = false // default-deny

	blobReq, _ := http.NewRequest("GET", "https://registry.example.com:443/v2/myapp/blobs/sha256:abc123", nil)
	blobReq.Host = "registry.example.com"

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	reg := &p.Registries[0]

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.handleRegistryTLSRequest(serverConn, blobReq, "registry.example.com", "10.0.0.1", nil, reg, time.Now())
		serverConn.Close()
	}()

	reader := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(reader, blobReq)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	// Drain the body so the writer goroutine can finish.
	io.ReadAll(resp.Body)
	resp.Body.Close()

	<-done

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("default-deny: blob request should be denied, got %d", resp.StatusCode)
	}
}

// TestProxy_MITM_ChunkedResponseComplete verifies that large chunked
// responses are fully delivered through the MITM proxy without hanging.
// This is a regression test for the Helm repo add hang issue.
func TestProxy_MITM_ChunkedResponseComplete(t *testing.T) {
	p, skills, _, ca := setupProxyWithCA(t)

	// Create a ~100KB response body (simulating a Helm index).
	largeBody := make([]byte, 100*1024)
	for i := range largeBody {
		largeBody[i] = byte('A' + (i % 26))
	}

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Write without setting Content-Length to force chunked encoding.
		w.Header().Set("Content-Type", "application/yaml")
		w.WriteHeader(http.StatusOK)
		w.Write(largeBody)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	_, backendPort, _ := net.SplitHostPort(backendURL.Host)

	skills.AddSkill(auth.Skill{
		ID: "s1", Token: "tok-1", Active: true,
		AllowedHost: []string{"127.0.0.1"},
	})

	p.Transport = backend.Client().Transport

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer proxyListener.Close()

	proxySrv := &http.Server{Handler: p}
	go proxySrv.Serve(proxyListener)
	defer proxySrv.Close()

	proxyConn, err := net.Dial("tcp", proxyListener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer proxyConn.Close()

	connectReq := fmt.Sprintf("CONNECT 127.0.0.1:%s HTTP/1.1\r\nHost: 127.0.0.1:%s\r\n%s: tok-1\r\n\r\n",
		backendPort, backendPort, AuthHeader)
	proxyConn.Write([]byte(connectReq))

	br := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected CONNECT 200, got %d", resp.StatusCode)
	}

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

	httpReq, _ := http.NewRequest("GET", fmt.Sprintf("https://127.0.0.1:%s/index.yaml", backendPort), nil)
	httpReq.Write(tlsConn)

	// Set a deadline so the test fails fast instead of hanging indefinitely
	// if the fix regresses.
	tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))

	tlsReader := bufio.NewReader(tlsConn)
	httpResp, err := http.ReadResponse(tlsReader, httpReq)
	if err != nil {
		t.Fatalf("read HTTPS response: %v", err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if len(body) != len(largeBody) {
		t.Errorf("body length: got %d, want %d", len(body), len(largeBody))
	}
	if httpResp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", httpResp.StatusCode)
	}
}

// Alias for use in test file.
var StatusApproved = approval.StatusApproved
