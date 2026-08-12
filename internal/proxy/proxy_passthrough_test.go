package proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/olljanat-ai/firewall4ai/internal/config"
)

// mtlsBackend starts a TLS server that requires a client certificate and
// reports whether the client presented one.
func mtlsBackend(t *testing.T, clientAuth tls.ClientAuthType) *httptest.Server {
	t.Helper()
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, "the server has asked for the client to provide credentials")
			return
		}
		io.WriteString(w, "client certificate: "+r.TLS.PeerCertificates[0].Subject.CommonName)
	}))
	backend.TLS = &tls.Config{ClientAuth: clientAuth}
	backend.StartTLS()
	t.Cleanup(backend.Close)
	return backend
}

func TestProbeClientCertRequest(t *testing.T) {
	tests := []struct {
		name       string
		clientAuth tls.ClientAuthType
		want       bool
	}{
		{"server requires client certificate", tls.RequireAnyClientCert, true},
		{"server requests client certificate", tls.RequestClientCert, true},
		{"server does not ask for one", tls.NoClientCert, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := mtlsBackend(t, tt.clientAuth)
			addr := strings.TrimPrefix(backend.URL, "https://")

			got, _ := probeClientCertRequest(addr, "127.0.0.1")
			if got != tt.want {
				t.Errorf("probeClientCertRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShouldPassthrough_ConfiguredHost(t *testing.T) {
	p, _, _ := setupProxy(t)
	p.TLSPassthroughHosts = []string{"*.azmk8s.io"}

	// A configured host is never probed, so the (unreachable) address is fine.
	if !p.shouldPassthrough("cluster.swedencentral.azmk8s.io", "cluster.swedencentral.azmk8s.io:443") {
		t.Error("expected configured wildcard host to require passthrough")
	}
	if p.isPassthroughHost("example.com") {
		t.Error("example.com is not in the passthrough list")
	}
}

func TestUpstreamRequiresClientCert_CachesProbe(t *testing.T) {
	backend := mtlsBackend(t, tls.RequireAnyClientCert)
	addr := strings.TrimPrefix(backend.URL, "https://")

	p, _, _ := setupProxy(t)
	if !p.shouldPassthrough("127.0.0.1", addr) {
		t.Fatal("expected mTLS backend to require passthrough")
	}

	// Once cached, the answer must survive the backend going away.
	backend.Close()
	if !p.shouldPassthrough("127.0.0.1", addr) {
		t.Error("expected cached probe result to be reused")
	}
}

func TestPeekClientHello(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error: %v", err)
	}
	defer listener.Close()

	type result struct {
		serverName string
		raw        []byte
		err        error
	}
	results := make(chan result, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			results <- result{err: err}
			return
		}
		defer conn.Close()
		name, raw, err := peekClientHello(conn, 5*time.Second)
		results <- result{serverName: name, raw: raw, err: err}
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	defer conn.Close()
	// The handshake never completes (the peek server answers nothing), which
	// is fine: only the ClientHello matters here.
	tlsConn := tls.Client(conn, &tls.Config{ServerName: "sni.example.com"})
	tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
	go tlsConn.Handshake()

	got := <-results
	if got.err != nil {
		t.Fatalf("peekClientHello() error: %v", got.err)
	}
	if got.serverName != "sni.example.com" {
		t.Errorf("peekClientHello() serverName = %q, want %q", got.serverName, "sni.example.com")
	}
	if len(got.raw) == 0 || got.raw[0] != 0x16 {
		t.Errorf("peekClientHello() raw = %v, want a TLS handshake record", got.raw)
	}
}

// TestTransparentTLSPassthrough verifies the reported failure: a client that
// authenticates with a certificate (Terraform/helm against a Kubernetes API
// server) reaches the upstream server with its own certificate intact.
func TestTransparentTLSPassthrough(t *testing.T) {
	backend := mtlsBackend(t, tls.RequireAnyClientCert)
	backendAddr := strings.TrimPrefix(backend.URL, "https://")

	p, _, approvals, _ := setupProxyWithCA(t)
	p.TLSPassthroughHosts = []string{"k8s.example.com"}
	p.dialUpstream = func(network, addr string) (net.Conn, error) {
		// The proxy resolves the SNI host; send it to the test backend.
		return net.Dial(network, backendAddr)
	}
	approvals.Decide("k8s.example.com", "", "", "", StatusApproved, "cluster")

	clientCert := testClientCert(t)
	resp := roundTripThroughTransparentTLS(t, p, "k8s.example.com", &tls.Config{
		ServerName:         "k8s.example.com",
		InsecureSkipVerify: true, // #nosec G402 -- backend uses a test certificate
		Certificates:       []tls.Certificate{*clientCert},
	})

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 through TLS passthrough, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.HasPrefix(string(body), "client certificate:") {
		t.Errorf("client certificate did not reach the upstream server: %s", body)
	}
}

// TestTransparentTLSMITMAfterPeek verifies that reading the ClientHello up
// front does not break normal MITM interception: the replayed bytes must
// still produce a valid TLS session with the proxy.
func TestTransparentTLSMITMAfterPeek(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "inspected")
	}))
	defer backend.Close()

	p, _, approvals, _ := setupProxyWithCA(t)
	approvals.Decide("inspect.example.com", "", "", "", StatusApproved, "ok")
	p.Transport = &testRedirectTransport{
		inner:      backend.Client().Transport,
		targetHost: backend.Listener.Addr().String(),
	}
	// Never probe: the fake host does not resolve.
	p.clientCertProbes = map[string]clientCertProbe{
		"inspect.example.com:443": {required: false, checkedAt: time.Now()},
	}

	resp := roundTripThroughTransparentTLS(t, p, "inspect.example.com", &tls.Config{
		ServerName:         "inspect.example.com",
		InsecureSkipVerify: true, // #nosec G402 -- the proxy signs with its own test CA
	})

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 through MITM, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "inspected" {
		t.Errorf("body = %q, want %q", body, "inspected")
	}
}

// TestShouldPassthrough_SkipsConfiguredRepoHosts verifies that configured
// infrastructure keeps being inspected: tunneling a registry would silently
// disable image-level approval.
func TestShouldPassthrough_SkipsConfiguredRepoHosts(t *testing.T) {
	backend := mtlsBackend(t, tls.RequireAnyClientCert)
	addr := strings.TrimPrefix(backend.URL, "https://")

	p, _, _ := setupProxy(t)
	p.Registries = []config.RegistryConfig{{Name: "test", Hosts: []string{"127.0.0.1"}}}

	if p.shouldPassthrough("127.0.0.1", addr) {
		t.Error("configured registry host must stay inspected")
	}

	// An explicit passthrough entry still wins.
	p.TLSPassthroughHosts = []string{"127.0.0.1"}
	if !p.shouldPassthrough("127.0.0.1", addr) {
		t.Error("explicit passthrough entry must override the registry check")
	}
}

// TestConnectTLSPassthrough covers the same fix for agents that use the proxy
// explicitly (CONNECT) instead of transparent interception.
func TestConnectTLSPassthrough(t *testing.T) {
	backend := mtlsBackend(t, tls.RequireAnyClientCert)
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	p, _, approvals, _ := setupProxyWithCA(t)
	approvals.Decide("127.0.0.1", "", "", "", StatusApproved, "cluster")

	proxyAddr, cleanup := startProxyServer(t, p)
	defer cleanup()

	status, proxyConn := connectViaProxy(t, proxyAddr, backendURL.Host, nil)
	defer proxyConn.Close()
	if status != http.StatusOK {
		t.Fatalf("expected CONNECT 200, got %d", status)
	}

	clientCert := testClientCert(t)
	tlsConn := tls.Client(proxyConn, &tls.Config{
		ServerName:         "127.0.0.1",
		InsecureSkipVerify: true, // #nosec G402 -- backend uses a test certificate
		Certificates:       []tls.Certificate{*clientCert},
	})
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("client handshake through tunnel: %v", err)
	}

	req, _ := http.NewRequest("GET", backend.URL+"/", nil)
	req.Header.Set("Connection", "close")
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("ReadResponse() error: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(string(body), "client certificate:") {
		t.Errorf("client certificate did not reach the upstream server: %d %s", resp.StatusCode, body)
	}
}

// testClientCert generates a certificate the test client can present.
func testClientCert(t *testing.T) *tls.Certificate {
	t.Helper()
	_, _, _, ca := setupProxyWithCA(t)
	cert, err := ca.GenerateHostCert("terraform-client")
	if err != nil {
		t.Fatalf("GenerateHostCert() error: %v", err)
	}
	return cert
}

// roundTripThroughTransparentTLS sends one HTTPS request through the proxy's
// transparent TLS listener and returns the response.
func roundTripThroughTransparentTLS(t *testing.T, p *Proxy, host string, clientTLS *tls.Config) *http.Response {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error: %v", err)
	}
	defer listener.Close()
	go p.ServeTransparentTLS(listener)

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	tlsConn := tls.Client(conn, clientTLS)
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("client handshake error: %v", err)
	}

	req, err := http.NewRequest("GET", "https://"+host+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}
	req.Header.Set("Connection", "close")
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("write request error: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("ReadResponse() error: %v", err)
	}
	return resp
}
