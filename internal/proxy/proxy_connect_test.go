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

	"github.com/olljanat-ai/firewall4ai/internal/credentials"
)

// startProxyServer starts a proxy HTTP server and returns its address and cleanup func.
func startProxyServer(t *testing.T, p *Proxy) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: p}
	go srv.Serve(listener)
	return listener.Addr().String(), func() {
		srv.Close()
		listener.Close()
	}
}

// connectViaProxy dials the proxy, sends a CONNECT request, and returns the
// response status code and the underlying connection for TLS upgrade.
// The connection is raw (no buffered reader wrapping).
func connectViaProxy(t *testing.T, proxyAddr, targetHost string, headers map[string]string) (int, net.Conn) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}

	reqLine := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetHost, targetHost)
	for k, v := range headers {
		reqLine += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	reqLine += "\r\n"
	conn.Write([]byte(reqLine))

	// Parse the CONNECT request so http.ReadResponse knows not to expect a body.
	connectReq, _ := http.NewRequest("CONNECT", "http://"+targetHost, nil)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		conn.Close()
		t.Fatalf("read CONNECT response: %v", err)
	}
	statusCode := resp.StatusCode
	if resp.Body != nil {
		resp.Body.Close()
	}

	// If rejected, return the status code. Caller should close conn.
	if statusCode != 200 {
		return statusCode, conn
	}

	// Wrap the connection so that any buffered data from bufio.Reader is
	// available to subsequent reads (e.g. TLS handshake).
	buffered := br.Buffered()
	if buffered > 0 {
		peek, _ := br.Peek(buffered)
		conn = &prefixConn{Conn: conn, prefix: peek}
	}

	return statusCode, conn
}

// prefixConn prepends buffered data before reading from the underlying conn.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

func TestProxy_CONNECT_NoAuth_Anonymous(t *testing.T) {
	p, _, _ := setupProxy(t)

	proxyAddr, cleanup := startProxyServer(t, p)
	defer cleanup()

	status, conn := connectViaProxy(t, proxyAddr, "example.com:443", nil)
	defer conn.Close()

	// No approval -> timeout -> 407.
	if status != http.StatusProxyAuthRequired {
		t.Errorf("expected 407 for unapproved CONNECT, got %d", status)
	}
}

func TestProxy_CONNECT_HostNotApproved(t *testing.T) {
	p, _, _ := setupProxy(t)

	proxyAddr, cleanup := startProxyServer(t, p)
	defer cleanup()

	status, conn := connectViaProxy(t, proxyAddr, "blocked.com:443", nil)
	defer conn.Close()

	// No approval exists, times out waiting → 407.
	if status != http.StatusProxyAuthRequired {
		t.Errorf("expected 407, got %d", status)
	}
}

// TestProxy_MITM_InspectsHTTPS verifies end-to-end MITM: the proxy terminates
// the client TLS, reads the inner HTTP request, injects credentials, and
// forwards to the real HTTPS backend.
func TestProxy_MITM_InspectsHTTPS(t *testing.T) {
	p, _, approvals, ca := setupProxyWithCA(t)

	var receivedAuth string
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("secure response"))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	_, backendPort, _ := net.SplitHostPort(backendURL.Host)

	// Approve the host via approval manager.
	approvals.Decide("127.0.0.1", "", "", "", StatusApproved, "test")

	p.Credentials.Add(credentials.Credential{
		ID:            "cred-1",
		HostPattern:   "127.0.0.1",
		InjectionType: credentials.InjectBearer,
		Token:         "injected-secret",
		Active:        true,
	})

	p.Transport = backend.Client().Transport

	proxyAddr, cleanup := startProxyServer(t, p)
	defer cleanup()

	status, proxyConn := connectViaProxy(t, proxyAddr, fmt.Sprintf("127.0.0.1:%s", backendPort), nil)
	defer proxyConn.Close()

	if status != 200 {
		t.Fatalf("expected CONNECT 200, got %d", status)
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

	httpReq, _ := http.NewRequest("GET", fmt.Sprintf("https://127.0.0.1:%s/api/data", backendPort), nil)
	httpReq.Write(tlsConn)

	tlsReader := bufio.NewReader(tlsConn)
	httpResp, err := http.ReadResponse(tlsReader, httpReq)
	if err != nil {
		t.Fatalf("read HTTPS response: %v", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", httpResp.StatusCode)
	}

	if receivedAuth != "Bearer injected-secret" {
		t.Errorf("expected injected bearer token, got %q", receivedAuth)
	}
}

// TestProxy_MITM_HostCertVerifiable checks that the MITM'd connection
// presents a valid certificate for the target host.
func TestProxy_MITM_HostCertVerifiable(t *testing.T) {
	p, _, approvals, ca := setupProxyWithCA(t)
	approvals.Decide("test.example.com", "", "", "", StatusApproved, "test")

	proxyAddr, cleanup := startProxyServer(t, p)
	defer cleanup()

	status, proxyConn := connectViaProxy(t, proxyAddr, "test.example.com:443", nil)
	defer proxyConn.Close()

	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Certificate)
	tlsConn := tls.Client(proxyConn, &tls.Config{
		RootCAs:    caPool,
		ServerName: "test.example.com",
	})

	err := tlsConn.Handshake()
	if err != nil {
		t.Fatalf("TLS handshake should succeed with CA trust: %v", err)
	}
	tlsConn.Close()

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("expected peer certificates")
	}
	cn := state.PeerCertificates[0].Subject.CommonName
	if cn != "test.example.com" {
		t.Errorf("expected CN test.example.com, got %q", cn)
	}
}

// TestProxy_MITM_ChunkedResponseComplete verifies that large chunked
// responses are fully delivered through the MITM proxy without hanging.
func TestProxy_MITM_ChunkedResponseComplete(t *testing.T) {
	p, _, approvals, ca := setupProxyWithCA(t)

	largeBody := make([]byte, 100*1024)
	for i := range largeBody {
		largeBody[i] = byte('A' + (i % 26))
	}

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		w.WriteHeader(http.StatusOK)
		w.Write(largeBody)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	_, backendPort, _ := net.SplitHostPort(backendURL.Host)

	// Approve the host via approval manager.
	approvals.Decide("127.0.0.1", "", "", "", StatusApproved, "test")

	p.Transport = backend.Client().Transport

	proxyAddr, cleanup := startProxyServer(t, p)
	defer cleanup()

	status, proxyConn := connectViaProxy(t, proxyAddr, fmt.Sprintf("127.0.0.1:%s", backendPort), nil)
	defer proxyConn.Close()

	if status != 200 {
		t.Fatalf("expected CONNECT 200, got %d", status)
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
