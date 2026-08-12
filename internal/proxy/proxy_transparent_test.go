package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeConn is a net.Conn that only answers questions about its addresses,
// which is all transparentDestination needs.
type fakeConn struct {
	net.Conn
	local net.Addr
}

func (c fakeConn) LocalAddr() net.Addr { return c.local }

func TestTransparentDestination(t *testing.T) {
	listenAddr := &net.TCPAddr{IP: net.ParseIP("10.255.255.1"), Port: 8443}

	tests := []struct {
		name     string
		sniHost  string
		origAddr string
		origErr  error
		wantHost string
		wantPort string
		wantErr  bool
	}{
		{
			name:     "SNI host with redirected port",
			sniHost:  "example.com",
			origAddr: "93.184.216.34:443",
			wantHost: "example.com",
			wantPort: "443",
		},
		{
			name:     "SNI host wins over the destination IP",
			sniHost:  "example.com",
			origAddr: "93.184.216.34:8443",
			wantHost: "example.com",
			wantPort: "8443",
		},
		{
			name:     "SNI host without netfilter answer",
			sniHost:  "example.com",
			origErr:  errors.New("no conntrack entry"),
			wantHost: "example.com",
			wantPort: "443",
		},
		{
			name:     "no SNI falls back to the original destination",
			origAddr: "10.0.0.5:443",
			wantHost: "10.0.0.5",
			wantPort: "443",
		},
		{
			name:     "no SNI on a non-standard port",
			origAddr: "10.0.0.5:9443",
			wantHost: "10.0.0.5",
			wantPort: "9443",
		},
		{
			name:    "no SNI and no netfilter answer",
			origErr: errors.New("no conntrack entry"),
			wantErr: true,
		},
		{
			name:     "no SNI on a connection that was never redirected",
			origAddr: listenAddr.String(),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, _, _ := setupProxy(t)
			p.origDst = func(net.Conn) (string, error) { return tt.origAddr, tt.origErr }

			host, port, err := p.transparentDestination(fakeConn{local: listenAddr}, tt.sniHost)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("transparentDestination() = %q/%q, want an error", host, port)
				}
				return
			}
			if err != nil {
				t.Fatalf("transparentDestination() error: %v", err)
			}
			if host != tt.wantHost || port != tt.wantPort {
				t.Errorf("transparentDestination() = %q/%q, want %q/%q", host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}

// TestTransparentTLSWithoutSNI covers the reported failure: an HTTPS request
// addressed to a bare IP carries no SNI, so the destination has to come from
// the pre-DNAT address. The client verifies the proxy certificate against the
// IP, exactly as curl does.
func TestTransparentTLSWithoutSNI(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "inspected "+r.Host)
	}))
	defer backend.Close()

	p, _, approvals, ca := setupProxyWithCA(t)
	approvals.Decide("10.0.0.5", "", "", "", StatusApproved, "ip destination")
	p.Transport = &testRedirectTransport{
		inner:      backend.Client().Transport,
		targetHost: backend.Listener.Addr().String(),
	}
	p.origDst = func(net.Conn) (string, error) { return "10.0.0.5:443", nil }
	// Never probe: the fake destination does not exist.
	p.clientCertProbes = map[string]clientCertProbe{
		"10.0.0.5:443": {required: false, checkedAt: time.Now()},
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.CertPEM) {
		t.Fatal("failed to add the test CA to the trust pool")
	}

	// ServerName is an IP literal, so Go sends no SNI and validates the
	// certificate against its IP SANs.
	resp := roundTripThroughTransparentTLS(t, p, "10.0.0.5", &tls.Config{
		ServerName: "10.0.0.5",
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	})

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 through MITM, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "inspected 10.0.0.5" {
		t.Errorf("body = %q, want %q", body, "inspected 10.0.0.5")
	}
}

// TestTransparentTLSWithoutSNIPassthrough verifies that the client-certificate
// exception also applies to destinations addressed by IP: a Kubernetes API
// server reached as https://<ip>/ must be tunneled with the client's own
// certificate intact.
func TestTransparentTLSWithoutSNIPassthrough(t *testing.T) {
	backend := mtlsBackend(t, tls.RequireAnyClientCert)
	backendAddr := strings.TrimPrefix(backend.URL, "https://")
	backendIP, _, err := net.SplitHostPort(backendAddr)
	if err != nil {
		t.Fatalf("SplitHostPort() error: %v", err)
	}

	p, _, approvals, _ := setupProxyWithCA(t)
	approvals.Decide(backendIP, "", "", "", StatusApproved, "cluster")
	// The connection was redirected from the backend's own address, which is
	// also what the proxy probes and dials.
	p.origDst = func(net.Conn) (string, error) { return backendAddr, nil }

	clientCert := testClientCert(t)
	resp := roundTripThroughTransparentTLS(t, p, backendIP, &tls.Config{
		ServerName:         backendIP, // IP literal: no SNI on the wire
		InsecureSkipVerify: true,      // #nosec G402 -- backend uses a test certificate
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

// TestTransparentTLSWithoutSNIUnknownDestination verifies that a connection
// the proxy cannot place at all is closed instead of being guessed at.
func TestTransparentTLSWithoutSNIUnknownDestination(t *testing.T) {
	p, _, _, _ := setupProxyWithCA(t)
	p.origDst = func(net.Conn) (string, error) { return "", errors.New("no conntrack entry") }

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
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "10.0.0.5", // IP literal: no SNI on the wire
		InsecureSkipVerify: true,       // #nosec G402 -- the handshake must fail anyway
	})
	if err := tlsConn.Handshake(); err == nil {
		t.Fatal("expected the handshake to fail for an unknown destination")
	}

	if !hasLogDetail(p, "no SNI provided and original destination unavailable") {
		t.Error("expected the dropped connection to be logged")
	}
}

// hasLogDetail reports whether any log entry contains the given text.
func hasLogDetail(p *Proxy, want string) bool {
	for _, entry := range p.Logger.Recent(100) {
		if strings.Contains(entry.Detail, want) {
			return true
		}
	}
	return false
}
