// proxy_passthrough.go implements TLS passthrough for upstream servers that
// authenticate their clients with certificates (mutual TLS), such as Kubernetes
// API servers.
//
// Those connections cannot be inspected: the proxy terminates the client's TLS
// session, and it has no access to the client's private key, so the session the
// proxy opens to the upstream server carries no client certificate at all. The
// server then rejects the request ("the server has asked for the client to
// provide credentials"). For such hosts the proxy splices the raw TCP stream
// instead, so the client's own TLS session — and with it its certificate —
// reaches the server untouched. Access control stays at the host level, since
// nothing inside the tunnel is visible.

package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
)

const (
	// clientCertProbeTTL is how long the result of a client-certificate probe
	// is reused before the upstream server is probed again.
	clientCertProbeTTL = 30 * time.Minute

	// clientCertProbeTimeout bounds a single probe handshake.
	clientCertProbeTimeout = 10 * time.Second

	// clientHelloTimeout bounds how long the proxy waits for a client to send
	// its TLS ClientHello on a transparently intercepted connection.
	clientHelloTimeout = 30 * time.Second
)

// clientCertProbe caches whether an upstream server asks for a client
// certificate during the TLS handshake.
type clientCertProbe struct {
	required  bool
	checkedAt time.Time
}

// upstreamAddr returns addr with the default HTTPS port appended when the
// address carries no port.
func upstreamAddr(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, "443")
}

// isPassthroughHost reports whether the host is listed in the configured
// TLS passthrough list, which forces passthrough without probing. Entries
// support the same `*.example.com` wildcards as approvals.
func (p *Proxy) isPassthroughHost(host string) bool {
	for _, pattern := range p.TLSPassthroughHosts {
		if approval.MatchHost(pattern, host) {
			return true
		}
	}
	return false
}

// shouldPassthrough reports whether connections to the given host must be
// tunneled without inspection. addr is the upstream address including port,
// host the hostname used for SNI.
//
// Configured infrastructure hosts (registries, Helm repos, package repos, code
// libraries) are never tunneled automatically: they authenticate with tokens,
// and tunneling them would silently disable image and package approval. An
// explicit entry in TLSPassthroughHosts still wins.
func (p *Proxy) shouldPassthrough(host, addr string) bool {
	if p.isPassthroughHost(host) {
		return true
	}
	if p.isConfiguredRepoHost(host) {
		return false
	}
	return p.upstreamRequiresClientCert(host, addr)
}

// upstreamRequiresClientCert reports whether the upstream server asks its
// clients for a certificate, which makes the connection impossible to inspect.
// Probe results are cached per address.
func (p *Proxy) upstreamRequiresClientCert(host, addr string) bool {
	p.probeMu.Lock()
	if probe, ok := p.clientCertProbes[addr]; ok && time.Since(probe.checkedAt) < clientCertProbeTTL {
		p.probeMu.Unlock()
		return probe.required
	}
	p.probeMu.Unlock()

	required, err := probeClientCertRequest(addr, host)
	if err != nil && !required {
		// The probe could not complete (network error, unreachable host).
		// Fall back to normal inspection and retry on the next connection.
		return false
	}

	p.probeMu.Lock()
	if p.clientCertProbes == nil {
		p.clientCertProbes = make(map[string]clientCertProbe)
	}
	p.clientCertProbes[addr] = clientCertProbe{required: required, checkedAt: time.Now()}
	p.probeMu.Unlock()

	if required && p.Logger != nil {
		p.Logger.Add(proxylog.Entry{
			Method: "TLS",
			Host:   host,
			Status: "allowed",
			Detail: "upstream requests a client certificate: TLS inspection disabled for this host",
		})
	}
	return required
}

// probeClientCertRequest opens a throw-away TLS handshake to the upstream
// server and reports whether the server asked the client for a certificate.
// The handshake error is returned as well: a server that *requires* a client
// certificate aborts the handshake after the proxy offers none, which is still
// a positive detection.
func probeClientCertRequest(addr, serverName string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), clientCertProbeTimeout)
	defer cancel()

	rawConn, err := upstreamDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer rawConn.Close()

	var requested bool
	cfg := newUpstreamTLSConfig(serverName)
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		requested = true
		return &tls.Certificate{}, nil // the proxy has no certificate to offer
	}

	tlsConn := tls.Client(rawConn, cfg)
	err = tlsConn.HandshakeContext(ctx)
	tlsConn.Close()
	return requested, err
}

// handleTLSPassthrough tunnels a transparently intercepted TLS connection to
// its destination without inspecting it. clientHello holds the ClientHello
// bytes already consumed from clientConn; they are replayed to the upstream
// server so the client's handshake continues end to end.
func (p *Proxy) handleTLSPassthrough(clientConn net.Conn, host string, clientHello []byte, sourceIP string, start time.Time) {
	// Only host-level approvals authorize a passthrough: paths, packages and
	// image references cannot be enforced on a stream the proxy cannot read.
	status := p.checkApproval(host, "", nil, sourceIP)
	if status != approval.StatusApproved {
		p.Logger.Add(proxylog.Entry{
			Method: "TRANSPARENT",
			Host:   host,
			Status: string(status),
			Detail: "host not approved (TLS passthrough)",
		})
		return
	}

	dial := p.dialUpstream
	if dial == nil {
		dial = func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, 10*time.Second)
		}
	}

	upstream, err := dial("tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		p.Logger.Add(proxylog.Entry{
			Method:   "TRANSPARENT",
			Host:     host,
			Status:   "error",
			Detail:   "TLS passthrough dial: " + err.Error(),
			Duration: time.Since(start).Milliseconds(),
		})
		return
	}
	defer upstream.Close()

	if _, err := upstream.Write(clientHello); err != nil {
		p.Logger.Add(proxylog.Entry{
			Method:   "TRANSPARENT",
			Host:     host,
			Status:   "error",
			Detail:   "TLS passthrough write: " + err.Error(),
			Duration: time.Since(start).Milliseconds(),
		})
		return
	}

	p.Logger.Add(proxylog.Entry{
		Method:   "TRANSPARENT",
		Host:     host,
		Status:   "allowed",
		Detail:   "TLS passthrough (client certificate authentication, no inspection)",
		Duration: time.Since(start).Milliseconds(),
	})

	spliceConns(clientConn, upstream)
}

// spliceConns copies data in both directions until either side closes,
// then returns.
func spliceConns(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(a, b)
		closeWrite(a)
	}()
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		closeWrite(b)
	}()
	wg.Wait()
}

// closeWrite half-closes a connection when possible so the peer sees EOF
// while data can still flow the other way.
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}

// errClientHelloCaptured aborts the throw-away handshake used to read the
// ClientHello once the information the proxy needs has been captured.
var errClientHelloCaptured = errors.New("client hello captured")

// peekClientHello reads the TLS ClientHello from conn and returns the SNI
// server name together with the raw bytes consumed. The bytes must be replayed
// to whoever continues the handshake: a local TLS server for MITM, or the
// upstream server for passthrough.
func peekClientHello(conn net.Conn, timeout time.Duration) (serverName string, raw []byte, err error) {
	if timeout > 0 {
		conn.SetReadDeadline(time.Now().Add(timeout))
		defer conn.SetReadDeadline(time.Time{})
	}

	var recorded bytes.Buffer
	peek := tls.Server(readOnlyConn{reader: io.TeeReader(conn, &recorded)}, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			serverName = hello.ServerName
			return nil, errClientHelloCaptured
		},
	})
	err = peek.Handshake()
	if !errors.Is(err, errClientHelloCaptured) {
		if err == nil {
			err = errors.New("no client hello received")
		}
		return "", recorded.Bytes(), err
	}
	return serverName, recorded.Bytes(), nil
}

// replayConn re-serves already consumed bytes before reading from the
// underlying connection. Writes go straight to the connection.
type replayConn struct {
	net.Conn
	reader io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// newReplayConn returns conn with the given bytes prepended to its read stream.
func newReplayConn(conn net.Conn, replay []byte) net.Conn {
	return &replayConn{Conn: conn, reader: io.MultiReader(bytes.NewReader(replay), conn)}
}

// readOnlyConn adapts a reader to net.Conn and discards everything written to
// it. It lets a TLS server parse a ClientHello without sending anything back
// to the client.
type readOnlyConn struct{ reader io.Reader }

func (c readOnlyConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c readOnlyConn) Write(p []byte) (int, error) { return len(p), nil }
func (c readOnlyConn) Close() error                { return nil }
func (c readOnlyConn) LocalAddr() net.Addr         { return nil }
func (c readOnlyConn) RemoteAddr() net.Addr        { return nil }
func (c readOnlyConn) SetDeadline(time.Time) error { return nil }

func (c readOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (c readOnlyConn) SetWriteDeadline(time.Time) error { return nil }
