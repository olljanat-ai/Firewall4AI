// proxy_upstream.go configures the outbound (proxy -> internet) side of the
// proxy. Because the proxy terminates the agent's TLS session with its own CA,
// the upstream TLS session is established by the proxy itself. Upstream
// certificates that cannot be verified against the system trust store (internal
// PKI, self-signed appliances such as Kubernetes API servers) are accepted
// instead of failing the request, but every such connection is logged so the
// admin can see which hosts present untrusted certificates.

package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"time"

	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
)

// upstreamDialer is the TCP dialer used for all outbound connections.
var upstreamDialer = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
}

// allCipherSuites returns every cipher suite Go supports, including the ones
// it marks as insecure, so that legacy upstream servers and old agent clients
// can still negotiate a connection.
func allCipherSuites() []uint16 {
	all := append([]*tls.CipherSuite{}, tls.CipherSuites()...)
	all = append(all, tls.InsecureCipherSuites()...)
	ids := make([]uint16, 0, len(all))
	for _, cs := range all {
		ids = append(ids, cs.ID)
	}
	return ids
}

// newUpstreamTLSConfig returns the TLS configuration used when the proxy
// connects to an upstream server. Certificate verification is done manually in
// dialUpstreamTLS so an unverifiable certificate can be logged instead of
// breaking the request.
func newUpstreamTLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName: serverName,

		// Verification is performed by verifyUpstreamCert after the handshake;
		// its result is logged, never used to reject the connection.
		InsecureSkipVerify: true, // #nosec G402

		// Accept old servers too (Go 1.22 raised the client default to TLS 1.2).
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: allCipherSuites(),
	}
}

// verifyUpstreamCert validates the certificate chain presented by an upstream
// server against the system trust store and the expected hostname. It returns
// nil when the chain is trusted.
func verifyUpstreamCert(serverName string, state tls.ConnectionState) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("server presented no certificate")
	}
	opts := x509.VerifyOptions{
		DNSName:       serverName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range state.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}
	_, err := state.PeerCertificates[0].Verify(opts)
	return err
}

// dialUpstreamTLS establishes a TLS connection to an upstream server. The
// handshake never fails because of an untrusted or mismatched certificate;
// such certificates are logged and the connection continues.
func (p *Proxy) dialUpstreamTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	rawConn, err := upstreamDialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	tlsConn := tls.Client(rawConn, newUpstreamTLSConfig(host))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}

	if verr := verifyUpstreamCert(host, tlsConn.ConnectionState()); verr != nil && p.Logger != nil {
		p.Logger.Add(proxylog.Entry{
			Method: "TLS",
			Host:   host,
			Status: "allowed",
			Detail: "untrusted upstream certificate accepted: " + verr.Error(),
		})
	}

	return tlsConn, nil
}
