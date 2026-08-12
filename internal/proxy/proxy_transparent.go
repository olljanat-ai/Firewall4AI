// proxy_transparent.go handles transparent TLS interception: accepting
// connections redirected by iptables, determining the destination from the SNI
// hostname of the TLS ClientHello (falling back to the pre-DNAT destination for
// clients that send none, such as `curl https://10.0.0.5/`), and performing
// MITM inspection with per-request approval via the shared processRequest
// function. Hosts that authenticate clients with certificates are tunneled
// instead (see proxy_passthrough.go).

package proxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
)

// ServeTransparentTLS accepts connections from the given listener and handles
// them as transparent TLS interceptions.
func (p *Proxy) ServeTransparentTLS(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go p.HandleTransparentTLS(conn)
	}
}

// HandleTransparentTLS handles a raw TCP connection redirected by iptables for
// transparent HTTPS interception. The target host comes from the SNI server
// name, or from the pre-DNAT destination when the client sent none, and TLS is
// then terminated so requests can be read and forwarded via processRequest.
func (p *Proxy) HandleTransparentTLS(clientConn net.Conn) {
	defer clientConn.Close()

	if p.CA == nil {
		return
	}

	start := time.Now()
	sourceIP := extractSourceIP(clientConn.RemoteAddr().String())
	if p.OnActivity != nil {
		p.OnActivity(sourceIP)
	}

	// Read the ClientHello before answering it, so the destination is known
	// while the client's handshake can still be handed over untouched to the
	// upstream server if this host cannot be inspected.
	sniHost, clientHello, err := peekClientHello(clientConn, clientHelloTimeout)
	if err != nil {
		p.Logger.Add(proxylog.Entry{
			Method: "TRANSPARENT",
			Status: "error",
			Detail: "read TLS client hello: " + err.Error(),
		})
		return
	}
	// Clients that address a server by IP send no SNI; the destination then
	// only exists in the kernel's connection tracking.
	host, port, err := p.transparentDestination(clientConn, sniHost)
	if err != nil {
		p.Logger.Add(proxylog.Entry{
			Method: "TRANSPARENT",
			Status: "error",
			Detail: "no SNI provided and original destination unavailable: " + err.Error(),
		})
		return
	}
	addr := net.JoinHostPort(host, port)

	// Servers that authenticate clients with certificates cannot be MITM'd:
	// the proxy has no access to the client's private key. Tunnel instead.
	if p.shouldPassthrough(host, addr) {
		p.handleTLSPassthrough(clientConn, host, addr, clientHello, sourceIP, start)
		return
	}

	tlsConfig := newMITMTLSConfig(func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return p.CA.GenerateHostCert(host)
	})

	tlsConn := tls.Server(newReplayConn(clientConn, clientHello), tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		p.Logger.Add(proxylog.Entry{
			Method: "TRANSPARENT",
			Status: "error",
			Detail: "TLS handshake failed: " + err.Error(),
		})
		return
	}
	defer tlsConn.Close()

	// Read HTTP requests from the decrypted connection.
	reader := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				p.Logger.Add(proxylog.Entry{
					Method: "TRANSPARENT",
					Host:   host,
					Status: "error",
					Detail: "read request: " + err.Error(),
				})
			}
			return
		}

		p.handleTransparentTLSRequest(tlsConn, req, host, addr, sourceIP)
	}
}

// transparentDestination resolves where a transparently intercepted connection
// was originally headed, returning the host used for approvals, certificates
// and SNI, plus the upstream port.
//
// The SNI server name wins when the client sent one: approvals and certificates
// are keyed by hostname, and a redirected connection to a virtual host must not
// collapse into the shared IP behind it. The pre-DNAT destination recovered
// from netfilter supplies the port, and the host itself for clients that send
// no SNI because they addressed the server by IP.
func (p *Proxy) transparentDestination(conn net.Conn, sniHost string) (host, port string, err error) {
	host, port = sniHost, "443"

	origAddr, origErr := p.originalDst(conn)
	if origErr == nil {
		// A connection that reached this listener directly rather than through
		// a REDIRECT reports the listener's own address, which says nothing
		// about the client's intended destination.
		if local := conn.LocalAddr(); local != nil && origAddr == local.String() {
			origErr = errors.New("connection was not redirected")
		}
	}
	if origErr == nil {
		if origHost, origPort, splitErr := net.SplitHostPort(origAddr); splitErr == nil {
			if host == "" {
				host = origHost
			}
			port = origPort
		} else {
			origErr = splitErr
		}
	}

	if host == "" {
		return "", "", origErr
	}
	return host, port, nil
}

// originalDst returns the pre-DNAT destination of a redirected connection.
// Tests replace the lookup, which needs a real netfilter conntrack entry.
func (p *Proxy) originalDst(conn net.Conn) (string, error) {
	if p.origDst != nil {
		return p.origDst(conn)
	}
	return originalDestination(conn)
}

// handleTransparentTLSRequest processes a request from a transparent TLS
// connection via processRequest. host identifies the destination for approvals
// and logging, addr is the "host:port" the request is forwarded to.
func (p *Proxy) handleTransparentTLSRequest(clientConn net.Conn, req *http.Request, host, addr, sourceIP string) {
	// Set URL for HTTPS forwarding.
	req.URL.Scheme = "https"
	req.URL.Host = addr
	req.Host = host

	resp, _ := p.processRequest(req, sourceIP)
	if resp == nil {
		write502TLS(clientConn)
		return
	}

	// Write response to the TLS connection.
	forwardTLS(clientConn, resp)
	if resp.Body != nil {
		resp.Body.Close()
	}
}
