// proxy_transparent.go handles transparent TLS interception: accepting
// connections redirected by iptables, extracting the SNI hostname from
// the TLS ClientHello, and performing MITM inspection with per-request approval
// via the shared processRequest function.

package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"

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

// HandleTransparentTLS handles a raw TCP connection redirected by iptables
// for transparent HTTPS interception. It terminates TLS using SNI to
// determine the target host, then reads and forwards HTTP requests via
// processRequest.
func (p *Proxy) HandleTransparentTLS(clientConn net.Conn) {
	defer clientConn.Close()

	if p.CA == nil {
		return
	}

	sourceIP := extractSourceIP(clientConn.RemoteAddr().String())
	if p.OnActivity != nil {
		p.OnActivity(sourceIP)
	}
	var sniHost string

	tlsConfig := newMITMTLSConfig(func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		sniHost = info.ServerName
		if sniHost == "" {
			return nil, fmt.Errorf("no SNI provided for transparent TLS")
		}
		return p.CA.GenerateHostCert(sniHost)
	})

	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		p.Logger.Add(proxylog.Entry{
			Method: "TRANSPARENT",
			Status: "error",
			Detail: "TLS handshake failed: " + err.Error(),
		})
		return
	}
	defer tlsConn.Close()

	if sniHost == "" {
		return
	}

	// Read HTTP requests from the decrypted connection.
	reader := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				p.Logger.Add(proxylog.Entry{
					Method: "TRANSPARENT",
					Host:   sniHost,
					Status: "error",
					Detail: "read request: " + err.Error(),
				})
			}
			return
		}

		p.handleTransparentTLSRequest(tlsConn, req, sniHost, sourceIP)
	}
}

// handleTransparentTLSRequest processes a request from a transparent TLS
// connection via processRequest.
func (p *Proxy) handleTransparentTLSRequest(clientConn net.Conn, req *http.Request, host, sourceIP string) {
	// Set URL for HTTPS forwarding.
	req.URL.Scheme = "https"
	req.URL.Host = host + ":443"
	req.Host = host

	resp, _ := p.processRequest(req, sourceIP)

	// Write response to the TLS connection.
	forwardTLS(clientConn, resp)
	if resp.Body != nil {
		resp.Body.Close()
	}
}
