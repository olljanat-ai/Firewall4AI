// proxy_connect.go handles HTTP CONNECT tunnels via goproxy: MITM TLS
// inspection with per-request approval, and blind TCP tunneling fallback.

package proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/auth"
	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
)

// handleConnectDecision is the goproxy CONNECT handler. It decides whether to
// MITM (for TLS inspection), blind tunnel, or reject the connection.
func (p *Proxy) handleConnectDecision(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	start := time.Now()
	h := host
	if hp, _, err := net.SplitHostPort(host); err == nil {
		h = hp
	}
	sourceIP := extractSourceIP(ctx.Req.RemoteAddr)
	if p.OnActivity != nil {
		p.OnActivity(sourceIP)
	}

	var skill *auth.Skill // Agents are identified by IP, not by token.

	// For CONNECT with MITM, auto-approve hosts that belong to configured
	// infrastructure (registries, Helm repos, package repos, code libraries)
	// since the real access control happens per-item inside the tunnel.
	// For other hosts, check host-level approval. Per-request path checks
	// happen in handleMITMRequest via processRequest.
	// For blind tunnels (no MITM), use host-only check since we can't inspect paths.
	var status approval.Status
	if p.CA != nil && p.isConfiguredRepoHost(h) {
		status = approval.StatusApproved
	} else if p.CA != nil {
		status = p.checkHostApproval(h, skill, sourceIP)
	} else {
		status = p.checkApproval(h, "", skill, sourceIP)
	}
	if status != approval.StatusApproved {
		p.Logger.Add(proxylog.Entry{
			SkillID: getSkillID(skill),
			Method:  "CONNECT",
			Host:    h,
			Status:  string(status),
			Detail:  "host not approved",
		})
		ctx.Resp = errorResponse(ctx.Req, statusToHTTPCode(status), denialMessage(status, h))
		return goproxy.RejectConnect, host
	}

	// Use ConnectHijack to take over the connection and handle MITM/blind tunnel ourselves.
	// This preserves the CONNECT-level skill for inner MITM'd requests.
	return &goproxy.ConnectAction{
		Action: goproxy.ConnectHijack,
		Hijack: func(req *http.Request, client net.Conn, ctx *goproxy.ProxyCtx) {
			// goproxy's ConnectHijack does NOT write the 200 response;
			// we must send it before starting TLS or blind tunnel.
			client.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
			if p.CA != nil {
				p.handleMITM(client, h, host, skill, sourceIP, start)
			} else {
				p.handleBlindTunnel(client, h, host, skill, start)
			}
		},
	}, host
}

// newMITMTLSConfig returns a shared TLS configuration for MITM interception.
// The getCertFunc callback is invoked during the TLS handshake to provide the
// appropriate certificate for the connecting client.
func newMITMTLSConfig(getCertFunc func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		GetCertificate: getCertFunc,

		// Allow also TLS 1.0 and 1.1 (Go 1.22 set minimum to TLS 1.2)
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS13,

		// Disable experimental X25519Kyber768Draft00 (Go 1.23 enables it by default)
		// and disable X25519MLKEM768 (Go 1.24 enables it by default) by listing curve list from:
		// https://github.com/golang/go/blob/go1.23.5/src/crypto/tls/defaults.go#L20
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		},

		// Allow all ciphers, including those marked "insecure" by Go
		CipherSuites: func() []uint16 {
			all := append([]*tls.CipherSuite{}, tls.CipherSuites()...)
			all = append(all, tls.InsecureCipherSuites()...)
			var ids []uint16
			for _, cs := range all {
				ids = append(ids, cs.ID)
			}
			return ids
		}(),

		// Force HTTP/1.1 to avoid issues with HTTP/2 connection.
		NextProtos: []string{"http/1.1"},
	}
}

// handleMITM performs TLS MITM: terminates the client TLS with a generated cert,
// reads the inner HTTP requests, applies auth/approval/credential injection via
// processRequest, and writes responses back.
func (p *Proxy) handleMITM(clientConn net.Conn, host, targetAddr string, skill *auth.Skill, sourceIP string, start time.Time) {
	defer clientConn.Close()

	sid := getSkillID(skill)

	// Present a CA-signed certificate for this host to the client.
	hostCert, err := p.CA.GenerateHostCert(host)
	if err != nil {
		p.Logger.Add(proxylog.Entry{
			SkillID: sid,
			Method:  "CONNECT",
			Host:    host,
			Status:  "error",
			Detail:  "generate host cert: " + err.Error(),
		})
		return
	}
	tlsConfig := newMITMTLSConfig(func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if info.ServerName != "" && info.ServerName != host {
			return p.CA.GenerateHostCert(info.ServerName)
		}
		return hostCert, nil
	})

	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		p.Logger.Add(proxylog.Entry{
			SkillID: sid,
			Method:  "CONNECT",
			Host:    host,
			Status:  "error",
			Detail:  "MITM TLS handshake failed: " + err.Error(),
		})
		return
	}
	defer tlsClientConn.Close()

	p.Logger.Add(proxylog.Entry{
		SkillID:  sid,
		Method:   "CONNECT",
		Host:     host,
		Status:   "allowed",
		Detail:   "TLS MITM tunnel established",
		Duration: time.Since(start).Milliseconds(),
	})

	// Read HTTP requests from the decrypted client connection.
	reader := bufio.NewReader(tlsClientConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				p.Logger.Add(proxylog.Entry{
					SkillID: sid,
					Method:  "CONNECT",
					Host:    host,
					Status:  "error",
					Detail:  "read request: " + err.Error(),
				})
			}
			return
		}

		// Ensure targetAddr has a port for upstream forwarding.
		upstreamAddr := targetAddr
		if !strings.Contains(upstreamAddr, ":") {
			upstreamAddr += ":443"
		}

		// Set URL for HTTPS forwarding.
		req.URL.Scheme = "https"
		req.URL.Host = upstreamAddr
		req.Host = host

		resp, _ := p.processRequest(req, sourceIP)

		// Write response to the TLS connection.
		forwardTLS(tlsClientConn, resp)
		if resp.Body != nil {
			resp.Body.Close()
		}
	}
}

// handleBlindTunnel is the fallback when no CA is configured: just pipe bytes.
func (p *Proxy) handleBlindTunnel(clientConn net.Conn, host, targetAddr string, skill *auth.Skill, start time.Time) {
	if !strings.Contains(targetAddr, ":") {
		targetAddr += ":443"
	}

	sid := getSkillID(skill)

	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		p.Logger.Add(proxylog.Entry{
			SkillID:  sid,
			Method:   "CONNECT",
			Host:     host,
			Status:   "error",
			Detail:   err.Error(),
			Duration: time.Since(start).Milliseconds(),
		})
		clientConn.Close()
		return
	}

	p.Logger.Add(proxylog.Entry{
		SkillID:  sid,
		Method:   "CONNECT",
		Host:     host,
		Status:   "allowed",
		Detail:   "blind tunnel (no TLS inspection)",
		Duration: time.Since(start).Milliseconds(),
	})

	// Bidirectional copy.
	go func() {
		defer targetConn.Close()
		defer clientConn.Close()
		io.Copy(targetConn, clientConn)
	}()
	go func() {
		defer targetConn.Close()
		defer clientConn.Close()
		io.Copy(clientConn, targetConn)
	}()
}
