// Package proxy implements the transparent HTTP+HTTPS proxy with approval gates
// and TLS MITM inspection for HTTPS traffic.
package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/auth"
	"github.com/olljanat-ai/firewall4ai/internal/certgen"
	"github.com/olljanat-ai/firewall4ai/internal/config"
	"github.com/olljanat-ai/firewall4ai/internal/credentials"
	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
	"github.com/olljanat-ai/firewall4ai/internal/registry"
)

const (
	approvalTimeout = 5 * time.Minute
	// AuthHeader is used by AI agents to provide their skill token.
	AuthHeader = "X-Firewall4AI-Token"
	// maxFullLogBody is the maximum body size captured in full logging mode.
	maxFullLogBody = 64 * 1024 // 64 KB
)

// Proxy is the main proxy server.
type Proxy struct {
	Skills          *auth.SkillStore
	Approvals       *approval.Manager
	ImageApprovals  *approval.Manager // image-level approvals for container registries
	Registries      []config.RegistryConfig
	Credentials     *credentials.Manager
	Logger          *proxylog.Logger
	Transport       http.RoundTripper
	CA              *certgen.CA
	ApprovalTimeout time.Duration
}

// New creates a new Proxy with the given dependencies.
func New(skills *auth.SkillStore, approvals *approval.Manager, creds *credentials.Manager, logger *proxylog.Logger) *Proxy {
	return &Proxy{
		Skills:          skills,
		Approvals:       approvals,
		Credentials:     creds,
		Logger:          logger,
		ApprovalTimeout: approvalTimeout,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}
}

// ServeHTTP handles both HTTP requests and HTTPS CONNECT tunnels.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// extractHost returns the host (without port) from the request.
func extractHost(r *http.Request) string {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// extractSourceIP returns the IP address (without port) from a remote address string.
func extractSourceIP(remoteAddr string) string {
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return h
	}
	return remoteAddr
}

// getSkillID returns the skill ID or empty string for nil skills.
func getSkillID(skill *auth.Skill) string {
	if skill == nil {
		return ""
	}
	return skill.ID
}

// authenticateOptional extracts and validates the skill token.
// Returns (nil, nil) if no token is provided (anonymous access).
// Returns (nil, error) if an invalid token is provided.
func (p *Proxy) authenticateOptional(r *http.Request) (*auth.Skill, error) {
	token := r.Header.Get(AuthHeader)
	if token == "" {
		return nil, nil
	}
	skill, ok := p.Skills.Authenticate(token)
	if !ok {
		return nil, fmt.Errorf("invalid or inactive token")
	}
	return skill, nil
}

// checkApproval verifies the host+path is approved using three levels:
//  1. Global (skillID="" and sourceIP="") — applies to all agents on all VMs
//  2. VM-specific (skillID="" and sourceIP set) — applies to all agents on that VM
//  3. Skill-specific (skillID set) — applies to agents using that skill
//
// Checks are performed broadest-first. If no existing decision is found,
// a pending entry is registered at the most specific applicable level.
// The path parameter enables fine-grained URL path approval; empty path
// means host-level only (used for blind CONNECT tunnels).
func (p *Proxy) checkApproval(host, path string, skill *auth.Skill, sourceIP string) approval.Status {
	// Check pre-approved hosts for authenticated requests.
	if skill != nil && p.Skills.IsHostPreApproved(skill.Token, host) {
		return approval.StatusApproved
	}

	// 1. Check global approval (host+path approved/denied for all agents).
	if globalStatus, exists := p.Approvals.CheckExistingWithPath(host, path, "", ""); exists && globalStatus != approval.StatusPending {
		return globalStatus
	}

	// 2. Check VM-specific approval.
	if sourceIP != "" {
		if vmStatus, exists := p.Approvals.CheckExistingWithPath(host, path, "", sourceIP); exists && vmStatus != approval.StatusPending {
			return vmStatus
		}
	}

	// 3. Check skill-specific approval.
	if skill != nil {
		if skillStatus, exists := p.Approvals.CheckExistingWithPath(host, path, skill.ID, ""); exists && skillStatus != approval.StatusPending {
			return skillStatus
		}
	}

	// No decision found. Register as pending at the most specific level.
	// Skill-specific takes precedence over VM-specific.
	sid := getSkillID(skill)
	pendingIP := sourceIP
	if sid != "" {
		pendingIP = "" // skill-level pending, not VM-level
	}
	status := p.Approvals.Check(host, sid, pendingIP, path)
	if status == approval.StatusPending {
		status = p.Approvals.WaitForDecision(host, sid, pendingIP, path, p.ApprovalTimeout)
	}
	return status
}

// checkHostApproval checks if any approval (host-only or path-specific)
// exists for the host. Used for CONNECT+MITM where the tunnel must be
// allowed if any path-specific approval exists, since per-request checks
// will enforce path restrictions inside the tunnel.
func (p *Proxy) checkHostApproval(host string, skill *auth.Skill, sourceIP string) approval.Status {
	// Check pre-approved hosts.
	if skill != nil && p.Skills.IsHostPreApproved(skill.Token, host) {
		return approval.StatusApproved
	}

	// 1. Global: any approval for this host.
	if status, exists := p.Approvals.CheckExistingForHost(host, "", ""); exists && status != approval.StatusPending {
		return status
	}

	// 2. VM-specific.
	if sourceIP != "" {
		if status, exists := p.Approvals.CheckExistingForHost(host, "", sourceIP); exists && status != approval.StatusPending {
			return status
		}
	}

	// 3. Skill-specific.
	if skill != nil {
		if status, exists := p.Approvals.CheckExistingForHost(host, skill.ID, ""); exists && status != approval.StatusPending {
			return status
		}
	}

	// No approval found. Register pending at host level (no path) and wait.
	sid := getSkillID(skill)
	pendingIP := sourceIP
	if sid != "" {
		pendingIP = ""
	}
	status := p.Approvals.Check(host, sid, pendingIP, "")
	if status == approval.StatusPending {
		status = p.Approvals.WaitForDecision(host, sid, pendingIP, "", p.ApprovalTimeout)
	}
	return status
}

// checkImageApproval performs three-level image approval for registry manifests.
func (p *Proxy) checkImageApproval(imageRef string, skill *auth.Skill, sourceIP string) approval.Status {
	sid := getSkillID(skill)

	// 1. Global.
	if status, ok := p.ImageApprovals.CheckExistingWithMatcher(imageRef, "", "", registry.MatchImageRef); ok && status != approval.StatusPending {
		return status
	}
	// 2. VM-specific.
	if sourceIP != "" {
		if status, ok := p.ImageApprovals.CheckExistingWithMatcher(imageRef, "", sourceIP, registry.MatchImageRef); ok && status != approval.StatusPending {
			return status
		}
	}
	// 3. Skill-specific.
	if sid != "" {
		if status, ok := p.ImageApprovals.CheckExistingWithMatcher(imageRef, sid, "", registry.MatchImageRef); ok && status != approval.StatusPending {
			return status
		}
	}

	// Register pending at the most specific level and wait.
	pendingIP := sourceIP
	if sid != "" {
		pendingIP = ""
	}
	p.ImageApprovals.Check(imageRef, sid, pendingIP, "")
	return p.ImageApprovals.WaitForDecision(imageRef, sid, pendingIP, "", p.ApprovalTimeout)
}

// captureRequestBody reads the request body (up to maxFullLogBody) and replaces it
// with a new reader so the request can still be forwarded.
func captureRequestBody(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxFullLogBody+1))
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return ""
	}
	if len(body) > maxFullLogBody {
		return string(body[:maxFullLogBody]) + "... (truncated)"
	}
	return string(body)
}

// captureResponseBody reads the response body (up to maxFullLogBody).
func captureResponseBody(resp *http.Response) string {
	if resp.Body == nil {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFullLogBody+1))
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return ""
	}
	if len(body) > maxFullLogBody {
		return string(body[:maxFullLogBody]) + "... (truncated)"
	}
	return string(body)
}

// getLoggingMode returns the logging mode for the request's host/path.
func (p *Proxy) getLoggingMode(host, path string, skill *auth.Skill, sourceIP string) approval.LoggingMode {
	sid := getSkillID(skill)
	return p.Approvals.GetLoggingMode(host, path, sid, sourceIP)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := extractHost(r)
	sourceIP := extractSourceIP(r.RemoteAddr)

	skill, err := p.authenticateOptional(r)
	if err != nil {
		p.Logger.Add(proxylog.Entry{
			Method: r.Method,
			Host:   host,
			Path:   r.URL.Path,
			Status: "denied",
			Detail: "auth failed: " + err.Error(),
		})
		http.Error(w, "Proxy authentication failed: "+err.Error(), http.StatusProxyAuthRequired)
		return
	}

	sid := getSkillID(skill)

	// Remove our custom header before forwarding.
	r.Header.Del(AuthHeader)

	status := p.checkApproval(host, r.URL.Path, skill, sourceIP)
	if status != approval.StatusApproved {
		p.Logger.Add(proxylog.Entry{
			SkillID: sid,
			Method:  r.Method,
			Host:    host,
			Path:    r.URL.Path,
			Status:  string(status),
			Detail:  "host not approved",
		})
		http.Error(w, fmt.Sprintf("Access to %s is %s. Awaiting admin approval.", host, status), http.StatusForbidden)
		return
	}

	// Check logging mode before injecting credentials (capture pre-injection headers).
	logMode := p.getLoggingMode(host, r.URL.Path, skill, sourceIP)
	var fullDetail *proxylog.FullDetail
	if logMode == approval.LoggingModeFull {
		reqBody := captureRequestBody(r)
		fullDetail = &proxylog.FullDetail{
			RequestHeaders: r.Header.Clone(),
			RequestBody:    reqBody,
		}
	}

	// Inject credentials.
	p.Credentials.InjectForRequest(r, sid)

	// Forward the request.
	r.RequestURI = ""
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}

	resp, err := p.Transport.RoundTrip(r)
	if err != nil {
		p.Logger.Add(proxylog.Entry{
			SkillID:    sid,
			Method:     r.Method,
			Host:       host,
			Path:       r.URL.Path,
			Status:     "error",
			Detail:     err.Error(),
			Duration:   time.Since(start).Milliseconds(),
			HasFullLog: fullDetail != nil,
			FullDetail: fullDetail,
		})
		http.Error(w, "Proxy error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if fullDetail != nil {
		fullDetail.ResponseHeaders = resp.Header.Clone()
		fullDetail.ResponseStatus = resp.StatusCode
		fullDetail.ResponseBody = captureResponseBody(resp)
	}

	p.Logger.Add(proxylog.Entry{
		SkillID:    sid,
		Method:     r.Method,
		Host:       host,
		Path:       r.URL.Path,
		Status:     "allowed",
		Detail:     fmt.Sprintf("%d %s", resp.StatusCode, resp.Status),
		Duration:   time.Since(start).Milliseconds(),
		HasFullLog: fullDetail != nil,
		FullDetail: fullDetail,
	})

	// Copy response headers.
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	targetHost := r.Host
	host := targetHost
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	sourceIP := extractSourceIP(r.RemoteAddr)

	skill, err := p.authenticateOptional(r)
	if err != nil {
		p.Logger.Add(proxylog.Entry{
			Method: "CONNECT",
			Host:   host,
			Status: "denied",
			Detail: "auth failed: " + err.Error(),
		})
		http.Error(w, "Proxy authentication failed: "+err.Error(), http.StatusProxyAuthRequired)
		return
	}

	// For CONNECT with MITM, check if any approval (host-only or path-specific)
	// exists. Per-request path checks happen in handleMITMRequest.
	// For blind tunnels (no MITM), use host-only check since we can't inspect paths.
	var status approval.Status
	if p.CA != nil {
		status = p.checkHostApproval(host, skill, sourceIP)
	} else {
		status = p.checkApproval(host, "", skill, sourceIP)
	}
	if status != approval.StatusApproved {
		p.Logger.Add(proxylog.Entry{
			SkillID: getSkillID(skill),
			Method:  "CONNECT",
			Host:    host,
			Status:  string(status),
			Detail:  "host not approved",
		})
		http.Error(w, fmt.Sprintf("CONNECT to %s is %s. Awaiting admin approval.", host, status), http.StatusForbidden)
		return
	}

	// Hijack the client connection.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Send 200 OK to tell the client the tunnel is established.
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// If we have a CA, perform TLS MITM inspection.
	if p.CA != nil {
		p.handleMITM(clientConn, host, targetHost, skill, sourceIP, start)
		return
	}

	// Fallback: blind tunnel (no inspection).
	p.handleBlindTunnel(clientConn, host, targetHost, skill, start)
}

// handleMITM performs TLS MITM: terminates the client TLS with a generated cert,
// reads the inner HTTP requests, applies auth/approval/credential injection,
// and forwards them to the real target over a new TLS connection.
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
	tlsConfig := &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if info.ServerName != "" && info.ServerName != host {
				return p.CA.GenerateHostCert(info.ServerName)
			}
			return hostCert, nil
		},
		MinVersion: tls.VersionTLS12,
	}

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

		p.handleMITMRequest(tlsClientConn, req, host, targetAddr, skill, sourceIP)
	}
}

// handleMITMRequest processes a single HTTP request read from the MITM'd TLS connection.
func (p *Proxy) handleMITMRequest(clientConn net.Conn, req *http.Request, host, targetAddr string, skill *auth.Skill, sourceIP string) {
	start := time.Now()
	sid := getSkillID(skill)

	// Remove proxy auth header if client re-sent it inside the tunnel.
	req.Header.Del(AuthHeader)

	// Check if this is a container registry request.
	if reg := registry.RegistryForHost(host, p.Registries); reg != nil {
		p.handleRegistryTLSRequest(clientConn, req, host, sourceIP, skill, reg, start)
		return
	}

	// Check path-level approval for this specific request.
	status := p.checkApproval(host, req.URL.Path, skill, sourceIP)
	if status != approval.StatusApproved {
		p.Logger.Add(proxylog.Entry{
			SkillID: sid,
			Method:  req.Method,
			Host:    host,
			Path:    req.URL.Path,
			Status:  string(status),
			Detail:  "path not approved",
		})
		resp := &http.Response{
			StatusCode: http.StatusForbidden,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
		}
		resp.Write(clientConn)
		return
	}

	// Check logging mode.
	logMode := p.getLoggingMode(host, req.URL.Path, skill, sourceIP)
	var fullDetail *proxylog.FullDetail
	if logMode == approval.LoggingModeFull {
		reqBody := captureRequestBody(req)
		fullDetail = &proxylog.FullDetail{
			RequestHeaders: req.Header.Clone(),
			RequestBody:    reqBody,
		}
	}

	// Set the URL for forwarding.
	req.URL.Scheme = "https"
	req.URL.Host = targetAddr
	if !strings.Contains(targetAddr, ":") {
		req.URL.Host = targetAddr + ":443"
	}
	req.RequestURI = ""

	// Inject credentials for HTTPS requests.
	p.Credentials.InjectForRequest(req, sid)

	resp, err := p.Transport.RoundTrip(req)
	if err != nil {
		p.Logger.Add(proxylog.Entry{
			SkillID:    sid,
			Method:     req.Method,
			Host:       host,
			Path:       req.URL.Path,
			Status:     "error",
			Detail:     err.Error(),
			Duration:   time.Since(start).Milliseconds(),
			HasFullLog: fullDetail != nil,
			FullDetail: fullDetail,
		})
		// Send a 502 response to the client.
		resp502 := &http.Response{
			StatusCode: http.StatusBadGateway,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
		}
		resp502.Write(clientConn)
		return
	}
	defer resp.Body.Close()

	if fullDetail != nil {
		fullDetail.ResponseHeaders = resp.Header.Clone()
		fullDetail.ResponseStatus = resp.StatusCode
		fullDetail.ResponseBody = captureResponseBody(resp)
	}

	p.Logger.Add(proxylog.Entry{
		SkillID:    sid,
		Method:     req.Method,
		Host:       host,
		Path:       req.URL.Path,
		Status:     "allowed",
		Detail:     fmt.Sprintf("%d %s", resp.StatusCode, resp.Status),
		Duration:   time.Since(start).Milliseconds(),
		HasFullLog: fullDetail != nil,
		FullDetail: fullDetail,
	})

	// Write response back to client.
	resp.Write(clientConn)
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

// HandleTransparentTLS handles a raw TCP connection redirected by iptables
// for transparent HTTPS interception. It terminates TLS using SNI to
// determine the target host, then reads and forwards HTTP requests.
func (p *Proxy) HandleTransparentTLS(clientConn net.Conn) {
	defer clientConn.Close()

	if p.CA == nil {
		return
	}

	sourceIP := extractSourceIP(clientConn.RemoteAddr().String())
	var sniHost string

	tlsConfig := &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sniHost = info.ServerName
			if sniHost == "" {
				return nil, fmt.Errorf("no SNI provided for transparent TLS")
			}
			return p.CA.GenerateHostCert(sniHost)
		},
		MinVersion: tls.VersionTLS12,
	}

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

// handleTransparentTLSRequest processes a single HTTP request from a
// transparent TLS connection.
func (p *Proxy) handleTransparentTLSRequest(clientConn net.Conn, req *http.Request, host, sourceIP string) {
	start := time.Now()

	// Authenticate (optional in transparent mode).
	skill, err := p.authenticateOptional(req)
	if err != nil {
		p.Logger.Add(proxylog.Entry{
			Method: req.Method,
			Host:   host,
			Path:   req.URL.Path,
			Status: "denied",
			Detail: "auth failed: " + err.Error(),
		})
		resp := &http.Response{
			StatusCode: http.StatusProxyAuthRequired,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
		}
		resp.Write(clientConn)
		return
	}

	sid := getSkillID(skill)
	req.Header.Del(AuthHeader)

	// Check if this is a container registry request.
	if reg := registry.RegistryForHost(host, p.Registries); reg != nil {
		p.handleRegistryTLSRequest(clientConn, req, host, sourceIP, skill, reg, start)
		return
	}

	status := p.checkApproval(host, req.URL.Path, skill, sourceIP)
	if status != approval.StatusApproved {
		p.Logger.Add(proxylog.Entry{
			SkillID: sid,
			Method:  req.Method,
			Host:    host,
			Path:    req.URL.Path,
			Status:  string(status),
			Detail:  "host not approved",
		})
		resp := &http.Response{
			StatusCode: http.StatusForbidden,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
		}
		resp.Write(clientConn)
		return
	}

	// Check logging mode.
	logMode := p.getLoggingMode(host, req.URL.Path, skill, sourceIP)
	var fullDetail *proxylog.FullDetail
	if logMode == approval.LoggingModeFull {
		reqBody := captureRequestBody(req)
		fullDetail = &proxylog.FullDetail{
			RequestHeaders: req.Header.Clone(),
			RequestBody:    reqBody,
		}
	}

	// Set URL for forwarding to the real backend.
	req.URL.Scheme = "https"
	req.URL.Host = host + ":443"
	req.RequestURI = ""

	// Inject credentials.
	p.Credentials.InjectForRequest(req, sid)

	resp, err := p.Transport.RoundTrip(req)
	if err != nil {
		p.Logger.Add(proxylog.Entry{
			SkillID:    sid,
			Method:     req.Method,
			Host:       host,
			Path:       req.URL.Path,
			Status:     "error",
			Detail:     err.Error(),
			Duration:   time.Since(start).Milliseconds(),
			HasFullLog: fullDetail != nil,
			FullDetail: fullDetail,
		})
		resp502 := &http.Response{
			StatusCode: http.StatusBadGateway,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
		}
		resp502.Write(clientConn)
		return
	}
	defer resp.Body.Close()

	if fullDetail != nil {
		fullDetail.ResponseHeaders = resp.Header.Clone()
		fullDetail.ResponseStatus = resp.StatusCode
		fullDetail.ResponseBody = captureResponseBody(resp)
	}

	p.Logger.Add(proxylog.Entry{
		SkillID:    sid,
		Method:     req.Method,
		Host:       host,
		Path:       req.URL.Path,
		Status:     "allowed",
		Detail:     fmt.Sprintf("%d %s", resp.StatusCode, resp.Status),
		Duration:   time.Since(start).Milliseconds(),
		HasFullLog: fullDetail != nil,
		FullDetail: fullDetail,
	})

	resp.Write(clientConn)
}

// handleRegistryTLSRequest handles a request to a known container registry host.
// Manifest requests trigger image-level approval; blob requests use repo-level
// approval; all other registry traffic (auth, /v2/ pings) is auto-approved.
func (p *Proxy) handleRegistryTLSRequest(clientConn net.Conn, req *http.Request, host, sourceIP string, skill *auth.Skill, reg *config.RegistryConfig, start time.Time) {
	sid := getSkillID(skill)
	urlPath := req.URL.Path

	name, _, pathType, isV2 := registry.ParsePath(urlPath)

	if isV2 && (pathType == "manifests" || pathType == "blobs") {
		// Manifest and blob requests use repo-level approval.
		// Approving a repo allows all tags, digests, and layers.
		repo := registry.ParseImageRepo(reg.Name, name)
		if !registry.CheckRepoApproval(p.ImageApprovals, repo) {
			if pathType == "blobs" {
				// Blobs don't create pending entries; they are only
				// allowed if the repo was already approved via a manifest.
				p.Logger.Add(proxylog.Entry{
					SkillID: sid,
					Method:  req.Method,
					Host:    host,
					Path:    urlPath,
					Status:  "denied",
					Detail:  "repository not approved: " + repo,
				})
				resp := &http.Response{
					StatusCode: http.StatusForbidden,
					ProtoMajor: 1,
					ProtoMinor: 1,
					Header:     make(http.Header),
				}
				resp.Write(clientConn)
				return
			}
			// Manifest: register pending and wait for admin decision.
			status := p.checkImageApproval(repo, skill, sourceIP)
			if status != approval.StatusApproved {
				p.Logger.Add(proxylog.Entry{
					SkillID: sid,
					Method:  req.Method,
					Host:    host,
					Path:    urlPath,
					Status:  string(status),
					Detail:  "image not approved: " + repo,
				})
				resp := &http.Response{
					StatusCode: http.StatusForbidden,
					ProtoMajor: 1,
					ProtoMinor: 1,
					Header:     make(http.Header),
				}
				resp.Write(clientConn)
				return
			}
		}
		p.Logger.Add(proxylog.Entry{
			SkillID:  sid,
			Method:   req.Method,
			Host:     host,
			Path:     urlPath,
			Status:   "allowed",
			Detail:   repo,
			Duration: time.Since(start).Milliseconds(),
		})
	} else {
		// Other registry traffic (auth, /v2/ ping, etc.): auto-approve.
		p.Logger.Add(proxylog.Entry{
			SkillID:  sid,
			Method:   req.Method,
			Host:     host,
			Path:     urlPath,
			Status:   "allowed",
			Detail:   "registry infra",
			Duration: time.Since(start).Milliseconds(),
		})
	}

	// Forward to the real backend.
	req.URL.Scheme = "https"
	req.URL.Host = host + ":443"
	req.RequestURI = ""

	resp, err := p.Transport.RoundTrip(req)
	if err != nil {
		p.Logger.Add(proxylog.Entry{
			SkillID:  sid,
			Method:   req.Method,
			Host:     host,
			Path:     urlPath,
			Status:   "error",
			Detail:   err.Error(),
			Duration: time.Since(start).Milliseconds(),
		})
		resp502 := &http.Response{
			StatusCode: http.StatusBadGateway,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
		}
		resp502.Write(clientConn)
		return
	}
	defer resp.Body.Close()

	resp.Write(clientConn)
}

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
