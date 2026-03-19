// Package proxy implements the transparent HTTP+HTTPS proxy with approval gates.
package proxy
 
import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
 
	"github.com/olljanat-ai/squid4claw/internal/approval"
	"github.com/olljanat-ai/squid4claw/internal/auth"
	"github.com/olljanat-ai/squid4claw/internal/credentials"
	proxylog "github.com/olljanat-ai/squid4claw/internal/logging"
)
 
const (
	approvalTimeout = 5 * time.Minute
	// Header used by AI agents to provide their skill token.
	AuthHeader = "X-Squid4Claw-Token"
)
 
// Proxy is the main proxy server.
type Proxy struct {
	Skills      *auth.SkillStore
	Approvals   *approval.Manager
	Credentials *credentials.Manager
	Logger      *proxylog.Logger
	Transport   http.RoundTripper
}
 
// New creates a new Proxy with the given dependencies.
func New(skills *auth.SkillStore, approvals *approval.Manager, creds *credentials.Manager, logger *proxylog.Logger) *Proxy {
	return &Proxy{
		Skills:      skills,
		Approvals:   approvals,
		Credentials: creds,
		Logger:      logger,
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
 
// authenticate extracts and validates the skill token.
func (p *Proxy) authenticate(r *http.Request) (*auth.Skill, error) {
	token := r.Header.Get(AuthHeader)
	if token == "" {
		return nil, fmt.Errorf("missing %s header", AuthHeader)
	}
	skill, ok := p.Skills.Authenticate(token)
	if !ok {
		return nil, fmt.Errorf("invalid or inactive token")
	}
	return skill, nil
}
 
// checkApproval verifies the host is approved for this skill.
func (p *Proxy) checkApproval(host string, skill *auth.Skill) approval.Status {
	// Check if host is pre-approved in skill config.
	if p.Skills.IsHostPreApproved(skill.Token, host) {
		return approval.StatusApproved
	}
 
	status := p.Approvals.Check(host, skill.ID)
	if status == approval.StatusPending {
		// Block and wait for admin decision.
		status = p.Approvals.WaitForDecision(host, skill.ID, approvalTimeout)
	}
	return status
}
 
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := extractHost(r)
 
	skill, err := p.authenticate(r)
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
 
	// Remove our custom header before forwarding.
	r.Header.Del(AuthHeader)
 
	status := p.checkApproval(host, skill)
	if status != approval.StatusApproved {
		p.Logger.Add(proxylog.Entry{
			SkillID: skill.ID,
			Method:  r.Method,
			Host:    host,
			Path:    r.URL.Path,
			Status:  string(status),
			Detail:  "host not approved",
		})
		http.Error(w, fmt.Sprintf("Access to %s is %s. Awaiting admin approval.", host, status), http.StatusForbidden)
		return
	}
 
	// Inject credentials.
	p.Credentials.InjectForRequest(r, skill.ID)
 
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
			SkillID:  skill.ID,
			Method:   r.Method,
			Host:     host,
			Path:     r.URL.Path,
			Status:   "error",
			Detail:   err.Error(),
			Duration: time.Since(start).Milliseconds(),
		})
		http.Error(w, "Proxy error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
 
	p.Logger.Add(proxylog.Entry{
		SkillID:  skill.ID,
		Method:   r.Method,
		Host:     host,
		Path:     r.URL.Path,
		Status:   "allowed",
		Detail:   fmt.Sprintf("%d %s", resp.StatusCode, resp.Status),
		Duration: time.Since(start).Milliseconds(),
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
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
 
	skill, err := p.authenticate(r)
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
 
	status := p.checkApproval(host, skill)
	if status != approval.StatusApproved {
		p.Logger.Add(proxylog.Entry{
			SkillID: skill.ID,
			Method:  "CONNECT",
			Host:    host,
			Status:  string(status),
			Detail:  "host not approved",
		})
		http.Error(w, fmt.Sprintf("CONNECT to %s is %s. Awaiting admin approval.", host, status), http.StatusForbidden)
		return
	}
 
	// Establish connection to target.
	targetAddr := r.Host
	if !strings.Contains(targetAddr, ":") {
		targetAddr += ":443"
	}
 
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		p.Logger.Add(proxylog.Entry{
			SkillID:  skill.ID,
			Method:   "CONNECT",
			Host:     host,
			Status:   "error",
			Detail:   err.Error(),
			Duration: time.Since(start).Milliseconds(),
		})
		http.Error(w, "Failed to connect to target", http.StatusBadGateway)
		return
	}
 
	// Hijack the connection.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		targetConn.Close()
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		targetConn.Close()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
 
	// Send 200 OK to client.
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
 
	p.Logger.Add(proxylog.Entry{
		SkillID:  skill.ID,
		Method:   "CONNECT",
		Host:     host,
		Status:   "allowed",
		Detail:   "tunnel established",
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
