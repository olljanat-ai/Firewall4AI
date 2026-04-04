// Package proxy implements the transparent HTTP+HTTPS proxy with approval gates
// and TLS MITM inspection for HTTPS traffic.
package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
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
	"github.com/olljanat-ai/firewall4ai/internal/library"
	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
	"github.com/olljanat-ai/firewall4ai/internal/registry"
)

const (
	approvalTimeout = 15 * time.Minute
	// AuthHeader is used by AI agents to provide their skill token.
	AuthHeader = "X-Firewall4AI-Token"
)

// responseBodyWrapper restores the full original response body (prefix for logging
// + remaining stream from upstream) while still allowing the original body to be
// closed properly by the defer resp.Body.Close().
type responseBodyWrapper struct {
	io.Reader
	original io.ReadCloser
}

func (w *responseBodyWrapper) Close() error {
	return w.original.Close()
}

// Proxy is the main proxy server.
type Proxy struct {
	Skills             *auth.SkillStore
	Approvals          *approval.Manager
	ImageApprovals     *approval.Manager // image-level approvals for container registries
	HelmChartApprovals *approval.Manager // Helm chart approvals
	PackageApprovals   *approval.Manager // OS Packages (e.g., Debian)
	LibraryApprovals   *approval.Manager // Code Libraries (e.g., Go, npm, PyPI, NuGet)
	Registries         []config.RegistryConfig
	HelmRepos          []config.PackageRepoConfig
	OSPackages         []config.PackageRepoConfig
	CodeLibraries      []config.PackageRepoConfig
	Credentials        *credentials.Manager
	Logger             *proxylog.Logger
	Transport          http.RoundTripper
	CA                 *certgen.CA
	ApprovalTimeout    time.Duration
	LearningMode       bool                  // when true, allow all traffic by default (still logged)
	OnActivity         func(sourceIP string) // called on each request with the source IP
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

// --- Host / source helpers ---

// isConfiguredRepoHost returns true if the host belongs to a configured
// container registry, Helm chart repo, OS package repo, or code library repo.
// These hosts are auto-approved at the CONNECT level when MITM is available,
// since the real access control happens per-item inside the tunnel.
func (p *Proxy) isConfiguredRepoHost(host string) bool {
	if registry.RegistryForHost(host, p.Registries) != nil {
		return true
	}
	if library.RepoForHost(host, p.HelmRepos) != nil {
		return true
	}
	if library.RepoForHost(host, p.OSPackages) != nil {
		return true
	}
	if library.RepoForHost(host, p.CodeLibraries) != nil {
		return true
	}
	return false
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

// getLoggingMode returns the logging mode for the request's host/path.
func (p *Proxy) getLoggingMode(host, path string, skill *auth.Skill, sourceIP string) approval.LoggingMode {
	sid := getSkillID(skill)
	return p.Approvals.GetLoggingMode(host, path, sid, sourceIP)
}

// --- Error response helpers ---

// statusToHTTPCode maps an approval status to the appropriate HTTP status code.
func statusToHTTPCode(status approval.Status) int {
	if status == approval.StatusPendingTimeout {
		return http.StatusProxyAuthRequired // 407
	}
	return http.StatusForbidden // 403
}

// denialMessage returns a clear plain text error message for denied/pending requests.
func denialMessage(status approval.Status, resource string) string {
	if status == approval.StatusPendingTimeout {
		return fmt.Sprintf("Firewall4AI: Access to %s is waiting for admin approval. Your request has been registered and an administrator needs to approve it. Please retry later.", resource)
	}
	return fmt.Sprintf("Firewall4AI: Access to %s is denied by firewall policy. Contact your administrator to request access.", resource)
}

// writeErrorResponse writes a plain text error response to an http.ResponseWriter.
func writeErrorResponse(w http.ResponseWriter, status approval.Status, resource string) {
	code := statusToHTTPCode(status)
	msg := denialMessage(status, resource)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	fmt.Fprintln(w, msg)
}

// writeErrorResponseConn writes a plain text error HTTP response to a raw net.Conn.
func writeErrorResponseConn(conn net.Conn, status approval.Status, resource string) {
	code := statusToHTTPCode(status)
	msg := denialMessage(status, resource)
	resp := &http.Response{
		StatusCode: code,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(msg + "\n")),
	}
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp.ContentLength = int64(len(msg) + 1)
	resp.Write(conn)
}

// --- Forwarding helpers ---

// forwardHTTP copies the upstream response headers, status, and body to an
// http.ResponseWriter.
func forwardHTTP(w http.ResponseWriter, resp *http.Response) {
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// forwardTLS writes the upstream response to a raw net.Conn using HTTP/1.1 wire format.
// When the upstream response uses chunked Transfer-Encoding (no Content-Length),
// the body is fully read and Content-Length is set explicitly. This prevents
// clients from hanging when resp.Write() re-chunks the body but the connection
// stays open (e.g. helm repo add with ~600KB index responses).
func forwardTLS(conn net.Conn, resp *http.Response) {
	if resp.ContentLength < 0 && resp.Body != nil {
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
		} else {
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
		}
		resp.TransferEncoding = nil
	}
	resp.Write(conn)
}

// write502TLS sends a minimal 502 Bad Gateway response to a raw net.Conn.
func write502TLS(conn net.Conn) {
	resp := &http.Response{
		StatusCode: http.StatusBadGateway,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	resp.Write(conn)
}

// --- Body capture helpers ---

// captureRequestBody reads the request body (up to maxFullLogBody) and replaces it
// with a new reader so the request can still be forwarded.
func captureRequestBody(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	maxBody := config.GetMaxFullLogBody()
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(maxBody)+1))
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return ""
	}
	if len(body) > maxBody {
		return string(body[:maxBody]) + "... (truncated)"
	}
	return string(body)
}

// captureResponseBody reads the response body (up to maxFullLogBody),
// decompressing it if the response carries a Content-Encoding header.
func captureResponseBody(resp *http.Response) string {
	if resp.Body == nil {
		return ""
	}
	maxBody := config.GetMaxFullLogBody()
	origBody := resp.Body

	prefix, err := io.ReadAll(io.LimitReader(origBody, int64(maxBody)+1))
	if err != nil && err != io.EOF {
		prefix = nil
	}

	resp.Body = &responseBodyWrapper{
		Reader:   io.MultiReader(bytes.NewReader(prefix), origBody),
		original: origBody,
	}

	decoded := prefix
	switch strings.ToLower(resp.Header.Get("Content-Encoding")) {
	case "gzip":
		if r, gerr := gzip.NewReader(bytes.NewReader(prefix)); gerr == nil {
			if plain, rerr := io.ReadAll(io.LimitReader(r, int64(maxBody)+1)); rerr == nil {
				r.Close()
				decoded = plain
			}
		}
	case "deflate":
		r := flate.NewReader(bytes.NewReader(prefix))
		if plain, rerr := io.ReadAll(io.LimitReader(r, int64(maxBody)+1)); rerr == nil {
			r.Close()
			decoded = plain
		}
	}

	if len(decoded) > maxBody {
		return string(decoded[:maxBody]) + "... (truncated)"
	}
	return string(decoded)
}

// captureInjectedHeaders compares request headers before and after credential
// injection and returns only the headers that were added or changed.
func captureInjectedHeaders(before map[string][]string, after http.Header) map[string][]string {
	diff := make(map[string][]string)
	for key, newVals := range after {
		oldVals, existed := before[key]
		if !existed {
			diff[key] = newVals
		} else if len(newVals) != len(oldVals) {
			diff[key] = newVals
		} else {
			for i, v := range newVals {
				if v != oldVals[i] {
					diff[key] = newVals
					break
				}
			}
		}
	}
	if len(diff) == 0 {
		return nil
	}
	return diff
}
