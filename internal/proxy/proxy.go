// Package proxy implements the transparent HTTP+HTTPS proxy with approval gates
// and TLS MITM inspection for HTTPS traffic, built on top of goproxy.
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

	"github.com/elazarl/goproxy"

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

	goProxy *goproxy.ProxyHttpServer
}

// goproxyLogBridge adapts our proxylog.Logger to goproxy's Logger interface,
// routing goproxy internal messages through our unified logging.
type goproxyLogBridge struct {
	logger *proxylog.Logger
}

func (b *goproxyLogBridge) Printf(format string, v ...any) {
	msg := fmt.Sprintf(format, v...)
	b.logger.Add(proxylog.Entry{
		Method: "GOPROXY",
		Status: "info",
		Detail: msg,
	})
}

// New creates a new Proxy with the given dependencies.
// The ca parameter is optional; when non-nil it enables TLS MITM inspection.
func New(skills *auth.SkillStore, approvals *approval.Manager, creds *credentials.Manager, logger *proxylog.Logger, ca *certgen.CA) *Proxy {
	p := &Proxy{
		Skills:          skills,
		Approvals:       approvals,
		Credentials:     creds,
		Logger:          logger,
		CA:              ca,
		ApprovalTimeout: approvalTimeout,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}

	gp := goproxy.NewProxyHttpServer()
	gp.Verbose = false
	gp.Logger = &goproxyLogBridge{logger: logger}

	// NonproxyHandler handles transparent HTTP requests that arrive with
	// relative URLs (from iptables REDIRECT of port 80 -> 8080). We
	// reconstruct the full URL from the Host header and delegate to
	// processRequest for approval checking and forwarding.
	gp.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host == "" {
			http.Error(w, "Firewall4AI: transparent request with no Host header", http.StatusBadRequest)
			return
		}
		req.URL.Scheme = "http"
		req.URL.Host = req.Host

		sourceIP := extractSourceIP(req.RemoteAddr)
		if p.OnActivity != nil {
			p.OnActivity(sourceIP)
		}

		resp, _ := p.processRequest(req, sourceIP)
		if resp == nil {
			http.Error(w, "Firewall4AI: no response from upstream", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// Copy response headers and status.
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})

	// CONNECT handler: decide MITM vs blind tunnel vs reject.
	gp.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(p.handleConnectDecision))

	// Request handler: auth, approval, credential injection, forwarding.
	gp.OnRequest().DoFunc(p.onRequest)

	// Response handler: no-op (logging done in onRequest/processRequest).
	gp.OnResponse().DoFunc(p.onResponse)

	p.goProxy = gp
	return p
}

// ServeHTTP handles both HTTP requests and HTTPS CONNECT tunnels.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.goProxy.ServeHTTP(w, r)
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

// errorResponse creates an *http.Response using goproxy.NewResponse to keep
// goproxy's internal state consistent when used within OnRequest handlers.
func errorResponse(req *http.Request, code int, msg string) *http.Response {
	return goproxy.NewResponse(req, "text/plain; charset=utf-8", code, msg+"\n")
}

// --- Forwarding helpers (for transparent TLS only) ---

// forwardTLS writes the upstream response to a raw net.Conn using HTTP/1.1 wire format.
// When the upstream response uses chunked Transfer-Encoding (no Content-Length),
// the body is fully read and Content-Length is set explicitly. This prevents
// clients from hanging when resp.Write() re-chunks the body but the connection
// stays open (e.g. helm repo add with ~600KB index responses).
func forwardTLS(conn net.Conn, resp *http.Response) {
	if resp.ContentLength < 0 && resp.Body != nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
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
