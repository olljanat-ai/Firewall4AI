// proxy_http.go contains the goproxy OnRequest/OnResponse hooks and the shared
// processRequest function that handles all HTTP and MITM'd HTTPS requests.

package proxy

import (
	"fmt"
	"net/http"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/auth"
	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"

	"github.com/olljanat-ai/firewall4ai/internal/library"
	"github.com/olljanat-ai/firewall4ai/internal/registry"
)

// requestContext stores per-request state for logging.
type requestContext struct {
	skill      *auth.Skill
	sourceIP   string
	host       string
	start      time.Time
	logMode    approval.LoggingMode
	fullDetail *proxylog.FullDetail
	logged     bool // true if already logged (e.g. by specialized handler)
}

// onRequest is the goproxy OnRequest hook. It handles authentication, approval,
// credential injection, forwarding, and logging for all HTTP proxy requests.
func (p *Proxy) onRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	sourceIP := extractSourceIP(req.RemoteAddr)
	if p.OnActivity != nil {
		p.OnActivity(sourceIP)
	}

	resp, rc := p.processRequest(req, sourceIP)
	ctx.UserData = rc
	return req, resp
}

// onResponse is the goproxy OnResponse hook. Currently a no-op since logging
// is handled in processRequest and specialized handlers.
func (p *Proxy) onResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	return resp
}

// processRequest handles the shared business logic for all request types:
// routing to specialized handlers, approval checking,
// credential injection, forwarding, and logging.
//
// Returns the response to send to the client. The returned requestContext
// contains logging state.
func (p *Proxy) processRequest(req *http.Request, sourceIP string) (*http.Response, *requestContext) {
	start := time.Now()
	host := extractHost(req)

	rc := &requestContext{
		start:    start,
		host:     host,
		sourceIP: sourceIP,
	}
	sid := getSkillID(rc.skill)

	// Route to specialized handlers.
	if reg := registry.RegistryForHost(host, p.Registries); reg != nil {
		return p.handleRegistryRequest(req, rc, reg), rc
	}
	if repo := library.RepoForHost(host, p.HelmRepos); repo != nil {
		return p.handleHelmChartRequest(req, rc, repo), rc
	}
	if repo := library.RepoForHost(host, p.OSPackages); repo != nil {
		return p.handlePackageRequest(req, rc, repo, true), rc
	}
	if repo := library.RepoForHost(host, p.CodeLibraries); repo != nil {
		return p.handlePackageRequest(req, rc, repo, false), rc
	}

	// Generic host+path approval.
	status := p.checkApproval(host, req.URL.Path, rc.skill, sourceIP)
	if status != approval.StatusApproved {
		resource := host + req.URL.Path
		p.Logger.Add(proxylog.Entry{
			SkillID: sid,
			Method:  req.Method,
			Host:    host,
			Path:    req.URL.Path,
			Status:  string(status),
			Detail:  "host not approved",
		})
		rc.logged = true
		return errorResponse(req, statusToHTTPCode(status), denialMessage(status, resource)), rc
	}

	// Check logging mode before injecting credentials (capture pre-injection headers).
	logMode := p.getLoggingMode(host, req.URL.Path, rc.skill, sourceIP)
	rc.logMode = logMode
	if logMode == approval.LoggingModeFull {
		reqBody := captureRequestBody(req)
		rc.fullDetail = &proxylog.FullDetail{
			RequestHeaders: req.Header.Clone(),
			RequestBody:    reqBody,
		}
	}

	// Inject credentials.
	p.Credentials.InjectForRequest(req, sourceIP)
	if rc.fullDetail != nil {
		rc.fullDetail.InjectedHeaders = captureInjectedHeaders(rc.fullDetail.RequestHeaders, req.Header)
	}

	// Normalize URL for forwarding.
	req.RequestURI = ""
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	// Forward the request.
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
			HasFullLog: rc.fullDetail != nil,
			FullDetail: rc.fullDetail,
		})
		rc.logged = true
		return errorResponse(req, http.StatusBadGateway, "Proxy error: "+err.Error()), rc
	}

	// Capture response body for full logging.
	if rc.fullDetail != nil {
		rc.fullDetail.ResponseHeaders = resp.Header.Clone()
		rc.fullDetail.ResponseStatus = resp.StatusCode
		rc.fullDetail.ResponseBody = captureResponseBody(resp)
	}

	p.Logger.Add(proxylog.Entry{
		SkillID:    sid,
		Method:     req.Method,
		Host:       host,
		Path:       req.URL.Path,
		Status:     "allowed",
		Detail:     fmt.Sprintf("%d %s", resp.StatusCode, resp.Status),
		Duration:   time.Since(start).Milliseconds(),
		HasFullLog: rc.fullDetail != nil,
		FullDetail: rc.fullDetail,
	})
	rc.logged = true

	return resp, rc
}

// forwardAndLog performs RoundTrip, logs the result, and returns the response.
// Used by specialized handlers after approval.
func (p *Proxy) forwardAndLog(req *http.Request, rc *requestContext, detail string) *http.Response {
	sid := getSkillID(rc.skill)
	host := rc.host
	urlPath := req.URL.Path

	req.RequestURI = ""
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	resp, err := p.Transport.RoundTrip(req)
	if err != nil {
		p.Logger.Add(proxylog.Entry{
			SkillID:  sid,
			Method:   req.Method,
			Host:     host,
			Path:     urlPath,
			Status:   "error",
			Detail:   err.Error(),
			Duration: time.Since(rc.start).Milliseconds(),
		})
		rc.logged = true
		return errorResponse(req, http.StatusBadGateway, "Proxy error: "+err.Error())
	}

	p.Logger.Add(proxylog.Entry{
		SkillID:  sid,
		Method:   req.Method,
		Host:     host,
		Path:     urlPath,
		Status:   "allowed",
		Detail:   fmt.Sprintf("%d %s", resp.StatusCode, resp.Status),
		Duration: time.Since(rc.start).Milliseconds(),
	})
	rc.logged = true

	return resp
}

// forwardRegistryAndLog is like forwardAndLog but logs with the provided approval
// detail before forwarding (used by registry requests where the detail contains
// the image/repo ref).
func (p *Proxy) forwardRegistryAndLog(req *http.Request, rc *requestContext, approvalDetail string) *http.Response {
	sid := getSkillID(rc.skill)

	// Log the approval before forwarding.
	p.Logger.Add(proxylog.Entry{
		SkillID:  sid,
		Method:   req.Method,
		Host:     rc.host,
		Path:     req.URL.Path,
		Status:   "allowed",
		Detail:   approvalDetail,
		Duration: time.Since(rc.start).Milliseconds(),
	})

	req.RequestURI = ""
	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}
	if req.URL.Host == "" {
		req.URL.Host = rc.host + ":443"
	}

	resp, err := p.Transport.RoundTrip(req)
	if err != nil {
		p.Logger.Add(proxylog.Entry{
			SkillID:  sid,
			Method:   req.Method,
			Host:     rc.host,
			Path:     req.URL.Path,
			Status:   "error",
			Detail:   err.Error(),
			Duration: time.Since(rc.start).Milliseconds(),
		})
		rc.logged = true
		return errorResponse(req, http.StatusBadGateway, "Proxy error: "+err.Error())
	}

	rc.logged = true
	return resp
}
