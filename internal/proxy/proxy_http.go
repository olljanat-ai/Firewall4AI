package proxy

import (
	"fmt"
	"net/http"
	"time"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"

	"github.com/olljanat-ai/firewall4ai/internal/library"
)

// handleHTTP handles plain HTTP proxy requests (non-CONNECT).
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := extractHost(r)
	sourceIP := extractSourceIP(r.RemoteAddr)
	if p.OnActivity != nil {
		p.OnActivity(sourceIP)
	}

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

	// Check if this is a Helm chart repository request.
	if repo := library.RepoForHost(host, p.HelmRepos); repo != nil {
		p.handleHelmChartRepoHTTPRequest(w, r, host, sourceIP, skill, repo, start)
		return
	}

	// Check if this is a package repository request.
	if repo := library.RepoForHost(host, p.OSPackages); repo != nil {
		p.handlePackageRepoHTTPRequest(w, r, host, sourceIP, skill, repo, true, start)
		return
	}
	if repo := library.RepoForHost(host, p.CodeLibraries); repo != nil {
		p.handlePackageRepoHTTPRequest(w, r, host, sourceIP, skill, repo, false, start)
		return
	}

	status := p.checkApproval(host, r.URL.Path, skill, sourceIP)
	if status != approval.StatusApproved {
		resource := host + r.URL.Path
		p.Logger.Add(proxylog.Entry{
			SkillID: sid,
			Method:  r.Method,
			Host:    host,
			Path:    r.URL.Path,
			Status:  string(status),
			Detail:  "host not approved",
		})
		writeErrorResponse(w, status, resource)
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

	// Inject credentials and capture injected headers for full logging.
	p.Credentials.InjectForRequest(r, sourceIP)
	if fullDetail != nil {
		fullDetail.InjectedHeaders = captureInjectedHeaders(fullDetail.RequestHeaders, r.Header)
	}

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

	forwardHTTP(w, resp)
}
