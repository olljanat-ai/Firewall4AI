// proxy_helm.go handles Helm chart repository traffic: detecting chart
// requests, applying per-chart approval, and forwarding to upstream repos.

package proxy

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/auth"
	"github.com/olljanat-ai/firewall4ai/internal/config"
	"github.com/olljanat-ai/firewall4ai/internal/library"
	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
)

// matchHelmRef checks if a Helm chart reference matches a pattern.
// Supports:
//   - Exact match: "helm:charts.jetstack.io/cert-manager"
//   - Wildcard: "helm:charts.jetstack.io/*" matches any chart from that repo
//   - Repo-level: "helm:charts.jetstack.io" covers "helm:charts.jetstack.io/cert-manager"
func matchHelmRef(pattern, ref string) bool {
	if pattern == ref {
		return true
	}
	// Wildcard: "helm:repo/*" matches "helm:repo/chart"
	if strings.HasSuffix(pattern, "/*") {
		prefix := pattern[:len(pattern)-1] // include trailing /
		return strings.HasPrefix(ref, prefix)
	}
	// Repo-level covers chart-level: "helm:repo" matches "helm:repo/chart"
	if !strings.Contains(pattern, "/") {
		return strings.HasPrefix(ref, pattern+"/")
	}
	return false
}

// helmRef builds the canonical approval key for a Helm chart or repo.
// Chart-level: "helm:<host>/<chartname>" (e.g., "helm:charts.jetstack.io/cert-manager")
// Repo-level:  "helm:<host>" (e.g., "helm:charts.jetstack.io")
func helmRef(host, chartName string) string {
	if chartName == "" {
		return "helm:" + host
	}
	return "helm:" + host + "/" + chartName
}

// checkHelmApprovalFastPath returns true if an existing (non-pending) approval
// in HelmChartApprovals already covers the given ref — either by exact match or
// because a repo-level approval covers a chart-level ref.
func (p *Proxy) checkHelmApprovalFastPath(ref string) bool {
	if p.LearningMode {
		return false // skip fast-path in learning mode; let checkRefApproval handle it
	}
	if status, ok := p.HelmChartApprovals.CheckExistingWithMatcher(ref, "", "", matchHelmRef); ok && status == approval.StatusApproved {
		return true
	}
	return false
}

// handleHelmChartRepoHTTPRequest handles plain-HTTP requests to a Helm chart repository.
// Index/metadata requests use repo-level approval; chart downloads use chart-level approval.
func (p *Proxy) handleHelmChartRepoHTTPRequest(w http.ResponseWriter, r *http.Request, host, sourceIP string, skill *auth.Skill, repo *config.PackageRepoConfig, start time.Time) {
	sid := getSkillID(skill)
	urlPath := r.URL.Path

	chartName, ok := library.ParsePackageName(urlPath, library.PackageType(repo.Type))
	if !ok {
		// Unknown path type — fall through to normal host approval.
		status := p.checkApproval(host, urlPath, skill, sourceIP)
		if status != approval.StatusApproved {
			writeErrorResponse(w, status, host+urlPath)
			return
		}
		p.forwardHTTPRequest(w, r, host, sid, urlPath, start)
		return
	}

	ref := helmRef(host, chartName)
	if chartName != "" && p.checkHelmApprovalFastPath(ref) {
		// Fast-path: an existing approval already covers this chart.
	} else {
		status := p.checkRefApproval(p.HelmChartApprovals, ref, skill, sourceIP, matchHelmRef)
		if status != approval.StatusApproved {
			p.Logger.Add(proxylog.Entry{
				SkillID: sid,
				Method:  r.Method,
				Host:    host,
				Path:    urlPath,
				Status:  string(status),
				Detail:  "helm chart not approved: " + ref,
			})
			writeErrorResponse(w, status, "helm chart "+ref)
			return
		}
	}

	p.Logger.Add(proxylog.Entry{
		SkillID: sid,
		Method:  r.Method,
		Host:    host,
		Path:    urlPath,
		Status:  "allowed",
		Detail:  ref,
	})
	p.forwardHTTPRequest(w, r, host, sid, urlPath, start)
}

// handleHelmChartRepoTLSRequest handles HTTPS requests to a Helm chart repository
// over a raw net.Conn (from CONNECT+MITM or transparent TLS interception).
func (p *Proxy) handleHelmChartRepoTLSRequest(clientConn net.Conn, req *http.Request, host, sourceIP string, skill *auth.Skill, repo *config.PackageRepoConfig, start time.Time) {
	sid := getSkillID(skill)
	urlPath := req.URL.Path

	chartName, ok := library.ParsePackageName(urlPath, library.PackageType(repo.Type))
	if !ok {
		// Unknown path type — fall through to normal host approval.
		status := p.checkApproval(host, urlPath, skill, sourceIP)
		if status != approval.StatusApproved {
			writeErrorResponseConn(clientConn, status, host+urlPath)
			return
		}
		p.forwardTLSRequest(clientConn, req, host, sid, urlPath, start)
		return
	}

	ref := helmRef(host, chartName)
	if chartName != "" && p.checkHelmApprovalFastPath(ref) {
		// Fast-path: existing approval covers this chart.
	} else {
		status := p.checkRefApproval(p.HelmChartApprovals, ref, skill, sourceIP, matchHelmRef)
		if status != approval.StatusApproved {
			p.Logger.Add(proxylog.Entry{
				SkillID: sid,
				Method:  req.Method,
				Host:    host,
				Path:    urlPath,
				Status:  string(status),
				Detail:  "helm chart not approved: " + ref,
			})
			writeErrorResponseConn(clientConn, status, "helm chart "+ref)
			return
		}
	}

	p.Logger.Add(proxylog.Entry{
		SkillID:  sid,
		Method:   req.Method,
		Host:     host,
		Path:     urlPath,
		Status:   "allowed",
		Detail:   ref,
		Duration: time.Since(start).Milliseconds(),
	})
	p.forwardTLSRequest(clientConn, req, host, sid, urlPath, start)
}

// forwardHTTPRequest forwards a pre-approved request over plain HTTP and logs the result.
func (p *Proxy) forwardHTTPRequest(w http.ResponseWriter, r *http.Request, host, sid, urlPath string, start time.Time) {
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
			SkillID:  sid,
			Method:   r.Method,
			Host:     host,
			Path:     urlPath,
			Status:   "error",
			Detail:   err.Error(),
			Duration: time.Since(start).Milliseconds(),
		})
		http.Error(w, "Proxy error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	p.Logger.Add(proxylog.Entry{
		SkillID:  sid,
		Method:   r.Method,
		Host:     host,
		Path:     urlPath,
		Status:   "allowed",
		Detail:   fmt.Sprintf("%d %s", resp.StatusCode, resp.Status),
		Duration: time.Since(start).Milliseconds(),
	})
	forwardHTTP(w, resp)
}

// forwardTLSRequest forwards a pre-approved request over TLS (raw conn) and logs the result.
func (p *Proxy) forwardTLSRequest(clientConn net.Conn, req *http.Request, host, sid, urlPath string, start time.Time) {
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
		write502TLS(clientConn)
		return
	}
	defer resp.Body.Close()
	p.Logger.Add(proxylog.Entry{
		SkillID:  sid,
		Method:   req.Method,
		Host:     host,
		Path:     urlPath,
		Status:   "allowed",
		Detail:   fmt.Sprintf("%d %s", resp.StatusCode, resp.Status),
		Duration: time.Since(start).Milliseconds(),
	})
	forwardTLS(clientConn, resp)
}
