// proxy_helm.go handles Helm chart repository traffic: detecting chart
// requests, applying per-chart approval, and forwarding to upstream repos.

package proxy

import (
	"net/http"
	"strings"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
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

// handleHelmChartRequest handles requests to a Helm chart repository.
// Index/metadata requests use repo-level approval; chart downloads use chart-level approval.
// Returns the response to send to the client.
func (p *Proxy) handleHelmChartRequest(req *http.Request, rc *requestContext, repo *config.PackageRepoConfig) *http.Response {
	sid := getSkillID(rc.skill)
	urlPath := req.URL.Path
	host := rc.host

	chartName, ok := library.ParsePackageName(urlPath, library.PackageType(repo.Type))
	if !ok {
		// Unknown path type — fall through to normal host approval.
		status := p.checkApproval(host, urlPath, rc.skill, rc.sourceIP)
		if status != approval.StatusApproved {
			rc.logged = true
			return errorResponse(req, statusToHTTPCode(status),
				denialMessage(status, host+urlPath))
		}
		return p.forwardAndLog(req, rc, "")
	}

	ref := helmRef(host, chartName)
	if chartName != "" && p.checkHelmApprovalFastPath(ref) {
		// Fast-path: an existing approval already covers this chart.
	} else {
		status := p.checkRefApproval(p.HelmChartApprovals, ref, rc.skill, rc.sourceIP, matchHelmRef)
		if status != approval.StatusApproved {
			p.Logger.Add(proxylog.Entry{
				SkillID: sid,
				Method:  req.Method,
				Host:    host,
				Path:    urlPath,
				Status:  string(status),
				Detail:  "helm chart not approved: " + ref,
			})
			rc.logged = true
			return errorResponse(req, statusToHTTPCode(status),
				denialMessage(status, "helm chart "+ref))
		}
	}

	p.Logger.Add(proxylog.Entry{
		SkillID: sid,
		Method:  req.Method,
		Host:    host,
		Path:    urlPath,
		Status:  "allowed",
		Detail:  ref,
	})
	return p.forwardAndLog(req, rc, ref)
}
