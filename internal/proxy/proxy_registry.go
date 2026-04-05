// proxy_registry.go handles Docker Registry V2 traffic: detecting manifest
// and blob requests, applying per-image approval using wildcard matching,
// and auto-approving registry infrastructure endpoints (auth, CDN, pings).

package proxy

import (
	"net/http"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/config"
	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
	"github.com/olljanat-ai/firewall4ai/internal/registry"
)

// handleRegistryRequest handles a request to a known container registry host.
// Manifest requests trigger image-level approval; blob requests use repo-level
// approval; all other registry traffic (auth, /v2/ pings) is auto-approved.
// Returns the response to send to the client.
func (p *Proxy) handleRegistryRequest(req *http.Request, rc *requestContext, reg *config.RegistryConfig) *http.Response {
	sid := getSkillID(rc.skill)
	urlPath := req.URL.Path
	host := rc.host

	name, _, pathType, isV2 := registry.ParsePath(urlPath)

	if isV2 && (pathType == "manifests" || pathType == "blobs") {
		// Manifest and blob requests use repo-level approval.
		repo := registry.ParseImageRepo(reg.Name, name)
		if p.LearningMode || !registry.CheckRepoApproval(p.ImageApprovals, repo) {
			if pathType == "blobs" && !p.LearningMode {
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
				rc.logged = true
				return errorResponse(req, statusToHTTPCode(approval.StatusDenied),
					denialMessage(approval.StatusDenied, "container image "+repo))
			}
			// Manifest (or blob in learning mode): register pending and wait.
			status := p.checkRefApproval(p.ImageApprovals, repo, rc.skill, rc.sourceIP, registry.MatchImageRef)
			if status != approval.StatusApproved {
				p.Logger.Add(proxylog.Entry{
					SkillID: sid,
					Method:  req.Method,
					Host:    host,
					Path:    urlPath,
					Status:  string(status),
					Detail:  "image not approved: " + repo,
				})
				rc.logged = true
				return errorResponse(req, statusToHTTPCode(status),
					denialMessage(status, "container image "+repo))
			}
		}
		return p.forwardRegistryAndLog(req, rc, repo)
	}

	// Other registry traffic (auth, /v2/ ping, etc.): auto-approve.
	return p.forwardRegistryAndLog(req, rc, "registry infra")
}
