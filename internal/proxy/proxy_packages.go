// proxy_packages.go handles OS package repository and code library traffic:
// detecting package requests, applying per-package approval, and forwarding
// to upstream package repositories (APT, APK, npm, PyPI, etc.).

package proxy

import (
	"net/http"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/config"
	"github.com/olljanat-ai/firewall4ai/internal/library"
	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
)

// packageRef builds the canonical approval key for an OS package or code library.
// Format: "<type>:<pkgname>" — e.g., "debian:curl", "golang:github.com/gorilla/mux".
func packageRef(repoType, pkgName string) string {
	return repoType + ":" + pkgName
}

// matchLibraryRef delegates to library.MatchPackageRef which supports exact
// matches and wildcard patterns (prefix/*, scope/*).
func matchLibraryRef(pattern, ref string) bool {
	return library.MatchPackageRef(pattern, ref)
}

// packageApprovalMgr returns the appropriate approval manager for the request.
// isOSPackage=true → PackageApprovals; false → LibraryApprovals.
func (p *Proxy) packageApprovalMgr(isOSPackage bool) *approval.Manager {
	if isOSPackage {
		return p.PackageApprovals
	}
	return p.LibraryApprovals
}

// handlePackageRequest handles a request to a package repository (OS package
// manager or code library). If the URL parses to a concrete package name,
// package-level approval is required; otherwise the request is treated as
// repository metadata and auto-approved.
// Returns the response to send to the client.
func (p *Proxy) handlePackageRequest(req *http.Request, rc *requestContext, repo *config.PackageRepoConfig, isOSPackage bool) *http.Response {
	sid := getSkillID(rc.skill)
	urlPath := req.URL.Path
	host := rc.host
	mgr := p.packageApprovalMgr(isOSPackage)

	pkgName, ok := library.ParsePackageName(urlPath, library.PackageType(repo.Type))
	if !ok {
		// No parser registered for this type — fall through to normal host approval.
		status := p.checkApproval(host, urlPath, rc.skill, rc.sourceIP)
		if status != approval.StatusApproved {
			rc.logged = true
			return errorResponse(req, statusToHTTPCode(status),
				denialMessage(status, host+urlPath))
		}
		return p.forwardAndLog(req, rc, "")
	}

	if pkgName == "" {
		// Metadata / index request: auto-approve.
		p.Logger.Add(proxylog.Entry{
			SkillID:  sid,
			Method:   req.Method,
			Host:     host,
			Path:     urlPath,
			Status:   "allowed",
			Detail:   "repo metadata (auto-approved)",
			Duration: 0,
		})
		return p.forwardAndLog(req, rc, "repo metadata")
	}

	// Package download: require explicit approval.
	ref := packageRef(repo.Type, pkgName)
	if library.CheckPackageApproval(mgr, pkgName) && !p.LearningMode {
		// Fast-path: approved (wildcard or exact match).
		p.Logger.Add(proxylog.Entry{
			SkillID:  sid,
			Method:   req.Method,
			Host:     host,
			Path:     urlPath,
			Status:   "allowed",
			Detail:   ref,
			Duration: 0,
		})
		return p.forwardAndLog(req, rc, ref)
	}

	status := p.checkRefApproval(mgr, ref, rc.skill, rc.sourceIP, matchLibraryRef)
	if status != approval.StatusApproved {
		p.Logger.Add(proxylog.Entry{
			SkillID: sid,
			Method:  req.Method,
			Host:    host,
			Path:    urlPath,
			Status:  string(status),
			Detail:  "package not approved: " + ref,
		})
		rc.logged = true
		return errorResponse(req, statusToHTTPCode(status),
			denialMessage(status, "package "+ref))
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
