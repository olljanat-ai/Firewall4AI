// proxy_packages.go handles OS package repository and code library traffic:
// detecting package requests, applying per-package approval, and forwarding
// to upstream package repositories (APT, APK, npm, PyPI, etc.).

package proxy

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/auth"
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

// handlePackageRepoHTTPRequest handles a plain-HTTP request to a package repository
// (OS package manager or code library). If the URL parses to a concrete package name,
// package-level approval is required; otherwise the request is treated as repository
// metadata and auto-approved.
func (p *Proxy) handlePackageRepoHTTPRequest(w http.ResponseWriter, r *http.Request, host, sourceIP string, skill *auth.Skill, repo *config.PackageRepoConfig, isOSPackage bool, start time.Time) {
	sid := getSkillID(skill)
	urlPath := r.URL.Path
	mgr := p.packageApprovalMgr(isOSPackage)

	pkgName, ok := library.ParsePackageName(urlPath, library.PackageType(repo.Type))
	if !ok {
		// No parser registered for this type — fall through to normal host approval.
		status := p.checkApproval(host, urlPath, skill, sourceIP)
		if status != approval.StatusApproved {
			writeErrorResponse(w, status, host+urlPath)
			return
		}
		p.forwardHTTPRequest(w, r, host, sid, urlPath, start)
		return
	}

	if pkgName == "" {
		// Metadata / index request: auto-approve.
		p.Logger.Add(proxylog.Entry{
			SkillID: sid,
			Method:  r.Method,
			Host:    host,
			Path:    urlPath,
			Status:  "allowed",
			Detail:  "repo metadata (auto-approved)",
		})
		p.forwardHTTPRequest(w, r, host, sid, urlPath, start)
		return
	}

	// Package download: require explicit approval.
	ref := packageRef(repo.Type, pkgName)
	if library.CheckPackageApproval(mgr, pkgName) && !p.LearningMode {
		// Fast-path: approved (wildcard or exact match).
		p.Logger.Add(proxylog.Entry{
			SkillID: sid,
			Method:  r.Method,
			Host:    host,
			Path:    urlPath,
			Status:  "allowed",
			Detail:  ref,
		})
		p.forwardHTTPRequest(w, r, host, sid, urlPath, start)
		return
	}

	status := p.checkRefApproval(mgr, ref, skill, sourceIP, matchLibraryRef)
	if status != approval.StatusApproved {
		p.Logger.Add(proxylog.Entry{
			SkillID: sid,
			Method:  r.Method,
			Host:    host,
			Path:    urlPath,
			Status:  string(status),
			Detail:  "package not approved: " + ref,
		})
		writeErrorResponse(w, status, "package "+ref)
		return
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

// handlePackageRepoTLSRequest handles an HTTPS request to a package repository
// over a raw net.Conn (from CONNECT+MITM or transparent TLS interception).
func (p *Proxy) handlePackageRepoTLSRequest(clientConn net.Conn, req *http.Request, host, sourceIP string, skill *auth.Skill, repo *config.PackageRepoConfig, isOSPackage bool, start time.Time) {
	sid := getSkillID(skill)
	urlPath := req.URL.Path
	mgr := p.packageApprovalMgr(isOSPackage)

	pkgName, ok := library.ParsePackageName(urlPath, library.PackageType(repo.Type))
	if !ok {
		// No parser registered — fall through to normal host approval.
		status := p.checkApproval(host, urlPath, skill, sourceIP)
		if status != approval.StatusApproved {
			writeErrorResponseConn(clientConn, status, host+urlPath)
			return
		}
		p.forwardTLSRequest(clientConn, req, host, sid, urlPath, start)
		return
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
			Duration: time.Since(start).Milliseconds(),
		})
		p.forwardTLSRequest(clientConn, req, host, sid, urlPath, start)
		return
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
			Duration: time.Since(start).Milliseconds(),
		})
		p.forwardTLSRequest(clientConn, req, host, sid, urlPath, start)
		return
	}

	status := p.checkRefApproval(mgr, ref, skill, sourceIP, matchLibraryRef)
	if status != approval.StatusApproved {
		p.Logger.Add(proxylog.Entry{
			SkillID:  sid,
			Method:   req.Method,
			Host:     host,
			Path:     urlPath,
			Status:   string(status),
			Detail:   "package not approved: " + ref,
			Duration: time.Since(start).Milliseconds(),
		})
		writeErrorResponseConn(clientConn, status, "package "+ref)
		return
	}

	p.Logger.Add(proxylog.Entry{
		SkillID:  sid,
		Method:   req.Method,
		Host:     host,
		Path:     urlPath,
		Status:   "allowed",
		Detail:   fmt.Sprintf("%s → forwarding", ref),
		Duration: time.Since(start).Milliseconds(),
	})
	p.forwardTLSRequest(clientConn, req, host, sid, urlPath, start)
}
