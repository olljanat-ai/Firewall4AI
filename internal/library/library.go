// Package library provides utility functions for detecting and handling
// package manager requests within the transparent proxy. It handles
// package name extraction from URL paths for Debian (apt), Go modules,
// npm, PyPI, and NuGet repositories.
package library

import (
	"strings"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/config"
)

// PackageType identifies the type of package manager.
type PackageType string

const (
	PackageDebian PackageType = "debian"
	PackageGo     PackageType = "golang"
	PackageNPM    PackageType = "npm"
	PackagePyPI   PackageType = "pypi"
	PackageNuGet  PackageType = "nuget"
)

// RepoForHost returns the package repository config if the host belongs to
// a configured package repository, or nil if it's not a known repo host.
func RepoForHost(host string, repos []config.PackageRepoConfig) *config.PackageRepoConfig {
	for i := range repos {
		for _, h := range repos[i].Hosts {
			if h == host {
				return &repos[i]
			}
		}
	}
	return nil
}

// ParsePackageName extracts a package name from the URL path based on the
// repository type. Returns (packageName, packageType, ok).
//
// Supported patterns:
//   - Debian: /debian/pool/main/c/curl/curl_7.88.1-10+deb12u5_amd64.deb -> "curl"
//     Also: /debian/dists/bookworm/main/binary-amd64/Packages* -> "" (metadata, auto-approve)
//   - Go: /github.com/foo/bar/@v/v1.0.0.zip -> "github.com/foo/bar"
//   - npm: /express or /@scope/package -> "express" or "@scope/package"
//   - PyPI: /simple/requests/ -> "requests"
//     Also: /packages/... -> "" (file download, needs repo-level check)
//   - NuGet: /v3-flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg -> "newtonsoft.json"
func ParsePackageName(urlPath string, repoType PackageType) (name string, ok bool) {
	switch repoType {
	case PackageDebian:
		return parseDebianPath(urlPath)
	case PackageGo:
		return parseGoPath(urlPath)
	case PackageNPM:
		return parseNPMPath(urlPath)
	case PackagePyPI:
		return parsePyPIPath(urlPath)
	case PackageNuGet:
		return parseNuGetPath(urlPath)
	}
	return "", false
}

// parseDebianPath extracts a Debian package name from an apt repository URL.
// Pool paths: /debian/pool/main/c/curl/curl_7.88.1-10_amd64.deb -> "curl"
// Also handles /ubuntu/pool/... paths.
// Dist metadata (Packages, Release, etc.) returns empty string (auto-approve).
func parseDebianPath(urlPath string) (string, bool) {
	// Pool download: extract package name from the directory component.
	// Pattern: /<repo>/pool/<component>/<prefix>/<package>/<filename>
	if idx := strings.Index(urlPath, "/pool/"); idx >= 0 {
		rest := urlPath[idx+6:] // after "/pool/"
		parts := strings.Split(rest, "/")
		// parts: [component, prefix, package, filename]
		if len(parts) >= 4 {
			return parts[2], true
		}
		// Might be a source package with fewer components
		if len(parts) >= 3 {
			return parts[1], true
		}
	}

	// Dist metadata (Packages, Release, InRelease, etc.) - auto-approve as infra.
	if strings.Contains(urlPath, "/dists/") {
		return "", true
	}

	// Other apt metadata (Release.gpg, etc.)
	return "", true
}

// parseGoPath extracts a Go module path from proxy.golang.org URLs.
// Pattern: /<module>/@v/<version>.<ext> or /<module>/@latest
// Example: /github.com/gorilla/mux/@v/v1.8.0.zip -> "github.com/gorilla/mux"
func parseGoPath(urlPath string) (string, bool) {
	if len(urlPath) < 2 {
		return "", false
	}
	path := urlPath[1:] // strip leading /

	// Look for /@v/ or /@latest
	if idx := strings.Index(path, "/@"); idx > 0 {
		return decodeCaps(path[:idx]), true
	}

	// Might be a .info, .mod, or .zip request with version in path
	return "", true
}

// decodeCaps reverses the Go module proxy encoding where uppercase letters
// are encoded as !<lowercase>. E.g., "!g!hub" -> "GHub"
func decodeCaps(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	esc := false
	for _, c := range s {
		if esc {
			b.WriteRune(rune(c) - 32) // lowercase to uppercase
			esc = false
			continue
		}
		if c == '!' {
			esc = true
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

// parseNPMPath extracts an npm package name from registry.npmjs.org URLs.
// Pattern: /<package> or /<package>/<version> or /<package>/-/<tarball>
// Scoped: /@scope/<package> or /@scope%2f<package>
func parseNPMPath(urlPath string) (string, bool) {
	if len(urlPath) < 2 {
		return "", true // root path — metadata
	}
	path := urlPath[1:] // strip leading /

	// Handle URL-encoded scoped packages: @scope%2fpackage
	path = strings.ReplaceAll(path, "%2f", "/")
	path = strings.ReplaceAll(path, "%2F", "/")

	// Scoped package: @scope/package
	if strings.HasPrefix(path, "@") {
		parts := strings.SplitN(path, "/", 3)
		if len(parts) >= 2 {
			name := parts[0] + "/" + parts[1]
			// Remove trailing segments like /-/tarball or /version
			return name, true
		}
		return "", false
	}

	// Unscoped package: package or package/version or package/-/tarball
	parts := strings.SplitN(path, "/", 2)
	if len(parts) >= 1 && parts[0] != "" && parts[0] != "-" {
		return parts[0], true
	}

	return "", true
}

// parsePyPIPath extracts a Python package name from PyPI URLs.
// Simple API: /simple/<package>/ -> "<package>"
// JSON API: /pypi/<package>/json -> "<package>"
// File downloads on files.pythonhosted.org don't contain clean package names.
func parsePyPIPath(urlPath string) (string, bool) {
	if len(urlPath) < 2 {
		return "", false
	}

	// Simple API: /simple/<package>/ or /simple/<package>
	if strings.HasPrefix(urlPath, "/simple/") {
		rest := urlPath[8:] // after "/simple/"
		rest = strings.TrimSuffix(rest, "/")
		if idx := strings.Index(rest, "/"); idx >= 0 {
			rest = rest[:idx]
		}
		if rest != "" {
			return normalizePackageName(rest), true
		}
		// /simple/ index page - auto-approve as infra
		return "", true
	}

	// JSON API: /pypi/<package>/json or /pypi/<package>/<version>/json
	if strings.HasPrefix(urlPath, "/pypi/") {
		rest := urlPath[6:] // after "/pypi/"
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) >= 1 && parts[0] != "" {
			return normalizePackageName(parts[0]), true
		}
	}

	// File downloads from files.pythonhosted.org
	// Pattern: /packages/<hash_prefix>/<hash>/<hash>/<filename>
	// Extract package name from filename
	if strings.HasPrefix(urlPath, "/packages/") {
		parts := strings.Split(urlPath, "/")
		if len(parts) > 0 {
			filename := parts[len(parts)-1]
			return extractPyPIPackageFromFilename(filename), true
		}
	}

	return "", true
}

// extractPyPIPackageFromFilename extracts the package name from a PyPI filename.
// Handles wheels (foo-1.0-py3-none-any.whl) and tarballs (foo-1.0.tar.gz).
func extractPyPIPackageFromFilename(filename string) string {
	// Wheel format: {name}-{version}(-{build})?-{python}-{abi}-{platform}.whl
	if strings.HasSuffix(filename, ".whl") {
		parts := strings.SplitN(filename, "-", 3)
		if len(parts) >= 2 {
			return normalizePackageName(parts[0])
		}
	}

	// Tarball format: {name}-{version}.tar.gz or {name}-{version}.zip
	// Split on "-" and take up to the first segment that starts with a digit
	parts := strings.Split(filename, "-")
	var nameParts []string
	for _, p := range parts {
		if len(p) > 0 && p[0] >= '0' && p[0] <= '9' {
			break
		}
		nameParts = append(nameParts, p)
	}
	if len(nameParts) > 0 {
		return normalizePackageName(strings.Join(nameParts, "-"))
	}

	return ""
}

// normalizePackageName normalizes a Python package name by lowercasing and
// replacing underscores/dots with hyphens (PEP 503 normalization).
func normalizePackageName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	return name
}

// parseNuGetPath extracts a NuGet package name from api.nuget.org URLs.
// Flat container: /v3-flatcontainer/<package>/index.json -> "<package>"
// Flat container: /v3-flatcontainer/<package>/<version>/<package>.<version>.nupkg -> "<package>"
// Registration: /v3/registration5-gz-semver2/<package>/index.json -> "<package>"
func parseNuGetPath(urlPath string) (string, bool) {
	lower := strings.ToLower(urlPath)

	// Flat container API
	if strings.HasPrefix(lower, "/v3-flatcontainer/") {
		rest := urlPath[18:] // after "/v3-flatcontainer/"
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) >= 1 && parts[0] != "" {
			return strings.ToLower(parts[0]), true
		}
	}

	// Registration endpoints
	for _, prefix := range []string{"/v3/registration", "/v3-registration"} {
		if strings.HasPrefix(lower, prefix) {
			// Find the package name segment after the registration path
			// Pattern: /v3/registration<N>-<options>/<package>/...
			idx := strings.Index(urlPath[len(prefix):], "/")
			if idx >= 0 {
				rest := urlPath[len(prefix)+idx+1:]
				parts := strings.SplitN(rest, "/", 2)
				if len(parts) >= 1 && parts[0] != "" {
					return strings.ToLower(parts[0]), true
				}
			}
		}
	}

	// Service index and other metadata - auto-approve
	return "", true
}

// CheckPackageApproval returns true if the package (or a broader wildcard
// pattern covering it) has been approved.
func CheckPackageApproval(mgr *approval.Manager, pkg string) bool {
	if pkg == "" {
		return true // metadata requests are auto-approved
	}
	// Exact match.
	if status, ok := mgr.CheckExisting(pkg, "", "", ""); ok && status == approval.StatusApproved {
		return true
	}
	// Wildcard match using MatchPackageRef.
	if status, ok := mgr.CheckExistingWithMatcher(pkg, "", "", MatchPackageRef); ok && status == approval.StatusApproved {
		return true
	}
	return false
}

// MatchPackageRef checks if a package name matches a pattern.
// Supports:
//   - Exact match: "express"
//   - Prefix wildcard: "github.com/gorilla/*" (matches any Go package under gorilla)
//   - Scope wildcard: "@types/*" (matches any npm package in @types scope)
func MatchPackageRef(pattern, pkg string) bool {
	if pattern == pkg {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := pattern[:len(pattern)-1] // include trailing /
		return strings.HasPrefix(pkg, prefix)
	}
	return false
}

// IsOSPackageType returns true if the package type is an OS-level package.
func IsOSPackageType(t PackageType) bool {
	return t == PackageDebian
}

// TypeLabel returns a human-readable label for the package type.
func TypeLabel(t PackageType) string {
	switch t {
	case PackageDebian:
		return "Debian"
	case PackageGo:
		return "Go"
	case PackageNPM:
		return "npm"
	case PackagePyPI:
		return "PyPI"
	case PackageNuGet:
		return "NuGet"
	default:
		return string(t)
	}
}
