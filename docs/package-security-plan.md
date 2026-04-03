# Plan: Package Security Integration (Issue #32)

## Context
GitHub issue #32 requests integrating package security/malware detection into Firewall4AI's transparent proxy. Since all npm/pip/etc. traffic already flows through the MITM proxy and package names are already parsed, the proxy can inspect registry metadata responses and filter out suspicious packages before they reach AI agents. The issue references "Safe-Chain" style checks (package age, typosquatting, etc.).

## Architecture Fit
Firewall4AI already:
- Intercepts all package registry traffic transparently (npm, pypi, nuget, etc.)
- Parses package names from URLs (`internal/library/` parsers)
- Has per-package approval via `approval.Manager`
- Has admin UI for configuration
- Has request logging infrastructure

The new feature adds a **response-filtering layer** between the upstream registry response and the agent, plus **metadata checks** before allowing package installation.

## Implementation Plan

### 1. Package Security Config (`internal/config/`)
Add to `Config` struct:
- `PackageSecurity` field with:
  - `Enabled bool`
  - `MinAgeDays int` (default: 7 — block packages published less than N days ago)
  - `BlockTyposquatting bool` (detect names similar to popular packages)
  - `Exclusions []string` (packages exempt from checks)
- Store in `state.json` alongside existing settings

**File:** `internal/config/config.go`

### 2. Package Security Checker (`internal/security/`)
New package with:
- `Checker` struct holding config
- `CheckNPMPackage(metadata []byte) (filtered []byte, blocked []string, error)` — parses npm registry JSON, checks version publish dates, removes versions younger than threshold
- `CheckPyPIPackage(metadata []byte) (filtered []byte, blocked []string, error)` — same for PyPI JSON API
- `IsTyposquat(name string, repoType string) bool` — Levenshtein distance check against top-1000 popular package names (embedded list)
- `IsExcluded(name string) bool`

Key checks:
- **Age check**: Parse `time` field from npm version metadata / PyPI `upload_time`. Remove versions below threshold.
- **Typosquatting**: Levenshtein distance <= 2 from known popular packages AND package is new (< 30 days)
- **Name pattern**: Flag packages with suspicious patterns (e.g., `-debug`, `_dev` suffixes of popular packages)

**Files:** `internal/security/checker.go`, `internal/security/checker_test.go`, `internal/security/popular_packages.go`

### 3. Proxy Integration (`internal/proxy/`)
Modify `handlePackageRepoHTTPRequest` and `handlePackageRepoTLSRequest`:
- After receiving upstream response for npm/pypi metadata requests (detected by URL path pattern and content-type)
- Run through security checker
- If package is blocked entirely: return 403 with `Firewall4AI: Package blocked by security policy`
- If versions filtered: return modified metadata response with young versions stripped
- Log blocked packages with new `PACKAGE_BLOCKED` log type

**File:** `internal/proxy/proxy.go` (lines ~1388-1500)

### 4. Logging (`internal/logging/`)
Add `TypePackageBlocked` to log entry types. Include package name, reason, and registry type.

**File:** `internal/logging/logging.go`

### 5. Admin UI (`web/static/`)
Add "Package Security" section to the System/Settings page:
- Toggle enable/disable
- Min age threshold slider/input
- Typosquatting detection toggle
- Exclusion list textarea
- Table showing recently blocked packages

**File:** `web/static/index.html`

### 6. Admin API Endpoints (`internal/api/`)
- `GET /api/package-security` — get current config
- `PUT /api/package-security` — update config
- `GET /api/package-security/blocked` — recent blocked packages log

**File:** `internal/api/admin.go`

## Implementation Order
1. Config struct + persistence
2. Security checker package (with tests) — this is the core logic
3. Proxy integration (response filtering)
4. Logging
5. API endpoints
6. Admin UI

## Verification
- `go test ./...` — all existing + new tests pass
- `make lint` — no vet issues
- Test with mock npm registry returning package metadata with young versions -> verify versions stripped
- Test typosquatting detection with known test cases (e.g., "loadsh" vs "lodash")
- Test exclusion list bypasses checks
- Test disabled state passes through unmodified

## Key Considerations
- **Performance**: Metadata parsing adds latency only to registry metadata requests, not blob/tarball downloads
- **npm specifics**: npm registry returns full package metadata at `GET /{package}` with all versions in `versions` object and `time` object with publish dates
- **PyPI specifics**: PyPI JSON API at `GET /pypi/{package}/json` returns `releases` with `upload_time` per file
- **Go stdlib only**: Use `encoding/json` for parsing, `unicode/utf8` + custom for Levenshtein — no new dependencies per project conventions
- **Backward compatible**: Feature is opt-in (disabled by default), no breaking changes
