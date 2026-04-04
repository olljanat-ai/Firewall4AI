# Firewall4AI

## Overview

Firewall4AI is a transparent, default-deny firewall and proxy appliance for controlling and monitoring outbound network traffic from isolated AI agent environments. It performs TLS MITM inspection and provides an admin web UI for managing agents, approvals, credentials, and logs.

## Architecture

- **Language:** Go 1.24+
- **Build:** Go modules (`go.mod`), `Makefile` provides `build`, `test`, `lint` targets
- **Admin UI:** Static HTML/CSS/JS embedded in the Go binary via `go:embed` (in `web/static/`)
- **Data persistence:** JSON-based state storage in `./data/` directory

### Key Components

- `cmd/firewall4ai/` — Main application entry point
- `internal/api/` — REST API split into focused files:
  - `api.go` — Handler struct, RegisterRoutes, shared helpers/types
  - `api_approvals.go` — URL approval endpoints
  - `api_skills.go` — Skill CRUD
  - `api_credentials.go` — Credential CRUD
  - `api_databases.go` — Database connection CRUD
  - `api_images.go` — Container image approval endpoints
  - `api_helm.go` — Helm chart approval endpoints
  - `api_packages.go` — OS package + code library approval endpoints
  - `api_logs.go` — Proxy log endpoints
  - `api_categories.go` — Categories, health, version, DHCP leases, backup/restore
  - `api_settings.go` — System settings, VM settings, learning mode
- `internal/proxy/` — Transparent HTTP/HTTPS proxy split into focused files:
  - `proxy.go` — Proxy struct, New(), ServeHTTP, shared helpers
  - `proxy_approval.go` — checkApproval, checkHostApproval, checkRefApproval (generic 3-level)
  - `proxy_http.go` — handleHTTP
  - `proxy_connect.go` — handleConnect, MITM, handleTLSRequest, blind tunnel
  - `proxy_transparent.go` — HandleTransparentTLS, ServeTransparentTLS
  - `proxy_registry.go` — Container registry request handling
  - `proxy_helm.go` — Helm chart repository handling + matchHelmRef
  - `proxy_packages.go` — OS package + code library handling
- `internal/dhcp/`, `internal/dns/`, `internal/tftp/` — Network services
- `internal/agent/`, `internal/image/` — Agent and disk image management
- `internal/certgen/` — TLS CA generation for MITM inspection
- `web/static/` — Admin UI static assets (embedded in binary)

## Replit Setup

The application has been adapted for Replit:

- **Admin UI:** Listens on `0.0.0.0:5000` (required for Replit preview)
- **Proxy server:** Listens on `:8080`
- **Transparent TLS:** Listens on `:8443` (non-fatal if unavailable)
- **DHCP/DNS/TFTP:** These require network privileges and will log non-fatal errors in dev environments

### Running

```
go run ./cmd/firewall4ai/
```

Or build first:
```
go build -o bin/firewall4ai ./cmd/firewall4ai/
./bin/firewall4ai
```

### Configuration

The app loads config from a JSON file (`-config` flag) or uses defaults:
- Proxy: `:8080`
- Agent API: `10.255.255.1:80`
- Transparent TLS: `:8443`
- Data dir: `./data/`

## Deployment

Configured for autoscale deployment:
- Build: `go build -o bin/firewall4ai ./cmd/firewall4ai/`
- Run: `./bin/firewall4ai`
