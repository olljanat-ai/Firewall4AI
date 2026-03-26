# CLAUDE.md - Firewall4AI

## Project Overview
Firewall4AI is a transparent firewall/proxy that controls AI agent internet access from isolated VM environments. It sits between agent VMs and the internet, intercepting all HTTP/HTTPS traffic transparently via iptables without requiring proxy configuration on agent VMs. It also provides network boot (PXE) infrastructure for automated provisioning of agent VMs.

## Architecture
- **Single Go binary** with minimal external dependencies
- **Seven listeners**: HTTP proxy (:8080), transparent TLS (:8443), admin UI (:443), agent API (10.255.255.1:80), DHCP (:67), DNS (:53), TFTP (:69)
- **iptables REDIRECT**: Port 80 -> :8080, port 443 -> :8443 for transparent interception
- **TLS MITM**: Auto-generated CA signs per-host certificates; agents must trust the CA
- **Default-deny**: All connections blocked until admin approves
- **Three-level approval**: Global (all agents/VMs) -> VM-specific (by source IP) -> Skill-specific (by skill token, for getting more permissions). Used for both host approvals and image approvals.
- **Container registry awareness**: Transparent proxy detects Docker Registry V2 traffic to configured registry hosts and applies per-image approval instead of per-host approval. No Docker mirror config needed on agent VMs.
- **Agent VM provisioning**: Agents are configured by MAC address and automatically PXE-booted with Alpine Linux, Debian, or Ubuntu. Fully automated installation with root-only, auto-login, and configurable extra packages.
- **Integrated network services**: DHCP, DNS, and TFTP servers are built into the single binary, replacing the previous dnsmasq dependency.
- **VM appliance**: Debian 13 ISO built with Elemental Toolkit, two NICs (eth0=internet, eth1=agent network 10.255.255.0/24)
- **Immutable OS**: Elemental Toolkit provides immutable rootfs with btrfs snapshots and OTA upgrades via container images
- **Persistent storage**: Rules (state.json), CA certificates, DHCP leases, netboot files, and logs stored on COS_PERSISTENT partition
- **Permanent DHCP leases**: Agents get stable IPs for reliable VM-specific approvals
- **SQL database proxy**: Agent API provides HTTP endpoints to query configured SQL databases (MSSQL, PostgreSQL, MySQL). Connections configured via admin UI with per-database API paths and credentials.

## Key Directories
```
cmd/firewall4ai/     - Application entry point (main.go)
internal/
  agent/             - Agent VM management (MAC, OS type, packages, status)
  api/               - REST API handlers for admin UI, agent API, and agent management
  approval/          - Default-deny approval system with three levels (global/VM/skill)
  auth/              - Skill tokens (GUID format) and authentication
  certgen/           - CA and per-host TLS certificate generation
  config/            - JSON configuration loading
  credentials/       - Credential injection (header/bearer/basic_auth/query_param)
  database/          - SQL database connection manager (MSSQL, PostgreSQL, MySQL)
  dhcp/              - Integrated DHCP server with PXE boot support
  dns/               - Integrated DNS forwarder with local hostname resolution
  logging/           - In-memory circular buffer request logger
  netboot/           - Network boot orchestration (iPXE, preseed, Alpine answer files)
  proxy/             - HTTP/HTTPS proxy with transparent + explicit modes
  registry/          - Docker Registry V2 utilities (path parsing, image ref matching)
  store/             - Generic JSON file persistence
  tftp/              - Integrated TFTP server for PXE boot files
web/static/          - Admin UI (vanilla HTML/JS/CSS, embedded at build time)
Dockerfile           - Multi-stage build: elemental CLI + firewall4ai binary + Debian 13 OS image
config/              - Elemental Toolkit and system configuration
  config.yaml        - Elemental install/upgrade config (partition sizes, OCI upgrade image)
  snapshotter.yaml   - Btrfs snapshotter config
  bootargs.cfg       - GRUB boot arguments
  50-elemental-initrd.conf - Dracut initrd configuration
  oem/               - OEM cloud-init configs (persistence, layout)
  firewall4ai/       - Application config (config.json)
  network/           - systemd-networkd .network files (eth0 DHCP, eth1 static)
systemd/             - systemd service units (firewall4ai, iptables)
scripts/             - Helper scripts (iptables rules)
```

## Building and Testing
```bash
make build           # Build the binary
make test            # Run all tests
make lint            # Run go vet
go test ./...        # Run tests directly

# Build ISO (requires Docker)
docker build . --build-arg VERSION=dev -t firewall4ai:dev
docker create --name export firewall4ai:dev
mkdir rootfs && docker export export | tar -x -C rootfs && docker rm export
sudo ./rootfs/usr/bin/elemental --debug build-iso --bootloader-in-rootfs --extra-cmdline "" dir:rootfs

# Upgrade existing installation
elemental upgrade --reboot --system oci:ghcr.io/olljanat-ai/firewall4ai:<version>
```

## Key Design Decisions
- **Transparent proxy mode**: iptables REDIRECT intercepts agent traffic; no proxy config needed on agent VMs. Agents can optionally still use explicit proxy mode.
- **Three-level approvals**: Approvals are checked broadest-first: (1) Global (`skill_id=""`, `source_ip=""`) applies to all agents on all VMs. (2) VM-specific (`skill_id=""`, `source_ip` set) applies to all agents on that VM. (3) Skill-specific (`skill_id` set) gives additional permissions beyond global/VM. Broader approvals cascade to notify narrower waiters.
- **URL path prefix**: Approvals can optionally restrict access to specific URL path prefixes (e.g., `github.com` with `path_prefix="/olljanat-ai/"` allows only that org's repos). Empty `PathPrefix` means all paths (backward compatible). When multiple approvals match, the most specific (longest PathPrefix) wins. For CONNECT+MITM, any path-specific approval implies host-level tunnel access; per-request path checks enforce restrictions inside the tunnel.
- **Anonymous access**: Agents can make requests without skill tokens. These go through the global/VM approval system. Invalid tokens are rejected; missing tokens are anonymous.
- **GUID tokens**: Skill tokens use UUID v4 format (e.g., `a1b2c3d4-e5f6-4789-abcd-ef0123456789`). Skill IDs can be user-provided or auto-generated GUIDs.
- **State persistence**: All state (skills, approvals, credentials, image approvals, agents, DHCP leases, disabled languages/distros) stored in a single `state.json` file, loaded at startup, saved on mutations and shutdown.
- **Registry integration**: Configured registry hosts are detected in the transparent proxy. Manifest requests (`/v2/{name}/manifests/{ref}`) trigger image-level approval. Blob requests are allowed at repo level once any image in that repo is approved. All other registry traffic (auth endpoints, /v2/ pings, CDN) is auto-approved since the registry is configured explicitly.
- **Language/distro toggle**: Admin can disable entire programming language types (e.g., npm, pypi) or OS distro types (e.g., alpine) via settings. Disabled types return 403 immediately without creating pending entries. Settings stored in `state.json` as `disabled_languages` and `disabled_distros` arrays.
- **Agent API**: Plain HTTP server on eth1 (10.255.255.1:80) serves `GET /v1/policy` (JSON with allowed/disallowed languages, packages, URLs), `POST /v1/db/{name}/query` (SQL database query proxy), `GET /ca.crt` (CA certificate), and boot endpoints for PXE netboot.
- **AI-agent-friendly errors**: Denied requests return 403 with clear plain text message. Pending requests waiting for admin approval return 407 with clear message. Both include `Firewall4AI:` prefix for easy identification.
- **Integrated DHCP/DNS/TFTP**: All network services run inside the single Go binary. No external dnsmasq dependency. DHCP assigns IPs with permanent leases, DNS forwards to upstream (1.1.1.1/1.0.0.1) with local hostname resolution, TFTP serves iPXE bootloader files.
- **Agent VM provisioning**: Agents are identified by MAC address. Admin configures OS type (Alpine/Debian/Ubuntu), version, disk device, and extra packages via the Agents tab. The system downloads netboot files (kernel+initrd), generates iPXE scripts and installer configs (Alpine answer file, Debian/Ubuntu preseed), and serves them via HTTP/TFTP for fully automated PXE installation.
- **PXE boot flow**: (1) Agent VM PXE boots → DHCP provides IP + next-server + boot filename. (2) iPXE loads from TFTP (or is built into the VM's firmware). (3) iPXE fetches boot script from `http://10.255.255.1/boot/ipxe?mac=XX`. (4) Boot script loads OS kernel+initrd with installer config URL. (5) OS installer runs unattended. (6) Agent reboots from disk with root auto-login.

## Common Patterns
- **Thread safety**: All managers use `sync.RWMutex`. Read operations use `RLock`, write operations use `Lock`.
- **Approval flow**: `Check(host, skillID, sourceIP, pathPrefix)` registers a pending entry, `WaitForDecision()` blocks until admin decides or timeout, `Decide()` notifies all waiters via channels with cascading (global notifies VM/skill waiters, host-only notifies path-specific waiters and vice versa).
- **Path matching**: `CheckExistingWithPath(host, path, skillID, sourceIP)` scans approvals using host wildcards and path prefix matching with longest-prefix-wins semantics. `CheckExistingForHost()` checks if any approval exists for a host regardless of path (used for CONNECT+MITM tunnel decisions). `MatchPath(prefix, path)` returns true if the request path starts with the prefix.
- **Source IP extraction**: `extractSourceIP()` in proxy.go strips the port from `RemoteAddr` to get the VM's IP for approval lookups.
- **Test helpers**: `setupProxy(t)` creates a test proxy with 50ms approval timeout. `setupProxyWithCA(t)` adds a CA for MITM tests. Registry tests use `setupProxy(t, upstream)` with a mock upstream `httptest.Server`.
- **Image approval**: Uses a second `approval.Manager` instance. `Host` field holds image references (e.g., `docker.io/library/ubuntu:latest`). `CheckExistingWithMatcher()` enables custom pattern matching via `registry.MatchImageRef()` which supports `docker.io/library/*` and `docker.io/library/ubuntu:*` wildcards.
- **Registry utilities**: `registry.ParsePath()` extracts name+reference from V2 API URLs. `registry.RegistryForHost()` looks up the registry config for a hostname. `registry.ParseImageRef()` constructs full image references. These are used by `handleRegistryTLSRequest()` in the proxy.
- **Agent management**: `agent.Manager` stores agent configs indexed by ID and MAC. `SetStaticLease()` and `SetHost()` keep DHCP/DNS in sync when agents are created/updated/deleted. Boot file downloads happen asynchronously with status tracking.
- **Minimal external dependencies**: Core proxy uses Go stdlib. Database drivers (MSSQL, PostgreSQL, MySQL) are the exception. Don't add unnecessary third-party packages.

## When Making Changes
- Run `go test ./...` after changes; all tests should pass
- The proxy handles three modes: explicit HTTP proxy, explicit CONNECT/MITM, and transparent TLS interception
- Error responses use `writeErrorResponse()` (for http.ResponseWriter) and `writeErrorResponseConn()` (for net.Conn). StatusDenied → 403, StatusPendingTimeout → 407. Always include plain text body with `Firewall4AI:` prefix.
- Disabled language/distro checks happen at the top of `handlePackageRepoHTTPRequest` and `handlePackageRepoTLSRequest` before any package parsing. Uses `config.IsLanguageDisabled()` and `config.IsDistroDisabled()`.
- The `checkApproval(host, path, skill, sourceIP)` function checks: pre-approved hosts -> global approvals -> VM-specific approvals -> skill-specific approvals -> register pending and wait. Path-aware matching uses longest-prefix-wins semantics.
- For CONNECT+MITM, `checkHostApproval()` allows the tunnel if any approval (host-only or path-specific) exists; per-request path checks happen in `handleMITMRequest()`. For blind tunnels (no MITM), only host-level approval is checked.
- All approval methods take four identifiers: `host`, `skillID`, `sourceIP`, `pathPrefix`. The approval key is `sourceIP|skillID|host|pathPrefix`.
- The admin UI is vanilla JS with no build step; changes to `web/static/` are embedded at compile time via `go:embed`
- VM appliance is built as a Debian 13 ISO via Elemental Toolkit (Dockerfile + `elemental build-iso`)
- System config: iptables rules in `scripts/`, network in `config/network/`
- DHCP/DNS/TFTP are integrated into the Go binary — no external dnsmasq needed
- Persistent data (state.json, CA certs, netboot files, DHCP leases) survives reboots/upgrades via COS_PERSISTENT partition
- OTA upgrades via `elemental upgrade --system oci:<image>` using the pushed container image from GHCR
- The transparent proxy detects registry hosts via `registry.RegistryForHost()` and routes to `handleRegistryTLSRequest()` for image-level approval instead of host-level
- Image approvals use a second `approval.Manager` instance, persisted as `image_approvals` in state.json
- Image approvals follow the same three-level pattern as host approvals; the `Host` field contains the image reference (e.g., `docker.io/library/ubuntu:latest`)
- Registry config is in `config.json` under `registries` array; each entry has `name` and `hosts` (all associated hostnames: registry API, auth, CDN)
- All configured registry hosts are auto-approved for network access; the real access control is per-image
- Agent management API: CRUD via `/api/agents`, boot file download trigger via `/api/agents/download`
- Boot endpoints on agent API: `/boot/ipxe?mac=XX` (iPXE script), `/boot/preseed/{id}` (Debian/Ubuntu), `/boot/autoinstall/{id}` (Alpine), `/boot/{os}/{ver}/kernel` and `/boot/{os}/{ver}/initrd` (boot files)
- Netboot files are cached in `{DataDir}/netboot/{os}/{version}/` and downloaded on demand when an agent is configured
- iPXE bootloader files (undionly.kpxe, ipxe.efi) are served via TFTP from `{DataDir}/netboot/tftp/`
- SQL database connections: CRUD via `/api/databases` (admin API). Agent API serves `POST /v1/db/{api_path}/query` with JSON body `{"query": "SELECT ...", "args": []}`. Each database has a unique `api_path` for routing. Passwords masked in admin API responses. Connections are lazily created and pooled via `database/sql`.
- Database manager (`database.Manager`) stores configs indexed by ID. `GetByAPIPath()` looks up active configs by API path. `Query()` determines read vs write queries by SQL prefix. Results returned as `{columns: [...], rows: [[...]], error: ""}`.
- The admin UI "Credentials" page includes a "SQL Databases" section for managing database connections with a separate modal form for MSSQL/PostgreSQL/MySQL configs.
- The admin UI "System" page (formerly "Settings") includes a service logs viewer at the top that shows `journalctl` output for whitelisted systemd services.
