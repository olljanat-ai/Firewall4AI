# CLAUDE.md - Firewall4AI

## Project Overview
Firewall4AI is a transparent firewall/proxy that controls AI agent internet access from isolated VM environments. It sits between agent VMs and the internet, intercepting all HTTP/HTTPS traffic transparently via iptables without requiring proxy configuration on agent VMs.

## Architecture
- **Single Go binary**, zero external dependencies (stdlib only)
- **Three listeners**: HTTP proxy (:8080), transparent TLS (:8443), admin UI (:443)
- **iptables REDIRECT**: Port 80 -> :8080, port 443 -> :8443 for transparent interception
- **TLS MITM**: Auto-generated CA signs per-host certificates; agents must trust the CA
- **Default-deny**: All connections blocked until admin approves
- **Three-level approval**: Global (all agents/VMs) -> VM-specific (by source IP) -> Skill-specific (by skill token, for getting more permissions)
- **VM appliance**: Debian 13 ISO built with Elemental Toolkit, two NICs (eth0=internet, eth1=agent network 10.255.255.0/24)
- **Immutable OS**: Elemental Toolkit provides immutable rootfs with btrfs snapshots and OTA upgrades via container images
- **Persistent storage**: Rules (state.json), CA certificates, DHCP leases, and logs stored on COS_PERSISTENT partition
- **Permanent DHCP leases**: Agents get stable IPs for reliable VM-specific approvals

## Key Directories
```
cmd/firewall4ai/     - Application entry point (main.go)
internal/
  api/               - REST API handlers for admin UI
  approval/          - Default-deny approval system with three levels (global/VM/skill)
  auth/              - Skill tokens (GUID format) and authentication
  certgen/           - CA and per-host TLS certificate generation
  config/            - JSON configuration loading
  credentials/       - Credential injection (header/bearer/basic_auth/query_param)
  logging/           - In-memory circular buffer request logger
  proxy/             - HTTP/HTTPS proxy with transparent + explicit modes
  store/             - Generic JSON file persistence
web/static/          - Admin UI (vanilla HTML/JS/CSS, embedded at build time)
Dockerfile           - Multi-stage build: elemental CLI + firewall4ai binary + Debian 13 OS image
config/              - Elemental Toolkit and system configuration
  config.yaml        - Elemental install/upgrade config (partition sizes, OCI upgrade image)
  snapshotter.yaml   - Btrfs snapshotter config
  bootargs.cfg       - GRUB boot arguments
  50-elemental-initrd.conf - Dracut initrd configuration
  oem/               - OEM cloud-init configs (persistence, layout)
  dnsmasq/           - dnsmasq DHCP/DNS config for agent network
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
- **Anonymous access**: Agents can make requests without skill tokens. These go through the global/VM approval system. Invalid tokens are rejected; missing tokens are anonymous.
- **GUID tokens**: Skill tokens use UUID v4 format (e.g., `a1b2c3d4-e5f6-4789-abcd-ef0123456789`). Skill IDs can be user-provided or auto-generated GUIDs.
- **State persistence**: All state (skills, approvals, credentials) stored in a single `state.json` file, loaded at startup, saved on mutations and shutdown.

## Common Patterns
- **Thread safety**: All managers use `sync.RWMutex`. Read operations use `RLock`, write operations use `Lock`.
- **Approval flow**: `Check(host, skillID, sourceIP)` registers a pending entry, `WaitForDecision()` blocks until admin decides or timeout, `Decide()` notifies all waiters via channels with cascading (global notifies VM/skill waiters).
- **Source IP extraction**: `extractSourceIP()` in proxy.go strips the port from `RemoteAddr` to get the VM's IP for approval lookups.
- **Test helpers**: `setupProxy(t)` creates a test proxy with 50ms approval timeout. `setupProxyWithCA(t)` adds a CA for MITM tests.
- **No external dependencies**: Everything uses Go stdlib. Don't add third-party packages.

## When Making Changes
- Run `go test ./...` after changes; all tests should pass
- The proxy handles three modes: explicit HTTP proxy, explicit CONNECT/MITM, and transparent TLS interception
- The `checkApproval()` function checks: pre-approved hosts -> global approvals -> VM-specific approvals -> skill-specific approvals -> register pending and wait
- All approval methods take three identifiers: `host`, `skillID`, `sourceIP`
- The admin UI is vanilla JS with no build step; changes to `web/static/` are embedded at compile time via `go:embed`
- VM appliance is built as a Debian 13 ISO via Elemental Toolkit (Dockerfile + `elemental build-iso`)
- System config: iptables rules in `scripts/`, dnsmasq config in `config/dnsmasq/`, network in `config/network/`
- Persistent data (state.json, CA certs, logs, DHCP leases) survives reboots/upgrades via COS_PERSISTENT partition
- OTA upgrades via `elemental upgrade --system oci:<image>` using the pushed container image from GHCR
