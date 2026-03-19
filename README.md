# Squid4Claw

Transparent HTTP/HTTPS proxy for controlling where AI agents can connect from isolated environments.

Connections are **denied by default** and require admin approval before first use. AI agents authenticate with skill-specific tokens that load per-skill rulesets. The proxy performs **TLS MITM inspection** on HTTPS traffic, enabling credential injection for both HTTP and HTTPS requests so agents never need to know secrets directly.

## Features

- **Default-deny proxy** - All outbound connections require explicit admin approval
- **TLS MITM inspection** - Full HTTPS inspection with auto-generated per-host certificates, enabling credential injection and request logging for encrypted traffic
- **Skill-based authentication** - Each AI agent skill gets its own token and ruleset
- **Pre-approved hosts** - Configure allowed hosts per skill to skip manual approval
- **Credential injection** - Inject API keys, bearer tokens, basic auth, or query parameters into both HTTP and HTTPS requests on behalf of agents
- **Auto-generated certificates** - CA and admin UI TLS certificates are generated automatically on first run
- **Admin UI** - Modern web interface (always HTTPS) for managing approvals, skills, credentials, and viewing logs
- **Real-time logging** - All proxy requests (including decrypted HTTPS) are logged and visible in the admin UI

## Architecture

```
AI Agent --[HTTP]--> Proxy (:8080) --[approved]--> Target Service
AI Agent --[HTTPS CONNECT]--> Proxy (:8080) --[TLS MITM]--> Target Service
                                |
                   Admin UI (:443/HTTPS) <-- Human Admin
```

The proxy runs two servers:
- **Proxy server** (default `:8080`) - Handles agent HTTP requests and HTTPS CONNECT with TLS MITM inspection
- **Admin server** (default `:443`) - Serves the admin UI and REST API over HTTPS (always TLS)

On first startup, the proxy:
1. Generates a **CA certificate** (`data/ca.crt` + `data/ca.key`) used for signing per-host TLS certificates during MITM inspection
2. Generates a **self-signed certificate** for the admin UI (or uses user-provided cert/key)

State is persisted to a JSON file in the data directory.

## Quick Start

### Option A: VM Appliance (Recommended)

Download a pre-built VM image from the [Releases](../../releases) page:

| Format | Platform |
|--------|----------|
| `squid4claw-*.qcow2` | QEMU/KVM, Proxmox |
| `squid4claw-*.vmdk` | VMware ESXi/Workstation |
| `squid4claw-*.vhdx` | Hyper-V |

The VM is a minimal Alpine Linux appliance that runs Squid4Claw as the main service with two network interfaces:

| Interface | Configuration | Purpose |
|-----------|--------------|---------|
| `eth0` | DHCP client | External/uplink to the internet |
| `eth1` | Static `10.255.255.1/24` | Internal network for AI agents |

**What's included:**
- **DHCP server** on eth1 serving `10.255.255.10` - `10.255.255.254` to agents
- **DNS server** (dnsmasq) forwarding to `1.1.1.1` and `1.0.0.1`
- **iptables firewall** that blocks all direct internet access from the agent network -- agents can only reach the proxy (port 8080) and admin UI (port 443)
- **TLS MITM inspection** with auto-generated CA certificate

**Setup:**
1. Create a VM with 2 NICs: one bridged/NAT to the internet, one on an isolated internal network
2. Boot the VM from the downloaded disk image
3. Access the admin UI at `https://10.255.255.1:443` from the agent network
4. Download the CA cert at `https://10.255.255.1:443/ca.crt` and install it on agent machines
5. Configure agents to use `http://10.255.255.1:8080` as their HTTP proxy

Default root password: `squid4claw` (change after first login via serial console or SSH)

### Option B: Standalone Binary

```bash
# Build
make build

# Run with defaults
./bin/squid4claw

# Run with config file
./bin/squid4claw -config config.json
```

On first run, the CA certificate is generated at `./data/ca.crt`. You must install this CA on systems that will connect through the proxy (see [Trusting the CA Certificate](#trusting-the-ca-certificate)).

The CA certificate is also available for download at `https://localhost:443/ca.crt`.

## Configuration

Create a `config.json` file (all fields optional):

```json
{
  "listen_addr": ":8080",
  "admin_addr": ":443",
  "data_dir": "./data",
  "tls_cert_file": "",
  "tls_key_file": "",
  "max_log_entries": 10000
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `listen_addr` | `:8080` | Proxy server listen address |
| `admin_addr` | `:443` | Admin UI/API listen address (always HTTPS) |
| `data_dir` | `./data` | Directory for persistent state and CA certificate |
| `tls_cert_file` | (empty) | Custom TLS certificate for admin server (auto-generated if empty) |
| `tls_key_file` | (empty) | Custom TLS key for admin server (auto-generated if empty) |
| `max_log_entries` | `10000` | Maximum log entries kept in memory |

## Trusting the CA Certificate

For TLS MITM inspection to work, the AI agent's environment must trust the Squid4Claw CA. The CA certificate is at `<data_dir>/ca.crt`.

### Debian/Ubuntu

```bash
sudo cp data/ca.crt /usr/local/share/ca-certificates/squid4claw.crt
sudo update-ca-certificates
```

### RHEL/CentOS/Fedora

```bash
sudo cp data/ca.crt /etc/pki/ca-trust/source/anchors/squid4claw.crt
sudo update-ca-trust
```

### For specific tools

```bash
# curl
curl --cacert data/ca.crt https://example.com

# Python requests
export REQUESTS_CA_BUNDLE=data/ca.crt

# Node.js
export NODE_EXTRA_CA_CERTS=data/ca.crt

# Go
export SSL_CERT_FILE=data/ca.crt
```

## Locking Down the Network with iptables

To force all HTTP/HTTPS traffic from the AI agent environment through Squid4Claw and block everything else, use the following iptables rules. This assumes:

- Squid4Claw runs on the **same host** as the agents (proxy at `127.0.0.1:8080`, admin at `127.0.0.1:443`)
- Squid4Claw runs as user `squid4claw` (so its own outbound traffic is not blocked)
- The agent runs as user `agent`

```bash
# ============================================================
# Squid4Claw iptables lockdown rules
# ============================================================
# Run as root. Adjust PROXY_USER, AGENT_USER, and ports as needed.

PROXY_USER=squid4claw
AGENT_USER=agent
PROXY_PORT=8080
ADMIN_PORT=443

# --- Allow the proxy process itself to make outbound connections ---
iptables -A OUTPUT -m owner --uid-owner $(id -u $PROXY_USER) -j ACCEPT

# --- Allow loopback (agent <-> proxy communication) ---
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT

# --- Allow established/related connections ---
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# --- Allow inbound to proxy and admin ports ---
iptables -A INPUT -p tcp --dport $PROXY_PORT -j ACCEPT
iptables -A INPUT -p tcp --dport $ADMIN_PORT -j ACCEPT

# --- Allow DNS for the proxy user ---
iptables -A OUTPUT -m owner --uid-owner $(id -u $PROXY_USER) -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner $(id -u $PROXY_USER) -p tcp --dport 53 -j ACCEPT

# --- Block ALL other outbound HTTP/HTTPS from the agent ---
iptables -A OUTPUT -m owner --uid-owner $(id -u $AGENT_USER) -p tcp --dport 80 -j REJECT
iptables -A OUTPUT -m owner --uid-owner $(id -u $AGENT_USER) -p tcp --dport 443 -j REJECT

# --- Block ALL other outbound TCP/UDP from the agent ---
iptables -A OUTPUT -m owner --uid-owner $(id -u $AGENT_USER) -p tcp -j REJECT
iptables -A OUTPUT -m owner --uid-owner $(id -u $AGENT_USER) -p udp -j REJECT
```

### With separate proxy host

If Squid4Claw runs on a different machine (e.g., gateway), adjust the rules for the agent host:

```bash
PROXY_IP=10.0.0.1
PROXY_PORT=8080
ADMIN_PORT=443

# Allow connections to the proxy only
iptables -A OUTPUT -p tcp -d $PROXY_IP --dport $PROXY_PORT -j ACCEPT
iptables -A OUTPUT -p tcp -d $PROXY_IP --dport $ADMIN_PORT -j ACCEPT

# Allow DNS
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT

# Allow established
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
iptables -A OUTPUT -o lo -j ACCEPT

# Block everything else
iptables -A OUTPUT -j REJECT
```

### Persisting iptables rules

```bash
# Save rules
iptables-save > /etc/iptables/rules.v4

# On Debian/Ubuntu, install iptables-persistent:
apt install iptables-persistent
```

### Verifying the lockdown

```bash
# As the agent user, direct connections should be blocked:
sudo -u agent curl https://example.com
# Expected: Connection refused

# Through the proxy (without token), should get 407:
sudo -u agent curl -x http://127.0.0.1:8080 http://example.com
# Expected: 407 Proxy Authentication Required

# Through the proxy with valid token:
sudo -u agent curl -x http://127.0.0.1:8080 \
  -H "X-Squid4Claw-Token: <token>" \
  --cacert data/ca.crt \
  https://example.com
# Expected: Works if host is approved
```

## Usage

### 1. Create a Skill

Via the admin UI or API:

```bash
curl -k -X POST https://localhost:443/api/skills \
  -H 'Content-Type: application/json' \
  -d '{"id": "web-scraper", "name": "Web Scraper Agent", "allowed_hosts": ["api.example.com"]}'
```

This returns a token that the AI agent must use for authentication.

### 2. Configure the AI Agent

Set the agent's HTTP proxy to `http://localhost:8080` and include the token header in all requests:

```
X-Squid4Claw-Token: <skill-token>
```

The agent's environment must also trust the Squid4Claw CA (see above).

### 3. Approve Connections

When an agent tries to connect to a host not in its pre-approved list, the request blocks and appears in the admin UI as pending. An admin can approve or deny it.

### 4. Credential Injection (Optional)

Configure credentials in the admin UI to automatically inject authentication into outgoing requests. This works for **both HTTP and HTTPS** thanks to TLS MITM inspection. Supported injection types:

- **Custom Header** - Set any header (e.g., `X-API-Key`)
- **Bearer Token** - Sets `Authorization: Bearer <token>`
- **Basic Auth** - Sets HTTP basic authentication
- **Query Parameter** - Appends a query parameter

Credentials can be scoped to specific hosts (with wildcard support like `*.example.com`) and specific skills.

## API Reference

### Skills
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/skills` | List all skills |
| `POST` | `/api/skills` | Create a skill |
| `PUT` | `/api/skills` | Update a skill |
| `DELETE` | `/api/skills?id=<id>` | Delete a skill |

### Approvals
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/approvals` | List all approvals |
| `GET` | `/api/approvals/pending` | List pending approvals |
| `POST` | `/api/approvals/decide` | Approve or deny a host |

### Credentials
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/credentials` | List credentials (secrets masked) |
| `POST` | `/api/credentials` | Add a credential |
| `PUT` | `/api/credentials` | Update a credential |
| `DELETE` | `/api/credentials?id=<id>` | Delete a credential |

### Logs
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/logs?limit=100` | Get recent log entries |
| `GET` | `/api/logs?after=<id>` | Get log entries after a given ID |
| `GET` | `/api/logs/stats` | Get log statistics |

### Other
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Health check |
| `GET` | `/ca.crt` | Download CA certificate |

## Development

```bash
# Run tests
make test

# Lint
make lint

# Build
make build

# Build, test, and lint
make all
```

## Building VM Images Locally

To build VM images locally (requires root on Alpine Linux or a CI environment):

```bash
cd vm
sudo VERSION=v1.0.0 ./build.sh
```

This produces `dist/squid4claw-v1.0.0.{qcow2,vmdk,vhdx}`.

## Release

Releases are automated via GitHub Actions. To create a release:

```bash
git tag v1.0.0
git push origin v1.0.0
```

This builds a Linux amd64 binary and VM appliance images (qcow2, vmdk, vhdx), then creates a GitHub release with auto-generated release notes.

## License

See [LICENSE](LICENSE) file.
