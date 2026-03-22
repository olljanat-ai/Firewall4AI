# Firewall4AI

> [!CAUTION]
> Be aware that this project is in early draft/beta state and things are constantly changing still.

Transparent firewall for controlling where AI agents can connect from isolated environments.

Agents need **no proxy configuration** - all HTTP/HTTPS traffic is intercepted transparently via iptables. Connections are **denied by default** and require admin approval before first use. Agents can optionally authenticate with skill-specific tokens (GUID format) for per-skill rulesets. The proxy performs **TLS MITM inspection** on HTTPS traffic, enabling credential injection so agents never need to know secrets directly.

## Features

- **Fully transparent proxy** - Agents need no proxy configuration; iptables redirects all HTTP/HTTPS traffic automatically
- **Default-deny firewall** - All outbound connections require explicit admin approval
- **Three-level approvals** - Admin can approve hosts globally (all agents), per VM (by source IP), or per skill (for granting additional permissions)
- **Anonymous and authenticated access** - Agents can make web calls without skill tokens; admin controls what is allowed
- **TLS MITM inspection** - Full HTTPS inspection with auto-generated per-host certificates
- **Skill-based authentication** - Optional per-skill GUID tokens for fine-grained access control
- **Pre-approved hosts** - Configure allowed hosts per skill to skip manual approval
- **Credential injection** - Inject API keys, bearer tokens, basic auth, or query parameters into requests on behalf of agents
- **Admin UI** - Modern web interface (always HTTPS) for managing approvals, skills, credentials, and viewing logs
- **Container registry control** - Transparently intercepts Docker/container image pulls with per-image approval (no Docker mirror configuration needed)
- **Real-time logging** - All proxy requests (including decrypted HTTPS) are logged and visible in the admin UI

## Network Architecture

```
                    +-----------------------------------------+
                    |           External Network              |
                    |        (Internet / Corp LAN)            |
                    +-------------------+---------------------+
                                        |
                                   +----+----+
                                   |  eth0   |
                                   | (DHCP)  |
                    +--------------+---------+--------------+
                    |          Firewall4AI VM                |
                    |                                        |
                    |  +----------------------------------+  |
                    |  |  firewall4ai process             |  |
                    |  |                                  |  |
                    |  |  Proxy HTTP     :8080            |  |
                    |  |  Transparent TLS:8443            |  |
                    |  |  Admin UI       :443 (HTTPS)     |  |
                    |  |  + registry image-level approval  |  |
                    |  +----------------------------------+  |
                    |                                        |
                    |  +----------------------------------+  |
                    |  |  iptables NAT (PREROUTING)       |  |
                    |  |                                  |  |
                    |  |  :80  --> REDIRECT --> :8080     |  |
                    |  |  :443 --> REDIRECT --> :8443     |  |
                    |  +----------------------------------+  |
                    |                                        |
                    +--------------+---------+--------------+
                                   |  eth1   |
                                   |10.255.255.1|
                                   +----+----+
                                        |
                    +-------------------+---------------------+
                    |      Internal Network (10.255.255.0/24) |
                    |           (Isolated / No Internet)      |
                    |                                         |
                    |  +----------+  +----------+  +-------+  |
                    |  | Agent VM |  | Agent VM |  | Agent |  |
                    |  |  .10     |  |  .11     |  | .12   |  |
                    |  +----------+  +----------+  +-------+  |
                    +-----------------------------------------+
```

### Traffic Flow

```
Agent VM                      Firewall4AI VM                   Internet
    |                               |                               |
    |  curl http://api.com/data     |                               |
    | ------ TCP :80 -------------> |                               |
    |     (iptables REDIRECT:8080)  |                               |
    |                               | --- check approval -------->  |
    |                               | <-- if approved, forward -->  |
    | <---- HTTP response --------- |                               |
    |                               |                               |
    |  curl https://api.com/data    |                               |
    | ------ TCP :443 ------------> |                               |
    |     (iptables REDIRECT:8443)  |                               |
    | <---- TLS (MITM cert) ------- |                               |
    | ------ HTTP inside TLS -----> |                               |
    |                               | --- TLS to real host -------> |
    |                               | <-- response ---------------- |
    | <---- response --------------- |                               |
    |                               |                               |
    | Agents need NO proxy config!  |  All traffic is intercepted.  |
```

### Firewall Rules Summary

| Direction | From | To | Rule |
|-----------|------|----|------|
| Agent -> Firewall4AI | eth1 | DNS (:53) | ACCEPT |
| Agent -> Firewall4AI | eth1 | DHCP (:67) | ACCEPT |
| Agent -> Firewall4AI | eth1 | Proxy (:8080) | ACCEPT |
| Agent -> Firewall4AI | eth1 | Transparent TLS (:8443) | ACCEPT |
| Agent -> Firewall4AI | eth1 | ICMP | ACCEPT |
| Agent -> Firewall4AI | eth1 | anything else | REJECT |
| Agent -> Internet | eth1 | FORWARD | REJECT |
| External -> Firewall4AI | eth0 | any | ACCEPT |
| NAT | eth1 :80 | REDIRECT :8080 | Transparent HTTP |
| NAT | eth1 :443 | REDIRECT :8443 | Transparent HTTPS |

## Quick Start
Download a ISO file from the [Releases](../../releases) page.

The VM is a minimal Debian appliance that runs Firewall4AI as the main service with two network interfaces:
| Interface | Configuration | Purpose |
|-----------|--------------|---------|
| `eth0` | DHCP client | External/uplink to the internet |
| `eth1` | Static `10.255.255.1/24` | Internal network for AI agents |

**What's included:**
- **DHCP server** on eth1 serving `10.255.255.10` - `10.255.255.254` to agents
- **DNS server** (dnsmasq) forwarding to `1.1.1.1` and `1.0.0.1`
- **iptables firewall** with transparent proxy redirect - agents need no proxy configuration
- **TLS MITM inspection** with auto-generated CA certificate

**Setup:**
1. Create a VM with 2 NICs: one bridged/NAT to the internet, one on an isolated internal network
2. Boot the VM from the downloaded disk image
3. Download the CA cert at `https://10.255.255.1:443/ca.crt` and install it on agent machines
4. Access the admin UI at `https://10.255.255.1:443`
5. Agents can now make HTTP/HTTPS requests normally - all traffic is intercepted and routed through the approval system

**No proxy configuration needed on agent VMs** - the transparent proxy intercepts all traffic automatically.

Default root password: `firewall4ai` (change after first login via serial console or SSH)

## Configuration
Create a `config.json` file (all fields optional):

```json
{
  "listen_addr": ":8080",
  "admin_addr": ":443",
  "transparent_tls_addr": ":8443",
  "data_dir": "./data",
  "tls_cert_file": "",
  "tls_key_file": "",
  "max_log_entries": 10000,
  "registries": [
    {"name": "docker.io", "hosts": ["registry-1.docker.io", "auth.docker.io", "production.cloudflare.docker.com"]},
    {"name": "ghcr.io", "hosts": ["ghcr.io"]}
  ]
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `listen_addr` | `:8080` | Proxy server listen address (HTTP proxy + transparent HTTP) |
| `admin_addr` | `:443` | Admin UI/API listen address (always HTTPS) |
| `transparent_tls_addr` | `:8443` | Transparent TLS interception listener (iptables redirects :443 here) |
| `data_dir` | `./data` | Directory for persistent state and CA certificate |
| `tls_cert_file` | (empty) | Custom TLS certificate for admin server (auto-generated if empty) |
| `tls_key_file` | (empty) | Custom TLS key for admin server (auto-generated if empty) |
| `max_log_entries` | `10000` | Maximum log entries kept in memory |
| `registries` | `[]` | Container registries for image-level approval (each with `name` and `hosts` list) |

## Trusting the CA Certificate
For TLS MITM inspection to work, the AI agent's environment must trust the Firewall4AI CA. The CA certificate is at `<data_dir>/ca.crt`.

### Debian/Ubuntu
```bash
sudo cp data/ca.crt /usr/local/share/ca-certificates/firewall4ai.crt
sudo update-ca-certificates
```

### RHEL/CentOS/Fedora
```bash
sudo cp data/ca.crt /etc/pki/ca-trust/source/anchors/firewall4ai.crt
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

## Usage

### Transparent Mode (No Configuration Required)
Once agents trust the CA certificate, all HTTP/HTTPS traffic is intercepted automatically:

```bash
# On the agent VM - just make normal requests:
curl http://api.example.com/data      # Intercepted via iptables :80 -> :8080
curl https://api.example.com/data     # Intercepted via iptables :443 -> :8443
```

The admin UI will show pending approval requests. Approve them globally (for all agents), per VM (by source IP), or create skills for granting additional permissions to specific agents.

### Skill-Based Access (Optional)
For granting additional permissions to specific agents, create skills and assign tokens:

#### 1. Create a Skill
Via the admin UI or API:
```bash
curl -k -X POST https://localhost:443/api/skills \
  -H 'Content-Type: application/json' \
  -d '{"name": "Web Scraper Agent", "allowed_hosts": ["api.example.com"]}'
```

This returns a GUID token and auto-generated skill ID. Skills can also have a custom ID:
```bash
curl -k -X POST https://localhost:443/api/skills \
  -H 'Content-Type: application/json' \
  -d '{"id": "web-scraper", "name": "Web Scraper Agent", "allowed_hosts": ["api.example.com"]}'
```

#### 2. Configure the AI Agent (Optional)
Agents can include the token in HTTP headers for skill-specific authentication:
```
X-Firewall4AI-Token: <skill-token-guid>
```

This works in both transparent mode (header in the HTTP request) and explicit proxy mode. Agents without a token are treated as anonymous and go through global approvals.

#### 3. Approve Connections
When an agent tries to connect to a host not in its pre-approved list, the request blocks and appears in the admin UI as pending. An admin can:
- **Approve** - Allow at the current level (skill-specific or VM-specific)
- **Approve VM** - Allow for all agents on that specific VM (by source IP)
- **Approve Global** - Allow for all agents on all VMs
- **Deny** - Block the connection

#### 4. Credential Injection (Optional)
Configure credentials in the admin UI to automatically inject authentication into outgoing requests. This works for **both HTTP and HTTPS** thanks to TLS MITM inspection. Supported injection types:
- **Custom Header** - Set any header (e.g., `X-API-Key`)
- **Bearer Token** - Sets `Authorization: Bearer <token>`
- **Basic Auth** - Sets HTTP basic authentication
- **Query Parameter** - Appends a query parameter

Credentials can be scoped to specific hosts (with wildcard support like `*.example.com`) and specific skills.

### Container Registry Control
Firewall4AI transparently intercepts container image pulls via the same TLS MITM proxy used for web traffic. **No Docker or containerd mirror configuration is needed on agent VMs** — image pulls are intercepted automatically, just like any other HTTPS traffic.

When registries are configured in `config.json`, the proxy recognizes traffic to those registry hosts and applies image-level approval instead of host-level approval. All associated hosts (registry API, auth endpoints, CDN) are auto-approved at the host level — the real access control happens per-image.

#### Container Image Approval Flow
When an agent pulls an image (e.g., `docker pull ubuntu:latest`):
1. Docker connects to `registry-1.docker.io` — transparently intercepted by iptables
2. The proxy detects this is a configured registry host and parses the image reference (`docker.io/library/ubuntu:latest`)
3. If no approval exists, a pending entry appears in the admin UI **Container Images** tab
4. Admin approves or denies the image pull
5. Wildcard patterns are supported for pre-approving images:
   - `docker.io/library/*` — all official Docker Hub images
   - `docker.io/library/ubuntu:*` — any tag of ubuntu
   - `ghcr.io/myorg/*` — all images from a GitHub organization

Image approvals use the same three-level system as host approvals (global, VM-specific, skill-specific).

#### Registry Configuration
The `registries` config lists all hostnames associated with each registry (API, auth, CDN):
```json
{
  "registries": [
    {"name": "docker.io", "hosts": ["registry-1.docker.io", "auth.docker.io", "production.cloudflare.docker.com"]},
    {"name": "ghcr.io", "hosts": ["ghcr.io"]}
  ]
}
```
