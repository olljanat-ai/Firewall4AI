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
Download a pre-built VM image from the [Releases](../../releases) page:

| Format | Platform |
|--------|----------|
| `firewall4ai-*.qcow2` | QEMU/KVM, Proxmox |
| `firewall4ai-*.vmdk` | VMware ESXi/Workstation |
| `firewall4ai-*.vhdx` | Hyper-V |

The VM is a minimal Alpine Linux appliance that runs Firewall4AI as the main service with two network interfaces:

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
  "max_log_entries": 10000
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

### Explicit Proxy Mode (Backward Compatible)
Agents can still be configured to use the proxy explicitly if preferred:
```bash
export HTTP_PROXY=http://10.255.255.1:8080
export HTTPS_PROXY=http://10.255.255.1:8080
```

Both transparent and explicit proxy modes work simultaneously.

## API Reference
### Skills
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/skills` | List all skills |
| `POST` | `/api/skills` | Create a skill (ID auto-generated if omitted, token is GUID) |
| `PUT` | `/api/skills` | Update a skill |
| `DELETE` | `/api/skills?id=<id>` | Delete a skill |

### Approvals
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/approvals` | List all approvals |
| `GET` | `/api/approvals/pending` | List pending approvals |
| `POST` | `/api/approvals/decide` | Approve or deny a host (empty `skill_id` + empty `source_ip` = global, empty `skill_id` + `source_ip` = VM-specific) |

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
