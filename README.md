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

## Quick Start
Download a ISO file from the [Releases](../../releases) page.

The VM is a minimal Debian appliance that runs Firewall4AI as the main service with two network interfaces:
| Interface | Configuration | Purpose |
|-----------|--------------|---------|
| `eth0` | DHCP client | External/uplink to the internet |
| `eth1` | Static `10.255.255.1/24` | Internal network for AI agents |

**What's included:**
- **DHCP server** on eth1 serving `10.255.255.10` - `10.255.255.254` to agents
- **DNS server** forwarding to `1.1.1.1` and `1.0.0.1`
- **iptables firewall** with transparent proxy redirect - agents need no proxy configuration
- **TLS MITM inspection** with auto-generated CA certificate

**Setup:**
1. Create a VM with 2 NICs: one bridged/NAT to the internet, one on an isolated internal network
2. Boot the VM from the downloaded disk image
3. Download the CA cert at `http://10.255.255.1/ca.crt` and install it on agent machines
4. Access the admin UI at `https://<external IP>`
5. Agents can now make HTTP/HTTPS requests normally - all traffic is intercepted and routed through the approval system

**No proxy configuration needed on agent VMs** - the transparent proxy intercepts all traffic automatically.

Default root password: `elemental` (change after first login via serial console or SSH)

## Trusting the CA Certificate
For TLS MITM inspection to work, the AI agent's environment must trust the Firewall4AI CA.
```bash
sudo wget http://10.255.255.1/ca.crt -O /usr/local/share/ca-certificates/ca.crt
sudo update-ca-certificates
```
