## Usage
### Transparent Mode
Once agents trust the CA certificate, all HTTP/HTTPS traffic is intercepted automatically:

```bash
# On the agent VM - just make normal requests:
curl http://api.example.com/data      # Intercepted via iptables :80 -> :8080
curl https://api.example.com/data     # Intercepted via iptables :443 -> :8443
curl https://cluster.example.com:6443 # HTTPS on other ports is intercepted too
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

### Client Certificate Authentication (mutual TLS)
Some servers authenticate their clients with certificates instead of tokens — Kubernetes API servers are the common case, including AKS, EKS and GKE clusters. Such connections cannot be inspected: the proxy has no access to the client's private key, so an intercepted session would reach the server without any certificate and the server would answer `the server has asked for the client to provide credentials`.

The proxy detects these servers automatically. Before intercepting a connection it checks whether the upstream server asks for a client certificate, and if it does, the connection is tunneled untouched so the client's own TLS session reaches the server. The result is cached per host for 30 minutes and shown in the request log:

```
TLS  onek8s-prototype.hcp.swedencentral.azmk8s.io
     upstream requests a client certificate: TLS inspection disabled for this host
```

Tunneled connections are still subject to approval, but only at the host level — URL paths, packages and image references are invisible inside the tunnel, so a path-restricted approval does not authorize one. This makes `kubectl`, `helm` and Terraform's `kubernetes`/`helm` providers work against clusters that use certificate authentication.

To force passthrough for hosts that are not detected automatically, list them in `config.json` (wildcards supported):
```json
{
  "tls_passthrough_hosts": ["*.azmk8s.io", "vault.internal.example.com"]
}
```

### HTTPS on Non-Standard Ports
Only traffic to a port that is redirected to the proxy is intercepted; everything else from the agent network is rejected outright. AKS, EKS and GKE publish their Kubernetes API on 443, but many other clusters do not — Oracle OKE, kubeadm and Rancher/RKE use 6443, OpenShift and minikube use 8443, MicroK8s uses 16443. Before these ports were redirected, an agent connecting to such a cluster got

```
Kubernetes cluster unreachable: Get "https://<ip>:6443/version":
dial tcp <ip>:6443: connect: connection refused
```

with nothing in the request log, because the connection never reached the proxy.

Ports 443, 6443, 8443, 9443 and 16443 are redirected by default. Override the list in `config.json`:
```json
{
  "transparent_tls_ports": [443, 6443, 8443, 9443, 16443, 8006]
}
```

The rules are installed at startup and re-checked every minute, so re-running the iptables script does not take them offline. A connection to a port that is *not* in the list is still rejected by the FORWARD chain; those packets are now logged to the kernel log, so `journalctl -k | grep FW4AI-NOT-INTERCEPTED` shows which destination an agent failed to reach.

### Upstream Certificate Trust
The proxy connects to upstream servers on behalf of agents, so it is the party that validates upstream certificates. Certificates that cannot be verified — internal PKI, self-signed appliances — are accepted rather than failing the request, and each one is recorded in the request log:

```
TLS  k8s.internal.example.com
     untrusted upstream certificate accepted: x509: certificate signed by unknown authority
```

Access control stays with the approval system: an untrusted certificate does not grant access to a host that has not been approved.

### Disabling Transfer-Encoding per URL
When the agent's request has no declared length, the proxy forwards it with `Transfer-Encoding: chunked`. Some servers refuse chunked requests outright — Azure Blob Storage answers:

```xml
<Error><Code>UnsupportedHeader</Code><Message>One of the HTTP headers specified in the request is not supported.
...</Message><HeaderName>Transfer-Encoding</HeaderName></Error>
```

Edit the URL rule for that host (Rules → Edit) and set **Transfer-Encoding** to *Disabled*. The proxy then buffers the request body, sends an explicit `Content-Length`, and strips the `Transfer-Encoding` header for every request the rule covers. Combine it with a path prefix to limit the scope, e.g. host `onek8stfstate.blob.core.windows.net` with path prefix `/tfstate/`.

Bodies are buffered in memory, so requests larger than 10 MB are rejected with a `502` naming the limit instead of being sent chunked. Rules without the setting keep the default behaviour.

The same rule can be set through the API:

```bash
curl -X POST https://<firewall>/api/approvals/decide \
  -d '{"host":"onek8stfstate.blob.core.windows.net","path_prefix":"/tfstate/","status":"approved","disable_transfer_encoding":true}'
```

### Container Registry Control
Firewall4AI transparently intercepts container image pulls via the same TLS MITM proxy used for web traffic. **No Docker or containerd mirror configuration is needed on agent VMs** — image pulls are intercepted automatically, just like any other HTTPS traffic.

When registries are configured in `config.json`, the proxy recognizes traffic to those registry hosts and applies image-level approval instead of host-level approval. All associated hosts (registry API, auth endpoints, CDN) are auto-approved at the host level — the real access control happens per-image.

#### Container Image Approval Flow
When an agent pulls an image (e.g., `docker pull ubuntu:latest`):
1. Docker connects to `registry-1.docker.io` — transparently intercepted by iptables
2. The proxy detects this is a configured registry host and parses the image reference (`docker.io/library/ubuntu:latest`)
3. If no approval exists, a pending entry appears in the admin UI **Containers** tab
4. Admin approves or denies the image pull
5. Wildcard patterns are supported for pre-approving images:
   - `docker.io/library/*` — all official Docker Hub images
   - `docker.io/library/ubuntu:*` — any tag of ubuntu
   - `ghcr.io/myorg/*` — all images from a GitHub organization

Container Images use the same three-level system as host approvals (global, VM-specific, skill-specific).

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
