## Usage
### Transparent Mode
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
