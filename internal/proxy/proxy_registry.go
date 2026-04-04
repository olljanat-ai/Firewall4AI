package proxy

import (
        "net"
        "net/http"
        "time"

        "github.com/olljanat-ai/firewall4ai/internal/approval"
        "github.com/olljanat-ai/firewall4ai/internal/auth"
        "github.com/olljanat-ai/firewall4ai/internal/config"
        proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
        "github.com/olljanat-ai/firewall4ai/internal/registry"
)

// handleRegistryTLSRequest handles a request to a known container registry host.
// Manifest requests trigger image-level approval; blob requests use repo-level
// approval; all other registry traffic (auth, /v2/ pings) is auto-approved.
func (p *Proxy) handleRegistryTLSRequest(clientConn net.Conn, req *http.Request, host, sourceIP string, skill *auth.Skill, reg *config.RegistryConfig, start time.Time) {
        sid := getSkillID(skill)
        urlPath := req.URL.Path

        name, _, pathType, isV2 := registry.ParsePath(urlPath)

        if isV2 && (pathType == "manifests" || pathType == "blobs") {
                // Manifest and blob requests use repo-level approval.
                // Approving a repo allows all tags, digests, and layers.
                // In learning mode, skip the fast-path check since pending entries
                // won't match; go through checkImageApproval which handles learning mode.
                repo := registry.ParseImageRepo(reg.Name, name)
                if p.LearningMode || !registry.CheckRepoApproval(p.ImageApprovals, repo) {
                        if pathType == "blobs" && !p.LearningMode {
                                // Blobs don't create pending entries; they are only
                                // allowed if the repo was already approved via a manifest.
                                // In learning mode, blobs are allowed like manifests.
                                p.Logger.Add(proxylog.Entry{
                                        SkillID: sid,
                                        Method:  req.Method,
                                        Host:    host,
                                        Path:    urlPath,
                                        Status:  "denied",
                                        Detail:  "repository not approved: " + repo,
                                })
                                writeErrorResponseConn(clientConn, approval.StatusDenied, "container image "+repo)
                                return
                        }
                        // Manifest (or blob in learning mode): register pending and wait.
                        status := p.checkRefApproval(p.ImageApprovals, repo, skill, sourceIP, registry.MatchImageRef)
                        if status != approval.StatusApproved {
                                p.Logger.Add(proxylog.Entry{
                                        SkillID: sid,
                                        Method:  req.Method,
                                        Host:    host,
                                        Path:    urlPath,
                                        Status:  string(status),
                                        Detail:  "image not approved: " + repo,
                                })
                                writeErrorResponseConn(clientConn, status, "container image "+repo)
                                return
                        }
                }
                p.Logger.Add(proxylog.Entry{
                        SkillID:  sid,
                        Method:   req.Method,
                        Host:     host,
                        Path:     urlPath,
                        Status:   "allowed",
                        Detail:   repo,
                        Duration: time.Since(start).Milliseconds(),
                })
        } else {
                // Other registry traffic (auth, /v2/ ping, etc.): auto-approve.
                p.Logger.Add(proxylog.Entry{
                        SkillID:  sid,
                        Method:   req.Method,
                        Host:     host,
                        Path:     urlPath,
                        Status:   "allowed",
                        Detail:   "registry infra",
                        Duration: time.Since(start).Milliseconds(),
                })
        }

        // Forward to the real backend.
        req.URL.Scheme = "https"
        req.URL.Host = host + ":443"
        req.RequestURI = ""

        resp, err := p.Transport.RoundTrip(req)
        if err != nil {
                p.Logger.Add(proxylog.Entry{
                        SkillID:  sid,
                        Method:   req.Method,
                        Host:     host,
                        Path:     urlPath,
                        Status:   "error",
                        Detail:   err.Error(),
                        Duration: time.Since(start).Milliseconds(),
                })
                write502TLS(clientConn)
                return
        }
        defer resp.Body.Close()

        forwardTLS(clientConn, resp)
}
