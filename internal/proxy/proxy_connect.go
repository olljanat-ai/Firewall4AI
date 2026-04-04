package proxy

import (
        "bufio"
        "crypto/tls"
        "fmt"
        "io"
        "net"
        "net/http"
        "strings"
        "time"

        "github.com/olljanat-ai/firewall4ai/internal/approval"
        "github.com/olljanat-ai/firewall4ai/internal/auth"
        "github.com/olljanat-ai/firewall4ai/internal/library"
        proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
        "github.com/olljanat-ai/firewall4ai/internal/registry"
)

// handleConnect handles HTTPS CONNECT tunnel requests, with optional TLS MITM
// inspection when a CA is configured.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        targetHost := r.Host
        host := targetHost
        if h, _, err := net.SplitHostPort(host); err == nil {
                host = h
        }
        sourceIP := extractSourceIP(r.RemoteAddr)
        if p.OnActivity != nil {
                p.OnActivity(sourceIP)
        }

        skill, err := p.authenticateOptional(r)
        if err != nil {
                p.Logger.Add(proxylog.Entry{
                        Method: "CONNECT",
                        Host:   host,
                        Status: "denied",
                        Detail: "auth failed: " + err.Error(),
                })
                http.Error(w, "Proxy authentication failed: "+err.Error(), http.StatusProxyAuthRequired)
                return
        }

        // For CONNECT with MITM, auto-approve hosts that belong to configured
        // infrastructure (registries, Helm repos, package repos, code libraries)
        // since the real access control happens per-item inside the tunnel.
        // For other hosts, check host-level approval. Per-request path checks
        // happen in handleMITMRequest.
        // For blind tunnels (no MITM), use host-only check since we can't inspect paths.
        var status approval.Status
        if p.CA != nil && p.isConfiguredRepoHost(host) {
                status = approval.StatusApproved
        } else if p.CA != nil {
                status = p.checkHostApproval(host, skill, sourceIP)
        } else {
                status = p.checkApproval(host, "", skill, sourceIP)
        }
        if status != approval.StatusApproved {
                p.Logger.Add(proxylog.Entry{
                        SkillID: getSkillID(skill),
                        Method:  "CONNECT",
                        Host:    host,
                        Status:  string(status),
                        Detail:  "host not approved",
                })
                writeErrorResponse(w, status, host)
                return
        }

        // Hijack the client connection.
        hijacker, ok := w.(http.Hijacker)
        if !ok {
                http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
                return
        }
        clientConn, _, err := hijacker.Hijack()
        if err != nil {
                http.Error(w, err.Error(), http.StatusInternalServerError)
                return
        }

        // Send 200 OK to tell the client the tunnel is established.
        clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

        // If we have a CA, perform TLS MITM inspection.
        if p.CA != nil {
                p.handleMITM(clientConn, host, targetHost, skill, sourceIP, start)
                return
        }

        // Fallback: blind tunnel (no inspection).
        p.handleBlindTunnel(clientConn, host, targetHost, skill, start)
}

// newMITMTLSConfig returns a shared TLS configuration for MITM interception.
// The getCertFunc callback is invoked during the TLS handshake to provide the
// appropriate certificate for the connecting client.
func newMITMTLSConfig(getCertFunc func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
        return &tls.Config{
                GetCertificate: getCertFunc,

                // Allow also TLS 1.0 and 1.1 (Go 1.22 set minimum to TLS 1.2)
                MinVersion: tls.VersionTLS10,
                MaxVersion: tls.VersionTLS13,

                // Disable experimental X25519Kyber768Draft00 (Go 1.23 enables it by default)
                // and disable X25519MLKEM768 (Go 1.24 enables it by default) by listing curve list from:
                // https://github.com/golang/go/blob/go1.23.5/src/crypto/tls/defaults.go#L20
                CurvePreferences: []tls.CurveID{
                        tls.X25519,
                        tls.CurveP256,
                        tls.CurveP384,
                        tls.CurveP521,
                },

                // Allow all ciphers, including those marked "insecure" by Go
                CipherSuites: func() []uint16 {
                        all := append([]*tls.CipherSuite{}, tls.CipherSuites()...)
                        all = append(all, tls.InsecureCipherSuites()...)
                        var ids []uint16
                        for _, cs := range all {
                                ids = append(ids, cs.ID)
                        }
                        return ids
                }(),

                // Force HTTP/1.1 to avoid issues with HTTP/2 connection.
                NextProtos: []string{"http/1.1"},
        }
}

// handleMITM performs TLS MITM: terminates the client TLS with a generated cert,
// reads the inner HTTP requests, applies auth/approval/credential injection,
// and forwards them to the real target over a new TLS connection.
func (p *Proxy) handleMITM(clientConn net.Conn, host, targetAddr string, skill *auth.Skill, sourceIP string, start time.Time) {
        defer clientConn.Close()

        sid := getSkillID(skill)

        // Present a CA-signed certificate for this host to the client.
        hostCert, err := p.CA.GenerateHostCert(host)
        if err != nil {
                p.Logger.Add(proxylog.Entry{
                        SkillID: sid,
                        Method:  "CONNECT",
                        Host:    host,
                        Status:  "error",
                        Detail:  "generate host cert: " + err.Error(),
                })
                return
        }
        tlsConfig := newMITMTLSConfig(func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
                if info.ServerName != "" && info.ServerName != host {
                        return p.CA.GenerateHostCert(info.ServerName)
                }
                return hostCert, nil
        })

        tlsClientConn := tls.Server(clientConn, tlsConfig)
        if err := tlsClientConn.Handshake(); err != nil {
                p.Logger.Add(proxylog.Entry{
                        SkillID: sid,
                        Method:  "CONNECT",
                        Host:    host,
                        Status:  "error",
                        Detail:  "MITM TLS handshake failed: " + err.Error(),
                })
                return
        }
        defer tlsClientConn.Close()

        p.Logger.Add(proxylog.Entry{
                SkillID:  sid,
                Method:   "CONNECT",
                Host:     host,
                Status:   "allowed",
                Detail:   "TLS MITM tunnel established",
                Duration: time.Since(start).Milliseconds(),
        })

        // Read HTTP requests from the decrypted client connection.
        reader := bufio.NewReader(tlsClientConn)
        for {
                req, err := http.ReadRequest(reader)
                if err != nil {
                        if err != io.EOF {
                                p.Logger.Add(proxylog.Entry{
                                        SkillID: sid,
                                        Method:  "CONNECT",
                                        Host:    host,
                                        Status:  "error",
                                        Detail:  "read request: " + err.Error(),
                                })
                        }
                        return
                }

                // Ensure targetAddr has a port for upstream forwarding.
                upstreamAddr := targetAddr
                if !strings.Contains(upstreamAddr, ":") {
                        upstreamAddr += ":443"
                }
                p.handleTLSRequest(tlsClientConn, req, host, upstreamAddr, skill, sourceIP)
        }
}

// handleTLSRequest processes a single HTTP request from either a MITM'd
// explicit CONNECT tunnel or a transparent TLS interception. The targetAddr
// is used as the upstream host:port for forwarding (e.g. "example.com:443").
func (p *Proxy) handleTLSRequest(clientConn net.Conn, req *http.Request, host, targetAddr string, skill *auth.Skill, sourceIP string) {
        start := time.Now()
        sid := getSkillID(skill)

        // Remove proxy auth header if client re-sent it inside the tunnel.
        req.Header.Del(AuthHeader)

        // Check if this is a container registry request.
        if reg := registry.RegistryForHost(host, p.Registries); reg != nil {
                p.handleRegistryTLSRequest(clientConn, req, host, sourceIP, skill, reg, start)
                return
        }

        // Check if this is a Helm chart repository request.
        if repo := library.RepoForHost(host, p.HelmRepos); repo != nil {
                p.handleHelmChartRepoTLSRequest(clientConn, req, host, sourceIP, skill, repo, start)
                return
        }

        // Check if this is a package repository request.
        if repo := library.RepoForHost(host, p.OSPackages); repo != nil {
                p.handlePackageRepoTLSRequest(clientConn, req, host, sourceIP, skill, repo, true, start)
                return
        }
        if repo := library.RepoForHost(host, p.CodeLibraries); repo != nil {
                p.handlePackageRepoTLSRequest(clientConn, req, host, sourceIP, skill, repo, false, start)
                return
        }

        // Check path-level approval for this specific request.
        status := p.checkApproval(host, req.URL.Path, skill, sourceIP)
        if status != approval.StatusApproved {
                resource := host + req.URL.Path
                p.Logger.Add(proxylog.Entry{
                        SkillID: sid,
                        Method:  req.Method,
                        Host:    host,
                        Path:    req.URL.Path,
                        Status:  string(status),
                        Detail:  "path not approved",
                })
                writeErrorResponseConn(clientConn, status, resource)
                return
        }

        // Check logging mode.
        logMode := p.getLoggingMode(host, req.URL.Path, skill, sourceIP)
        var fullDetail *proxylog.FullDetail
        if logMode == approval.LoggingModeFull {
                reqBody := captureRequestBody(req)
                fullDetail = &proxylog.FullDetail{
                        RequestHeaders: req.Header.Clone(),
                        RequestBody:    reqBody,
                }
        }

        // Set the URL for forwarding.
        req.URL.Scheme = "https"
        req.URL.Host = targetAddr
        req.RequestURI = ""

        // Inject credentials for HTTPS requests.
        p.Credentials.InjectForRequest(req, sourceIP)
        if fullDetail != nil {
                fullDetail.InjectedHeaders = captureInjectedHeaders(fullDetail.RequestHeaders, req.Header)
        }

        resp, err := p.Transport.RoundTrip(req)
        if err != nil {
                p.Logger.Add(proxylog.Entry{
                        SkillID:    sid,
                        Method:     req.Method,
                        Host:       host,
                        Path:       req.URL.Path,
                        Status:     "error",
                        Detail:     err.Error(),
                        Duration:   time.Since(start).Milliseconds(),
                        HasFullLog: fullDetail != nil,
                        FullDetail: fullDetail,
                })
                write502TLS(clientConn)
                return
        }
        defer resp.Body.Close()

        if fullDetail != nil {
                fullDetail.ResponseHeaders = resp.Header.Clone()
                fullDetail.ResponseStatus = resp.StatusCode
                fullDetail.ResponseBody = captureResponseBody(resp)
        }

        p.Logger.Add(proxylog.Entry{
                SkillID:    sid,
                Method:     req.Method,
                Host:       host,
                Path:       req.URL.Path,
                Status:     "allowed",
                Detail:     fmt.Sprintf("%d %s", resp.StatusCode, resp.Status),
                Duration:   time.Since(start).Milliseconds(),
                HasFullLog: fullDetail != nil,
                FullDetail: fullDetail,
        })

        forwardTLS(clientConn, resp)
}

// handleBlindTunnel is the fallback when no CA is configured: just pipe bytes.
func (p *Proxy) handleBlindTunnel(clientConn net.Conn, host, targetAddr string, skill *auth.Skill, start time.Time) {
        if !strings.Contains(targetAddr, ":") {
                targetAddr += ":443"
        }

        sid := getSkillID(skill)

        targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
        if err != nil {
                p.Logger.Add(proxylog.Entry{
                        SkillID:  sid,
                        Method:   "CONNECT",
                        Host:     host,
                        Status:   "error",
                        Detail:   err.Error(),
                        Duration: time.Since(start).Milliseconds(),
                })
                clientConn.Close()
                return
        }

        p.Logger.Add(proxylog.Entry{
                SkillID:  sid,
                Method:   "CONNECT",
                Host:     host,
                Status:   "allowed",
                Detail:   "blind tunnel (no TLS inspection)",
                Duration: time.Since(start).Milliseconds(),
        })

        // Bidirectional copy.
        go func() {
                defer targetConn.Close()
                defer clientConn.Close()
                io.Copy(targetConn, clientConn)
        }()
        go func() {
                defer targetConn.Close()
                defer clientConn.Close()
                io.Copy(clientConn, targetConn)
        }()
}
