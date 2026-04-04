package proxy

import (
        "bufio"
        "crypto/tls"
        "fmt"
        "io"
        "net"
        "net/http"
        "strings"

        proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
)

// ServeTransparentTLS accepts connections from the given listener and handles
// them as transparent TLS interceptions.
func (p *Proxy) ServeTransparentTLS(listener net.Listener) {
        for {
                conn, err := listener.Accept()
                if err != nil {
                        return
                }
                go p.HandleTransparentTLS(conn)
        }
}

// HandleTransparentTLS handles a raw TCP connection redirected by iptables
// for transparent HTTPS interception. It terminates TLS using SNI to
// determine the target host, then reads and forwards HTTP requests.
func (p *Proxy) HandleTransparentTLS(clientConn net.Conn) {
        defer clientConn.Close()

        if p.CA == nil {
                return
        }

        sourceIP := extractSourceIP(clientConn.RemoteAddr().String())
        if p.OnActivity != nil {
                p.OnActivity(sourceIP)
        }
        var sniHost string

        tlsConfig := newMITMTLSConfig(func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
                sniHost = info.ServerName
                if sniHost == "" {
                        return nil, fmt.Errorf("no SNI provided for transparent TLS")
                }
                return p.CA.GenerateHostCert(sniHost)
        })

        tlsConn := tls.Server(clientConn, tlsConfig)
        if err := tlsConn.Handshake(); err != nil {
                p.Logger.Add(proxylog.Entry{
                        Method: "TRANSPARENT",
                        Status: "error",
                        Detail: "TLS handshake failed: " + err.Error(),
                })
                return
        }
        defer tlsConn.Close()

        if sniHost == "" {
                return
        }

        // Read HTTP requests from the decrypted connection.
        reader := bufio.NewReader(tlsConn)
        for {
                req, err := http.ReadRequest(reader)
                if err != nil {
                        if err != io.EOF {
                                p.Logger.Add(proxylog.Entry{
                                        Method: "TRANSPARENT",
                                        Host:   sniHost,
                                        Status: "error",
                                        Detail: "read request: " + err.Error(),
                                })
                        }
                        return
                }

                p.handleTransparentTLSRequest(tlsConn, req, sniHost, sourceIP)
        }
}

// handleTransparentTLSRequest authenticates a request from a transparent TLS
// connection and delegates to the unified handleTLSRequest handler.
func (p *Proxy) handleTransparentTLSRequest(clientConn net.Conn, req *http.Request, host, sourceIP string) {
        // Authenticate (optional in transparent mode).
        skill, err := p.authenticateOptional(req)
        if err != nil {
                p.Logger.Add(proxylog.Entry{
                        Method: req.Method,
                        Host:   host,
                        Path:   req.URL.Path,
                        Status: "denied",
                        Detail: "auth failed: " + err.Error(),
                })
                msg := "Firewall4AI: Proxy authentication failed: " + err.Error()
                resp := &http.Response{
                        StatusCode: http.StatusProxyAuthRequired,
                        ProtoMajor: 1,
                        ProtoMinor: 1,
                        Header:     make(http.Header),
                        Body:       io.NopCloser(strings.NewReader(msg + "\n")),
                }
                resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
                resp.ContentLength = int64(len(msg) + 1)
                resp.Write(clientConn)
                return
        }

        p.handleTLSRequest(clientConn, req, host, host+":443", skill, sourceIP)
}
