// Package dns implements a DNS forwarder for the agent network.
// It resolves local agent hostnames directly and forwards all other
// queries to upstream DNS servers. Uses github.com/miekg/dns for
// protocol handling.
package dns

import (
	"log"
	"net"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
)

// HostResolver resolves local hostnames to IPs.
// Returns nil if the hostname is not local.
type HostResolver func(name string) net.IP

// Server is a DNS forwarder that resolves local names and forwards others.
type Server struct {
	ListenAddr   string   // e.g., "10.255.255.1:53" or ":53"
	Upstream     []string // upstream DNS servers (e.g., "1.1.1.1:53")
	HostResolver HostResolver

	mu    sync.RWMutex
	hosts map[string]net.IP // static local hostname -> IP mappings
}

// NewServer creates a new DNS server.
func NewServer(listenAddr string, upstream []string) *Server {
	// Ensure upstream addresses have port.
	for i, u := range upstream {
		if _, _, err := net.SplitHostPort(u); err != nil {
			upstream[i] = net.JoinHostPort(u, "53")
		}
	}
	return &Server{
		ListenAddr: listenAddr,
		Upstream:   upstream,
		hosts:      make(map[string]net.IP),
	}
}

// SetHost adds or updates a local hostname mapping.
func (s *Server) SetHost(name string, ip net.IP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Ensure FQDN format with trailing dot.
	if !strings.HasSuffix(name, ".") {
		name = name + "."
	}
	s.hosts[strings.ToLower(name)] = ip
}

// RemoveHost removes a local hostname mapping.
func (s *Server) RemoveHost(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !strings.HasSuffix(name, ".") {
		name = name + "."
	}
	delete(s.hosts, strings.ToLower(name))
}

// resolveLocal checks if a query name matches a local hostname.
func (s *Server) resolveLocal(name string) net.IP {
	s.mu.RLock()
	ip, ok := s.hosts[strings.ToLower(name)]
	s.mu.RUnlock()
	if ok {
		return ip
	}
	if s.HostResolver != nil {
		return s.HostResolver(name)
	}
	return nil
}

// ListenAndServe starts the DNS server on UDP.
func (s *Server) ListenAndServe() error {
	mux := mdns.NewServeMux()
	mux.HandleFunc(".", s.handleRequest)

	server := &mdns.Server{
		Addr:    s.ListenAddr,
		Net:     "udp",
		Handler: mux,
	}

	log.Printf("DNS server listening on %s (upstream: %v)", s.ListenAddr, s.Upstream)
	return server.ListenAndServe()
}

func (s *Server) handleRequest(w mdns.ResponseWriter, r *mdns.Msg) {
	if len(r.Question) == 0 {
		return
	}

	q := r.Question[0]

	// Try local resolution for A queries.
	if q.Qtype == mdns.TypeA {
		if ip := s.resolveLocal(q.Name); ip != nil {
			resp := new(mdns.Msg)
			resp.SetReply(r)
			resp.Authoritative = true
			resp.Answer = append(resp.Answer, &mdns.A{
				Hdr: mdns.RR_Header{
					Name:   q.Name,
					Rrtype: mdns.TypeA,
					Class:  mdns.ClassINET,
					Ttl:    60,
				},
				A: ip.To4(),
			})
			w.WriteMsg(resp)
			return
		}
	}

	// Forward to upstream.
	resp := s.forwardQuery(r)
	if resp != nil {
		resp.Id = r.Id
		w.WriteMsg(resp)
	} else {
		// Return SERVFAIL if no upstream responded.
		fail := new(mdns.Msg)
		fail.SetRcode(r, mdns.RcodeServerFailure)
		w.WriteMsg(fail)
	}
}

func (s *Server) forwardQuery(r *mdns.Msg) *mdns.Msg {
	c := &mdns.Client{
		Timeout: 3 * time.Second,
	}
	for _, upstream := range s.Upstream {
		resp, _, err := c.Exchange(r, upstream)
		if err != nil {
			continue
		}
		return resp
	}
	return nil
}
