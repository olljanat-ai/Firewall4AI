// Package dns implements a simple DNS forwarder for the agent network.
// It resolves local agent hostnames directly and forwards all other
// queries to upstream DNS servers.
package dns

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// HostResolver resolves local hostnames to IPs.
// Returns nil if the hostname is not local.
type HostResolver func(name string) net.IP

// Server is a DNS forwarder that resolves local names and forwards others.
type Server struct {
	ListenAddr   string // e.g., "10.255.255.1:53" or ":53"
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
	conn, err := net.ListenPacket("udp", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("dns listen %s: %w", s.ListenAddr, err)
	}
	defer conn.Close()

	log.Printf("DNS server listening on %s (upstream: %v)", s.ListenAddr, s.Upstream)

	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("DNS read error: %v", err)
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go s.handleQuery(conn, pkt, addr)
	}
}

func (s *Server) handleQuery(conn net.PacketConn, pkt []byte, addr net.Addr) {
	if len(pkt) < 12 {
		return
	}

	// Parse query name and type.
	name, qtype, offset := parseQuestion(pkt)
	if name == "" || offset == 0 {
		return
	}

	// Try local resolution for A queries.
	if qtype == 1 { // A record
		if ip := s.resolveLocal(name); ip != nil {
			resp := buildAResponse(pkt, name, ip, offset)
			conn.WriteTo(resp, addr)
			return
		}
	}

	// Forward to upstream.
	resp := s.forwardQuery(pkt)
	if resp != nil {
		conn.WriteTo(resp, addr)
	}
}

func (s *Server) forwardQuery(pkt []byte) []byte {
	for _, upstream := range s.Upstream {
		conn, err := net.DialTimeout("udp", upstream, 3*time.Second)
		if err != nil {
			continue
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write(pkt); err != nil {
			conn.Close()
			continue
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			continue
		}
		return buf[:n]
	}
	// Return SERVFAIL if no upstream responded.
	return buildServFail(pkt)
}

// parseQuestion extracts the query name and type from a DNS packet.
// Returns the FQDN (with trailing dot), query type, and byte offset after the question.
func parseQuestion(pkt []byte) (string, uint16, int) {
	if len(pkt) < 12 {
		return "", 0, 0
	}
	qdcount := binary.BigEndian.Uint16(pkt[4:6])
	if qdcount == 0 {
		return "", 0, 0
	}

	offset := 12
	var labels []string
	for offset < len(pkt) {
		length := int(pkt[offset])
		if length == 0 {
			offset++
			break
		}
		if length&0xC0 == 0xC0 {
			// Compressed name — shouldn't happen in queries but handle it.
			offset += 2
			break
		}
		offset++
		if offset+length > len(pkt) {
			return "", 0, 0
		}
		labels = append(labels, string(pkt[offset:offset+length]))
		offset += length
	}

	if offset+4 > len(pkt) {
		return "", 0, 0
	}

	qtype := binary.BigEndian.Uint16(pkt[offset : offset+2])
	offset += 4 // qtype + qclass

	name := strings.Join(labels, ".") + "."
	return name, qtype, offset
}

// buildAResponse constructs a DNS response with an A record.
func buildAResponse(query []byte, name string, ip net.IP, questionEnd int) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)

	// Set response flags.
	resp[2] = 0x81 // QR=1, RD=1
	resp[3] = 0x80 // RA=1

	// Set ANCOUNT=1.
	binary.BigEndian.PutUint16(resp[6:8], 1)
	// Clear NSCOUNT and ARCOUNT.
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)

	// Truncate to question section.
	resp = resp[:questionEnd]

	// Add answer: pointer to name in question section.
	resp = append(resp, 0xC0, 0x0C) // Name pointer to offset 12.
	// Type A.
	resp = append(resp, 0x00, 0x01)
	// Class IN.
	resp = append(resp, 0x00, 0x01)
	// TTL: 60 seconds.
	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, 60)
	resp = append(resp, ttl...)
	// RDLENGTH: 4.
	resp = append(resp, 0x00, 0x04)
	// RDATA: IP address.
	resp = append(resp, ip.To4()...)

	return resp
}

// buildServFail constructs a SERVFAIL response.
func buildServFail(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	resp := make([]byte, len(query))
	copy(resp, query)
	resp[2] = 0x81 // QR=1, RD=1
	resp[3] = 0x82 // RA=1, RCODE=2 (SERVFAIL)
	// Clear answer/authority/additional counts.
	binary.BigEndian.PutUint16(resp[6:8], 0)
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	return resp
}
