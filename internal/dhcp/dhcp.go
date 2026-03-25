// Package dhcp implements a DHCP server for the agent network.
// It assigns IP addresses from a configurable range, supports permanent
// leases by MAC address, and provides PXE boot options for registered agents.
// Uses github.com/insomniacslk/dhcp for protocol handling.
package dhcp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/insomniacslk/dhcp/iana"
)

// Lease represents a DHCP lease.
type Lease struct {
	MAC      string    `json:"mac"`
	IP       string    `json:"ip"`
	Hostname string    `json:"hostname"`
	Expiry   time.Time `json:"expiry"` // zero value = infinite
}

// PXEInfo contains PXE boot parameters for an agent.
type PXEInfo struct {
	TFTPServer string // TFTP server IP (e.g., "10.255.255.1")
	Bootfile   string // Boot filename (e.g., "undionly.kpxe")
	IPXEScript string // iPXE script URL for chainloading
}

// PXE client architecture types re-exported from iana for backward compat.
const (
	ArchBIOSx86    = uint16(iana.INTEL_X86PC)
	ArchEFIx86     = uint16(iana.EFI_IA32)
	ArchEFIx86_64  = uint16(iana.EFI_X86_64)
	ArchEFIBC      = uint16(iana.EFI_BC)
	ArchEFIx86_64v = uint16(iana.EFI_ARM32) // mapped for backward compat (was 10)
)

// PXEProvider is called to get PXE boot info for a given MAC address.
// Returns nil if the MAC is not a registered agent.
type PXEProvider func(mac string, clientArch uint16, isIPXE bool) *PXEInfo

// Server is a DHCP server that serves the agent network.
type Server struct {
	ServerIP    net.IP // e.g., 10.255.255.1
	SubnetMask  net.IPMask
	RangeStart  net.IP // e.g., 10.255.255.10
	RangeEnd    net.IP // e.g., 10.255.255.254
	Gateway     net.IP
	DNS         []net.IP
	Interface   string // e.g., "eth1"
	PXEProvider PXEProvider

	mu     sync.RWMutex
	leases map[string]*Lease // MAC -> Lease
	ipUsed map[string]string // IP -> MAC

	// For loading/saving leases to state.
	OnLeaseChange func(leases []Lease)
}

// NewServer creates a new DHCP server.
func NewServer(serverIP, rangeStart, rangeEnd, gateway net.IP, mask net.IPMask, dns []net.IP, iface string) *Server {
	return &Server{
		ServerIP:   serverIP,
		SubnetMask: mask,
		RangeStart: rangeStart,
		RangeEnd:   rangeEnd,
		Gateway:    gateway,
		DNS:        dns,
		Interface:  iface,
		leases:     make(map[string]*Lease),
		ipUsed:     make(map[string]string),
	}
}

// LoadLeases restores leases from persisted state.
func (s *Server) LoadLeases(leases []Lease) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range leases {
		lease := l
		s.leases[l.MAC] = &lease
		s.ipUsed[l.IP] = l.MAC
	}
}

// ExportLeases returns all current leases for persistence.
func (s *Server) ExportLeases() []Lease {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Lease, 0, len(s.leases))
	for _, l := range s.leases {
		out = append(out, *l)
	}
	return out
}

// SetStaticLease assigns a fixed IP to a MAC address.
func (s *Server) SetStaticLease(mac, ip, hostname string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Remove old lease for this MAC if it had a different IP.
	if old, ok := s.leases[mac]; ok && old.IP != ip {
		delete(s.ipUsed, old.IP)
	}
	// Remove any existing lease for this IP if it was assigned to a different MAC.
	if oldMAC, ok := s.ipUsed[ip]; ok && oldMAC != mac {
		delete(s.leases, oldMAC)
	}

	s.leases[mac] = &Lease{
		MAC:      mac,
		IP:       ip,
		Hostname: hostname,
	}
	s.ipUsed[ip] = mac
}

// RemoveLease removes a lease by MAC address.
func (s *Server) RemoveLease(mac string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := s.leases[mac]; ok {
		delete(s.ipUsed, l.IP)
		delete(s.leases, mac)
	}
}

// GetLeaseByMAC returns the lease for a given MAC address.
func (s *Server) GetLeaseByMAC(mac string) *Lease {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if l, ok := s.leases[mac]; ok {
		cp := *l
		return &cp
	}
	return nil
}

// ListenAndServe starts the DHCP server on UDP port 67.
func (s *Server) ListenAndServe() error {
	laddr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: 67,
	}

	srv, err := server4.NewServer(s.Interface, laddr, s.handler)
	if err != nil {
		return fmt.Errorf("dhcp server: %w", err)
	}

	log.Printf("DHCP server listening on :67 (interface %s)", s.Interface)
	return srv.Serve()
}

func (s *Server) handler(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
	mac := m.ClientHWAddr.String()

	// Detect PXE client architecture.
	var clientArch uint16
	if archs := m.ClientArch(); len(archs) > 0 {
		clientArch = uint16(archs[0])
	}

	// Detect iPXE client via user class or vendor class.
	isIPXE := false
	for _, uc := range m.UserClass() {
		if uc == "iPXE" {
			isIPXE = true
			break
		}
	}
	if !isIPXE {
		vc := m.ClassIdentifier()
		if len(vc) >= 4 && vc[:4] == "iPXE" {
			isIPXE = true
		}
	}

	hostname := m.HostName()

	switch m.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		s.handleDiscover(conn, peer, m, mac, hostname, clientArch, isIPXE)
	case dhcpv4.MessageTypeRequest:
		s.handleRequest(conn, peer, m, mac, hostname, clientArch, isIPXE)
	case dhcpv4.MessageTypeRelease:
		log.Printf("DHCP RELEASE from %s", mac)
	case dhcpv4.MessageTypeInform:
		s.handleInform(conn, peer, m, mac)
	}
}

func (s *Server) handleDiscover(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4, mac, hostname string, clientArch uint16, isIPXE bool) {
	ip := s.allocateIP(mac, hostname)
	if ip == nil {
		log.Printf("DHCP DISCOVER from %s: no IP available", mac)
		return
	}
	log.Printf("DHCP DISCOVER from %s -> offering %s", mac, ip)

	resp := s.buildResponse(m, ip, dhcpv4.MessageTypeOffer, mac, clientArch, isIPXE)
	s.sendResponse(conn, peer, resp)
}

func (s *Server) handleRequest(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4, mac, hostname string, clientArch uint16, isIPXE bool) {
	ip := s.allocateIP(mac, hostname)
	if ip == nil {
		log.Printf("DHCP REQUEST from %s: no IP available, sending NAK", mac)
		resp := s.buildNak(m)
		s.sendResponse(conn, peer, resp)
		return
	}

	requestedIP := m.RequestedIPAddress()

	// If the client requested a specific IP, verify it matches.
	if requestedIP != nil && !requestedIP.IsUnspecified() && !requestedIP.Equal(ip) {
		s.mu.RLock()
		lease, exists := s.leases[mac]
		s.mu.RUnlock()
		if exists && net.ParseIP(lease.IP).Equal(requestedIP) {
			ip = requestedIP
		} else {
			log.Printf("DHCP REQUEST from %s for %s, but we assigned %s", mac, requestedIP, ip)
			if s.isInRange(requestedIP) {
				s.mu.RLock()
				occupant, taken := s.ipUsed[requestedIP.String()]
				s.mu.RUnlock()
				if !taken || occupant == mac {
					ip = requestedIP
				}
			}
		}
	}

	// Commit the lease.
	s.mu.Lock()
	if old, ok := s.leases[mac]; ok && old.IP != ip.String() {
		delete(s.ipUsed, old.IP)
	}
	s.leases[mac] = &Lease{
		MAC:      mac,
		IP:       ip.String(),
		Hostname: hostname,
	}
	s.ipUsed[ip.String()] = mac
	s.mu.Unlock()

	log.Printf("DHCP ACK to %s -> %s", mac, ip)

	if s.OnLeaseChange != nil {
		s.OnLeaseChange(s.ExportLeases())
	}

	resp := s.buildResponse(m, ip, dhcpv4.MessageTypeAck, mac, clientArch, isIPXE)
	s.sendResponse(conn, peer, resp)
}

func (s *Server) handleInform(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4, mac string) {
	log.Printf("DHCP INFORM from %s (%s)", mac, m.ClientIPAddr)
	resp := s.buildResponse(m, m.ClientIPAddr, dhcpv4.MessageTypeAck, mac, 0, false)
	s.sendResponse(conn, peer, resp)
}

func (s *Server) buildResponse(req *dhcpv4.DHCPv4, clientIP net.IP, msgType dhcpv4.MessageType, mac string, clientArch uint16, isIPXE bool) *dhcpv4.DHCPv4 {
	// Compute broadcast address.
	broadcast := make(net.IP, 4)
	serverIP4 := s.ServerIP.To4()
	for i := 0; i < 4; i++ {
		broadcast[i] = serverIP4[i] | ^s.SubnetMask[i]
	}

	modifiers := []dhcpv4.Modifier{
		dhcpv4.WithMessageType(msgType),
		dhcpv4.WithYourIP(clientIP),
		dhcpv4.WithServerIP(s.ServerIP),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(s.ServerIP)),
		dhcpv4.WithNetmask(s.SubnetMask),
		dhcpv4.WithRouter(s.Gateway),
		dhcpv4.WithDNS(s.DNS...),
		dhcpv4.WithOption(dhcpv4.OptBroadcastAddress(broadcast)),
		// Infinite lease time (0xFFFFFFFF).
		dhcpv4.WithLeaseTime(0xFFFFFFFF),
		// Renewal T1: 1 year.
		dhcpv4.WithOption(dhcpv4.OptRenewTimeValue(365 * 24 * time.Hour)),
		// Rebinding T2: ~1.5 years.
		dhcpv4.WithOption(dhcpv4.OptRebindingTimeValue(547 * 24 * time.Hour)),
	}

	// PXE boot options.
	var pxeInfo *PXEInfo
	if s.PXEProvider != nil {
		pxeInfo = s.PXEProvider(mac, clientArch, isIPXE)
	}
	if pxeInfo != nil {
		if isIPXE && pxeInfo.IPXEScript != "" {
			modifiers = append(modifiers, dhcpv4.WithOption(dhcpv4.OptBootFileName(pxeInfo.IPXEScript)))
		} else if pxeInfo.Bootfile != "" {
			modifiers = append(modifiers,
				dhcpv4.WithOption(dhcpv4.OptTFTPServerName(pxeInfo.TFTPServer)),
				dhcpv4.WithOption(dhcpv4.OptBootFileName(pxeInfo.Bootfile)),
			)
		}
		// Set siaddr (next-server) for PXE.
		if !isIPXE && pxeInfo.TFTPServer != "" {
			modifiers = append(modifiers, dhcpv4.WithServerIP(net.ParseIP(pxeInfo.TFTPServer)))
		}
		// Set boot file in the header field for legacy PXE.
		if !isIPXE && pxeInfo.Bootfile != "" {
			modifiers = append(modifiers, func(d *dhcpv4.DHCPv4) {
				d.BootFileName = pxeInfo.Bootfile
			})
		}
	}

	resp, err := dhcpv4.NewReplyFromRequest(req, modifiers...)
	if err != nil {
		log.Printf("DHCP: failed to build response: %v", err)
		return nil
	}
	return resp
}

func (s *Server) buildNak(req *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
	resp, err := dhcpv4.NewReplyFromRequest(req,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeNak),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(s.ServerIP)),
	)
	if err != nil {
		log.Printf("DHCP: failed to build NAK: %v", err)
		return nil
	}
	return resp
}

func (s *Server) sendResponse(conn net.PacketConn, peer net.Addr, resp *dhcpv4.DHCPv4) {
	if resp == nil {
		return
	}
	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: 68}

	// Use peer address if it's a unicast address.
	if peer != nil {
		if udpAddr, ok := peer.(*net.UDPAddr); ok && !udpAddr.IP.Equal(net.IPv4zero) {
			dst = &net.UDPAddr{IP: net.IPv4bcast, Port: 68}
		}
	}

	if _, err := conn.WriteTo(resp.ToBytes(), dst); err != nil {
		log.Printf("DHCP send error: %v", err)
	}
}

func (s *Server) allocateIP(mac, hostname string) net.IP {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Normalize MAC for lookup.
	mac = normMAC(mac)

	// Check existing lease.
	if lease, ok := s.leases[mac]; ok {
		return net.ParseIP(lease.IP)
	}

	// Allocate new IP from range.
	start := ipToUint32(s.RangeStart)
	end := ipToUint32(s.RangeEnd)

	for i := start; i <= end; i++ {
		candidate := uint32ToIP(i)
		if _, used := s.ipUsed[candidate.String()]; !used {
			s.leases[mac] = &Lease{
				MAC:      mac,
				IP:       candidate.String(),
				Hostname: hostname,
			}
			s.ipUsed[candidate.String()] = mac
			return candidate
		}
	}
	return nil
}

func (s *Server) isInRange(ip net.IP) bool {
	v := ipToUint32(ip)
	return v >= ipToUint32(s.RangeStart) && v <= ipToUint32(s.RangeEnd)
}

// normMAC normalizes a MAC address string to lowercase colon-separated format.
func normMAC(mac string) string {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return strings.ToLower(mac)
	}
	return hw.String()
}

func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}
