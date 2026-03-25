// Package dhcp implements a DHCP server for the agent network.
// It assigns IP addresses from a configurable range, supports permanent
// leases by MAC address, and provides PXE boot options for registered agents.
package dhcp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// MessageType represents DHCP message types (option 53).
type MessageType byte

const (
	Discover MessageType = 1
	Offer    MessageType = 2
	Request  MessageType = 3
	Decline  MessageType = 4
	Ack      MessageType = 5
	Nak      MessageType = 6
	Release  MessageType = 7
	Inform   MessageType = 8
)

// DHCP option codes.
const (
	OptSubnetMask       byte = 1
	OptRouter           byte = 3
	OptDNS              byte = 6
	OptHostname         byte = 12
	OptDomainName       byte = 15
	OptBroadcast        byte = 28
	OptRequestedIP      byte = 50
	OptLeaseTime        byte = 51
	OptMessageType      byte = 53
	OptServerID         byte = 54
	OptParamRequestList byte = 55
	OptRenewalTime      byte = 58
	OptRebindingTime    byte = 59
	OptVendorClassID    byte = 60
	OptTFTPServer       byte = 66
	OptBootfileName     byte = 67
	OptUserClass        byte = 77
	OptClientArch       byte = 93
	OptEnd              byte = 255
)

// PXE client architecture types.
const (
	ArchBIOSx86    uint16 = 0
	ArchEFIx86     uint16 = 6
	ArchEFIx86_64  uint16 = 7
	ArchEFIBC      uint16 = 9
	ArchEFIx86_64v uint16 = 10
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
	conn, err := net.ListenPacket("udp4", ":67")
	if err != nil {
		return fmt.Errorf("listen udp:67: %w", err)
	}
	defer conn.Close()

	// Bind to specific interface if possible.
	if s.Interface != "" {
		if rawConn, err := conn.(*net.UDPConn).SyscallConn(); err == nil {
			rawConn.Control(func(fd uintptr) {
				bindToDevice(fd, s.Interface)
			})
		}
	}

	log.Printf("DHCP server listening on :67 (interface %s)", s.Interface)

	buf := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("DHCP read error: %v", err)
			continue
		}
		if n < 240 {
			continue // Too small for a DHCP packet
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go s.handlePacket(conn, pkt, addr)
	}
}

func (s *Server) handlePacket(conn net.PacketConn, pkt []byte, addr net.Addr) {
	// Parse DHCP packet.
	if pkt[0] != 1 { // op: 1 = BOOTREQUEST
		return
	}

	hlen := int(pkt[2])
	if hlen > 16 {
		hlen = 16
	}
	mac := net.HardwareAddr(pkt[28 : 28+hlen]).String()
	xid := pkt[4:8]

	// Parse options.
	opts := parseOptions(pkt)
	msgType := MessageType(0)
	if v, ok := opts[OptMessageType]; ok && len(v) == 1 {
		msgType = MessageType(v[0])
	}

	var requestedIP net.IP
	if v, ok := opts[OptRequestedIP]; ok && len(v) == 4 {
		requestedIP = net.IP(v)
	}

	var hostname string
	if v, ok := opts[OptHostname]; ok {
		hostname = string(v)
	}

	// Detect PXE client.
	var clientArch uint16
	if v, ok := opts[OptClientArch]; ok && len(v) >= 2 {
		clientArch = binary.BigEndian.Uint16(v[:2])
	}

	isIPXE := false
	if v, ok := opts[OptUserClass]; ok && string(v) == "iPXE" {
		isIPXE = true
	}
	// Also check vendor class.
	if v, ok := opts[OptVendorClassID]; ok {
		vc := string(v)
		if len(vc) >= 4 && vc[:4] == "iPXE" {
			isIPXE = true
		}
	}

	switch msgType {
	case Discover:
		s.handleDiscover(conn, pkt, mac, xid, hostname, clientArch, isIPXE)
	case Request:
		s.handleRequest(conn, pkt, mac, xid, requestedIP, hostname, clientArch, isIPXE)
	case Release:
		// For permanent leases we don't actually release, just log.
		log.Printf("DHCP RELEASE from %s", mac)
	case Inform:
		s.handleInform(conn, pkt, mac, xid)
	}
}

func (s *Server) handleDiscover(conn net.PacketConn, pkt []byte, mac string, xid []byte, hostname string, clientArch uint16, isIPXE bool) {
	ip := s.allocateIP(mac, hostname)
	if ip == nil {
		log.Printf("DHCP DISCOVER from %s: no IP available", mac)
		return
	}
	log.Printf("DHCP DISCOVER from %s -> offering %s", mac, ip)

	resp := s.buildResponse(pkt, xid, ip, Offer, mac, clientArch, isIPXE)
	s.sendResponse(conn, resp)
}

func (s *Server) handleRequest(conn net.PacketConn, pkt []byte, mac string, xid []byte, requestedIP net.IP, hostname string, clientArch uint16, isIPXE bool) {
	ip := s.allocateIP(mac, hostname)
	if ip == nil {
		log.Printf("DHCP REQUEST from %s: no IP available, sending NAK", mac)
		resp := s.buildNak(pkt, xid, mac)
		s.sendResponse(conn, resp)
		return
	}

	// If the client requested a specific IP, verify it matches.
	if requestedIP != nil && !requestedIP.Equal(ip) {
		// Check if the requested IP is the one we have leased.
		s.mu.RLock()
		lease, exists := s.leases[mac]
		s.mu.RUnlock()
		if exists && net.ParseIP(lease.IP).Equal(requestedIP) {
			ip = requestedIP
		} else {
			log.Printf("DHCP REQUEST from %s for %s, but we assigned %s", mac, requestedIP, ip)
			// Allow the requested IP if it's in our range and available.
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
	// Remove old IP mapping if MAC had a different IP.
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

	resp := s.buildResponse(pkt, xid, ip, Ack, mac, clientArch, isIPXE)
	s.sendResponse(conn, resp)
}

func (s *Server) handleInform(conn net.PacketConn, pkt []byte, mac string, xid []byte) {
	// Client already has IP, just wants config.
	ciaddr := net.IP(pkt[12:16])
	log.Printf("DHCP INFORM from %s (%s)", mac, ciaddr)
	resp := s.buildResponse(pkt, xid, ciaddr, Ack, mac, 0, false)
	s.sendResponse(conn, resp)
}

func (s *Server) allocateIP(mac, hostname string) net.IP {
	s.mu.Lock()
	defer s.mu.Unlock()

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

func (s *Server) buildResponse(reqPkt []byte, xid []byte, clientIP net.IP, msgType MessageType, mac string, clientArch uint16, isIPXE bool) []byte {
	resp := make([]byte, 240)

	resp[0] = 2 // op: BOOTREPLY
	resp[1] = 1 // htype: Ethernet
	resp[2] = 6 // hlen: MAC length
	resp[3] = 0 // hops

	copy(resp[4:8], xid)

	// yiaddr: Your IP address.
	copy(resp[16:20], clientIP.To4())

	// siaddr: Next server IP (for PXE/TFTP).
	var pxeInfo *PXEInfo
	if s.PXEProvider != nil {
		pxeInfo = s.PXEProvider(mac, clientArch, isIPXE)
	}
	if pxeInfo != nil {
		siaddr := net.ParseIP(pxeInfo.TFTPServer).To4()
		if siaddr != nil {
			copy(resp[20:24], siaddr)
		}
		// Boot file name in the fixed header field (for legacy PXE).
		if pxeInfo.Bootfile != "" && !isIPXE {
			bootfile := []byte(pxeInfo.Bootfile)
			if len(bootfile) > 128 {
				bootfile = bootfile[:128]
			}
			copy(resp[108:108+len(bootfile)], bootfile)
		}
	}

	// chaddr: Client hardware address.
	hwAddr, _ := net.ParseMAC(mac)
	if hwAddr != nil {
		copy(resp[28:28+len(hwAddr)], hwAddr)
	}

	// Magic cookie.
	resp = append(resp[:240], 99, 130, 83, 99)

	// Options.
	resp = addOption(resp, OptMessageType, []byte{byte(msgType)})
	resp = addOption(resp, OptServerID, s.ServerIP.To4())
	resp = addOption(resp, OptSubnetMask, []byte(s.SubnetMask))
	resp = addOption(resp, OptRouter, s.Gateway.To4())

	// DNS servers.
	dnsBytes := make([]byte, 0, len(s.DNS)*4)
	for _, d := range s.DNS {
		dnsBytes = append(dnsBytes, d.To4()...)
	}
	resp = addOption(resp, OptDNS, dnsBytes)

	// Broadcast address.
	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = s.ServerIP.To4()[i] | ^s.SubnetMask[i]
	}
	resp = addOption(resp, OptBroadcast, broadcast)

	// Lease time: infinite (0xFFFFFFFF).
	leaseTime := make([]byte, 4)
	binary.BigEndian.PutUint32(leaseTime, 0xFFFFFFFF)
	resp = addOption(resp, OptLeaseTime, leaseTime)

	// Renewal time T1: 1 year.
	t1 := make([]byte, 4)
	binary.BigEndian.PutUint32(t1, 31536000)
	resp = addOption(resp, OptRenewalTime, t1)

	// Rebinding time T2: 1.5 years.
	t2 := make([]byte, 4)
	binary.BigEndian.PutUint32(t2, 47304000)
	resp = addOption(resp, OptRebindingTime, t2)

	// PXE boot options.
	if pxeInfo != nil {
		if isIPXE && pxeInfo.IPXEScript != "" {
			// iPXE client: provide HTTP boot script URL.
			resp = addOption(resp, OptBootfileName, []byte(pxeInfo.IPXEScript))
		} else if pxeInfo.Bootfile != "" {
			// Legacy PXE: provide TFTP boot file.
			resp = addOption(resp, OptTFTPServer, []byte(pxeInfo.TFTPServer))
			resp = addOption(resp, OptBootfileName, []byte(pxeInfo.Bootfile))
		}
	}

	resp = append(resp, OptEnd)

	// Pad to minimum 300 bytes.
	for len(resp) < 300 {
		resp = append(resp, 0)
	}

	return resp
}

func (s *Server) buildNak(reqPkt []byte, xid []byte, mac string) []byte {
	resp := make([]byte, 240)
	resp[0] = 2 // op: BOOTREPLY
	resp[1] = 1 // htype: Ethernet
	resp[2] = 6 // hlen
	copy(resp[4:8], xid)

	hwAddr, _ := net.ParseMAC(mac)
	if hwAddr != nil {
		copy(resp[28:28+len(hwAddr)], hwAddr)
	}

	resp = append(resp[:240], 99, 130, 83, 99)
	resp = addOption(resp, OptMessageType, []byte{byte(Nak)})
	resp = addOption(resp, OptServerID, s.ServerIP.To4())
	resp = append(resp, OptEnd)

	for len(resp) < 300 {
		resp = append(resp, 0)
	}
	return resp
}

func (s *Server) sendResponse(conn net.PacketConn, resp []byte) {
	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: 68}
	if _, err := conn.WriteTo(resp, dst); err != nil {
		log.Printf("DHCP send error: %v", err)
	}
}

// parseOptions extracts DHCP options from a packet starting after the magic cookie.
func parseOptions(pkt []byte) map[byte][]byte {
	opts := make(map[byte][]byte)
	if len(pkt) < 244 {
		return opts
	}
	// Verify magic cookie.
	if pkt[236] != 99 || pkt[237] != 130 || pkt[238] != 83 || pkt[239] != 99 {
		return opts
	}
	i := 240
	for i < len(pkt) {
		code := pkt[i]
		if code == OptEnd {
			break
		}
		if code == 0 { // Padding
			i++
			continue
		}
		if i+1 >= len(pkt) {
			break
		}
		length := int(pkt[i+1])
		if i+2+length > len(pkt) {
			break
		}
		data := make([]byte, length)
		copy(data, pkt[i+2:i+2+length])
		opts[code] = data
		i += 2 + length
	}
	return opts
}

func addOption(pkt []byte, code byte, data []byte) []byte {
	pkt = append(pkt, code, byte(len(data)))
	pkt = append(pkt, data...)
	return pkt
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
