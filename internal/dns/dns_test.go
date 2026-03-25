package dns

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestParseQuestion(t *testing.T) {
	// Build a DNS query for "example.com" type A class IN.
	pkt := make([]byte, 12) // header
	binary.BigEndian.PutUint16(pkt[0:2], 0x1234)  // ID
	binary.BigEndian.PutUint16(pkt[2:4], 0x0100)  // Flags: RD=1
	binary.BigEndian.PutUint16(pkt[4:6], 1)        // QDCOUNT=1

	// Question: example.com
	pkt = append(pkt, 7) // length "example"
	pkt = append(pkt, []byte("example")...)
	pkt = append(pkt, 3) // length "com"
	pkt = append(pkt, []byte("com")...)
	pkt = append(pkt, 0) // end of name

	// Type A (1) and class IN (1).
	typeClass := make([]byte, 4)
	binary.BigEndian.PutUint16(typeClass[0:2], 1) // A
	binary.BigEndian.PutUint16(typeClass[2:4], 1) // IN
	pkt = append(pkt, typeClass...)

	name, qtype, offset := parseQuestion(pkt)
	if name != "example.com." {
		t.Fatalf("expected example.com., got %s", name)
	}
	if qtype != 1 {
		t.Fatalf("expected type 1 (A), got %d", qtype)
	}
	if offset == 0 {
		t.Fatal("expected non-zero offset")
	}
}

func TestBuildAResponse(t *testing.T) {
	// Build a query packet.
	pkt := make([]byte, 12)
	binary.BigEndian.PutUint16(pkt[0:2], 0x1234)
	binary.BigEndian.PutUint16(pkt[2:4], 0x0100)
	binary.BigEndian.PutUint16(pkt[4:6], 1)

	pkt = append(pkt, 4)
	pkt = append(pkt, []byte("test")...)
	pkt = append(pkt, 0)
	typeClass := make([]byte, 4)
	binary.BigEndian.PutUint16(typeClass[0:2], 1)
	binary.BigEndian.PutUint16(typeClass[2:4], 1)
	pkt = append(pkt, typeClass...)

	_, _, offset := parseQuestion(pkt)
	ip := net.ParseIP("10.255.255.50")

	resp := buildAResponse(pkt, "test.", ip, offset)

	// Check response flag.
	if resp[2]&0x80 == 0 {
		t.Fatal("QR bit not set in response")
	}
	// Check ANCOUNT=1.
	ancount := binary.BigEndian.Uint16(resp[6:8])
	if ancount != 1 {
		t.Fatalf("expected ANCOUNT=1, got %d", ancount)
	}
	// Check that the IP is in the response.
	// Last 4 bytes should be the IP.
	respIP := net.IP(resp[len(resp)-4:])
	if !respIP.Equal(ip.To4()) {
		t.Fatalf("expected IP %v, got %v", ip, respIP)
	}
}

func TestBuildServFail(t *testing.T) {
	pkt := make([]byte, 12)
	binary.BigEndian.PutUint16(pkt[0:2], 0xABCD)

	resp := buildServFail(pkt)
	if resp == nil {
		t.Fatal("expected response")
	}
	// Check RCODE=2.
	if resp[3]&0x0F != 2 {
		t.Fatalf("expected RCODE=2, got %d", resp[3]&0x0F)
	}
}

func TestSetAndResolveHost(t *testing.T) {
	s := NewServer(":53", []string{"1.1.1.1"})

	s.SetHost("agent1", net.ParseIP("10.255.255.50"))
	s.SetHost("agent2.local", net.ParseIP("10.255.255.51"))

	ip := s.resolveLocal("agent1.")
	if ip == nil || !ip.Equal(net.ParseIP("10.255.255.50")) {
		t.Fatalf("expected 10.255.255.50, got %v", ip)
	}

	ip = s.resolveLocal("agent2.local.")
	if ip == nil || !ip.Equal(net.ParseIP("10.255.255.51")) {
		t.Fatalf("expected 10.255.255.51, got %v", ip)
	}

	// Unknown host.
	ip = s.resolveLocal("unknown.")
	if ip != nil {
		t.Fatalf("expected nil, got %v", ip)
	}
}

func TestRemoveHost(t *testing.T) {
	s := NewServer(":53", []string{"1.1.1.1"})
	s.SetHost("agent1", net.ParseIP("10.255.255.50"))
	s.RemoveHost("agent1")

	ip := s.resolveLocal("agent1.")
	if ip != nil {
		t.Fatalf("expected nil after remove, got %v", ip)
	}
}
