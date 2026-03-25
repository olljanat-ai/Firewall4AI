package dhcp

import (
	"net"
	"testing"
)

func TestAllocateIP(t *testing.T) {
	s := NewServer(
		net.ParseIP("10.255.255.1"),
		net.ParseIP("10.255.255.10"),
		net.ParseIP("10.255.255.14"),
		net.ParseIP("10.255.255.1"),
		net.CIDRMask(24, 32),
		[]net.IP{net.ParseIP("10.255.255.1")},
		"eth1",
	)

	// First allocation.
	ip := s.allocateIP("aa:bb:cc:dd:ee:01", "agent1")
	if ip == nil || ip.String() != "10.255.255.10" {
		t.Fatalf("expected 10.255.255.10, got %v", ip)
	}

	// Same MAC should get same IP.
	ip2 := s.allocateIP("aa:bb:cc:dd:ee:01", "agent1")
	if ip2.String() != "10.255.255.10" {
		t.Fatalf("expected same IP 10.255.255.10, got %v", ip2)
	}

	// Different MAC gets next IP.
	ip3 := s.allocateIP("aa:bb:cc:dd:ee:02", "agent2")
	if ip3 == nil || ip3.String() != "10.255.255.11" {
		t.Fatalf("expected 10.255.255.11, got %v", ip3)
	}
}

func TestAllocateIPExhaustion(t *testing.T) {
	s := NewServer(
		net.ParseIP("10.255.255.1"),
		net.ParseIP("10.255.255.10"),
		net.ParseIP("10.255.255.11"),
		net.ParseIP("10.255.255.1"),
		net.CIDRMask(24, 32),
		[]net.IP{net.ParseIP("10.255.255.1")},
		"eth1",
	)

	// Allocate both IPs.
	s.allocateIP("aa:bb:cc:dd:ee:01", "a1")
	s.allocateIP("aa:bb:cc:dd:ee:02", "a2")

	// Third should fail.
	ip := s.allocateIP("aa:bb:cc:dd:ee:03", "a3")
	if ip != nil {
		t.Fatalf("expected nil, got %v", ip)
	}
}

func TestStaticLease(t *testing.T) {
	s := NewServer(
		net.ParseIP("10.255.255.1"),
		net.ParseIP("10.255.255.10"),
		net.ParseIP("10.255.255.254"),
		net.ParseIP("10.255.255.1"),
		net.CIDRMask(24, 32),
		[]net.IP{net.ParseIP("10.255.255.1")},
		"eth1",
	)

	s.SetStaticLease("aa:bb:cc:dd:ee:01", "10.255.255.50", "agent1")

	ip := s.allocateIP("aa:bb:cc:dd:ee:01", "agent1")
	if ip.String() != "10.255.255.50" {
		t.Fatalf("expected static IP 10.255.255.50, got %v", ip)
	}

	// Another MAC should not get the static IP.
	ip2 := s.allocateIP("aa:bb:cc:dd:ee:02", "agent2")
	if ip2.String() == "10.255.255.50" {
		t.Fatalf("expected different IP, got the static one")
	}
}

func TestExportLoadLeases(t *testing.T) {
	s := NewServer(
		net.ParseIP("10.255.255.1"),
		net.ParseIP("10.255.255.10"),
		net.ParseIP("10.255.255.254"),
		net.ParseIP("10.255.255.1"),
		net.CIDRMask(24, 32),
		[]net.IP{net.ParseIP("10.255.255.1")},
		"eth1",
	)

	s.allocateIP("aa:bb:cc:dd:ee:01", "a1")
	s.allocateIP("aa:bb:cc:dd:ee:02", "a2")

	exported := s.ExportLeases()
	if len(exported) != 2 {
		t.Fatalf("expected 2 leases, got %d", len(exported))
	}

	// Load into new server.
	s2 := NewServer(
		net.ParseIP("10.255.255.1"),
		net.ParseIP("10.255.255.10"),
		net.ParseIP("10.255.255.254"),
		net.ParseIP("10.255.255.1"),
		net.CIDRMask(24, 32),
		[]net.IP{net.ParseIP("10.255.255.1")},
		"eth1",
	)
	s2.LoadLeases(exported)

	// Should reuse the same IPs.
	ip := s2.allocateIP("aa:bb:cc:dd:ee:01", "a1")
	if ip.String() != "10.255.255.10" {
		t.Fatalf("expected loaded IP 10.255.255.10, got %v", ip)
	}
}

func TestParseOptions(t *testing.T) {
	// Build a minimal DHCP packet.
	pkt := make([]byte, 244)
	pkt[236] = 99
	pkt[237] = 130
	pkt[238] = 83
	pkt[239] = 99
	// Add message type option.
	pkt = append(pkt, OptMessageType, 1, byte(Discover))
	// Add end.
	pkt = append(pkt, OptEnd)

	opts := parseOptions(pkt)
	if v, ok := opts[OptMessageType]; !ok || len(v) != 1 || MessageType(v[0]) != Discover {
		t.Fatalf("expected DISCOVER, got %v", opts)
	}
}

func TestBuildResponse(t *testing.T) {
	s := NewServer(
		net.ParseIP("10.255.255.1"),
		net.ParseIP("10.255.255.10"),
		net.ParseIP("10.255.255.254"),
		net.ParseIP("10.255.255.1"),
		net.CIDRMask(24, 32),
		[]net.IP{net.ParseIP("10.255.255.1")},
		"eth1",
	)

	reqPkt := make([]byte, 240)
	xid := []byte{0x12, 0x34, 0x56, 0x78}
	clientIP := net.ParseIP("10.255.255.10")

	resp := s.buildResponse(reqPkt, xid, clientIP, Offer, "aa:bb:cc:dd:ee:01", 0, false)

	// Verify it's a BOOTREPLY.
	if resp[0] != 2 {
		t.Fatal("expected op=2 (BOOTREPLY)")
	}
	// Verify XID.
	if resp[4] != 0x12 || resp[5] != 0x34 {
		t.Fatal("XID mismatch")
	}
	// Verify yiaddr.
	yiaddr := net.IP(resp[16:20])
	if !yiaddr.Equal(clientIP.To4()) {
		t.Fatalf("yiaddr mismatch: %v vs %v", yiaddr, clientIP)
	}
	// Verify magic cookie.
	if resp[240] != 99 || resp[241] != 130 || resp[242] != 83 || resp[243] != 99 {
		t.Fatal("magic cookie mismatch")
	}
}

func TestRemoveLease(t *testing.T) {
	s := NewServer(
		net.ParseIP("10.255.255.1"),
		net.ParseIP("10.255.255.10"),
		net.ParseIP("10.255.255.14"),
		net.ParseIP("10.255.255.1"),
		net.CIDRMask(24, 32),
		[]net.IP{net.ParseIP("10.255.255.1")},
		"eth1",
	)

	s.allocateIP("aa:bb:cc:dd:ee:01", "a1")
	s.RemoveLease("aa:bb:cc:dd:ee:01")

	// IP should now be available again.
	ip := s.allocateIP("aa:bb:cc:dd:ee:02", "a2")
	if ip.String() != "10.255.255.10" {
		t.Fatalf("expected 10.255.255.10 reused, got %v", ip)
	}
}
