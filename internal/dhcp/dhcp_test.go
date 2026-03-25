package dhcp

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
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

	// Build a fake DHCP Discover request.
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	req, err := dhcpv4.New(
		dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		dhcpv4.WithHwAddr(mac),
	)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}

	clientIP := net.ParseIP("10.255.255.10")
	resp := s.buildResponse(req, clientIP, dhcpv4.MessageTypeOffer, "aa:bb:cc:dd:ee:01", 0, false)

	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	// Verify it's a BOOTREPLY (OpCode 2).
	if resp.OpCode != dhcpv4.OpcodeBootReply {
		t.Fatalf("expected OpcodeBootReply, got %v", resp.OpCode)
	}
	// Verify transaction ID matches.
	if resp.TransactionID != req.TransactionID {
		t.Fatal("XID mismatch")
	}
	// Verify yiaddr.
	if !resp.YourIPAddr.Equal(clientIP.To4()) {
		t.Fatalf("yiaddr mismatch: %v vs %v", resp.YourIPAddr, clientIP)
	}
	// Verify message type is Offer.
	if resp.MessageType() != dhcpv4.MessageTypeOffer {
		t.Fatalf("expected Offer, got %v", resp.MessageType())
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
