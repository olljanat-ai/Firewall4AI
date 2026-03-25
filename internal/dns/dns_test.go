package dns

import (
	"net"
	"testing"

	mdns "github.com/miekg/dns"
)

func TestHandleLocalAQuery(t *testing.T) {
	s := NewServer(":15353", []string{"1.1.1.1"})
	s.SetHost("agent1", net.ParseIP("10.255.255.50"))

	// Build a DNS query for "agent1." type A.
	r := new(mdns.Msg)
	r.SetQuestion("agent1.", mdns.TypeA)

	rec := &testResponseWriter{}
	s.handleRequest(rec, r)

	if rec.msg == nil {
		t.Fatal("expected response")
	}
	if len(rec.msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(rec.msg.Answer))
	}
	a, ok := rec.msg.Answer[0].(*mdns.A)
	if !ok {
		t.Fatal("expected A record")
	}
	if !a.A.Equal(net.ParseIP("10.255.255.50").To4()) {
		t.Fatalf("expected 10.255.255.50, got %v", a.A)
	}
}

func TestHandleForwardReturnsServFail(t *testing.T) {
	// Use a non-routable upstream so forwarding fails.
	s := NewServer(":15353", []string{"192.0.2.1:53"})

	r := new(mdns.Msg)
	r.SetQuestion("example.com.", mdns.TypeA)

	rec := &testResponseWriter{}
	s.handleRequest(rec, r)

	if rec.msg == nil {
		t.Fatal("expected response")
	}
	if rec.msg.Rcode != mdns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL, got rcode %d", rec.msg.Rcode)
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

// testResponseWriter implements dns.ResponseWriter for testing.
type testResponseWriter struct {
	msg *mdns.Msg
}

func (w *testResponseWriter) LocalAddr() net.Addr       { return &net.UDPAddr{} }
func (w *testResponseWriter) RemoteAddr() net.Addr      { return &net.UDPAddr{} }
func (w *testResponseWriter) WriteMsg(m *mdns.Msg) error { w.msg = m; return nil }
func (w *testResponseWriter) Write([]byte) (int, error)  { return 0, nil }
func (w *testResponseWriter) Close() error               { return nil }
func (w *testResponseWriter) TsigStatus() error          { return nil }
func (w *testResponseWriter) TsigTimersOnly(bool)        {}
func (w *testResponseWriter) Hijack()                    {}
