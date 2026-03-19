package approval

import (
	"testing"
	"time"
)

func TestManager_CheckRegistersAndReturns(t *testing.T) {
	m := NewManager()

	// First check should return pending and register.
	status := m.Check("example.com", "skill-1")
	if status != StatusPending {
		t.Errorf("expected pending, got %s", status)
	}

	// Second check should still return pending.
	status = m.Check("example.com", "skill-1")
	if status != StatusPending {
		t.Errorf("expected pending on re-check, got %s", status)
	}
}

func TestManager_Decide(t *testing.T) {
	m := NewManager()
	m.Check("example.com", "skill-1")

	m.Decide("example.com", "skill-1", StatusApproved, "looks good")

	status := m.Check("example.com", "skill-1")
	if status != StatusApproved {
		t.Errorf("expected approved, got %s", status)
	}
}

func TestManager_DecideNewHost(t *testing.T) {
	m := NewManager()
	// Decide without prior Check.
	m.Decide("new.com", "skill-1", StatusDenied, "blocked")

	status := m.Check("new.com", "skill-1")
	if status != StatusDenied {
		t.Errorf("expected denied, got %s", status)
	}
}

func TestManager_WaitForDecision(t *testing.T) {
	m := NewManager()
	m.Check("example.com", "skill-1")

	// Decide in background after short delay.
	go func() {
		time.Sleep(50 * time.Millisecond)
		m.Decide("example.com", "skill-1", StatusApproved, "ok")
	}()

	status := m.WaitForDecision("example.com", "skill-1", 2*time.Second)
	if status != StatusApproved {
		t.Errorf("expected approved, got %s", status)
	}
}

func TestManager_WaitForDecisionTimeout(t *testing.T) {
	m := NewManager()
	m.Check("slow.com", "skill-1")

	status := m.WaitForDecision("slow.com", "skill-1", 50*time.Millisecond)
	if status != StatusDenied {
		t.Errorf("expected denied on timeout, got %s", status)
	}
}

func TestManager_WaitForDecisionAlreadyDecided(t *testing.T) {
	m := NewManager()
	m.Check("example.com", "skill-1")
	m.Decide("example.com", "skill-1", StatusApproved, "pre-decided")

	status := m.WaitForDecision("example.com", "skill-1", time.Second)
	if status != StatusApproved {
		t.Errorf("expected approved for already-decided, got %s", status)
	}
}

func TestManager_ListPending(t *testing.T) {
	m := NewManager()
	m.Check("a.com", "skill-1")
	m.Check("b.com", "skill-1")
	m.Decide("b.com", "skill-1", StatusApproved, "ok")

	pending := m.ListPending()
	if len(pending) != 1 {
		t.Errorf("expected 1 pending, got %d", len(pending))
	}
	if pending[0].Host != "a.com" {
		t.Errorf("expected a.com pending, got %s", pending[0].Host)
	}
}

func TestManager_ListAll(t *testing.T) {
	m := NewManager()
	m.Check("a.com", "skill-1")
	m.Check("b.com", "skill-1")

	all := m.ListAll()
	if len(all) != 2 {
		t.Errorf("expected 2 total, got %d", len(all))
	}
}

func TestManager_LoadAndExport(t *testing.T) {
	m := NewManager()
	m.Check("a.com", "skill-1")
	m.Decide("a.com", "skill-1", StatusApproved, "ok")

	exported := m.Export()

	m2 := NewManager()
	m2.LoadApprovals(exported)

	status := m2.Check("a.com", "skill-1")
	if status != StatusApproved {
		t.Errorf("expected approved after load, got %s", status)
	}
}
