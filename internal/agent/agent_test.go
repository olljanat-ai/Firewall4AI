package agent

import (
	"testing"
)

func TestAddAndGet(t *testing.T) {
	m := NewManager()
	err := m.Add(Agent{
		ID:       "a1",
		MAC:      "AA:BB:CC:DD:EE:01",
		Hostname: "agent1",
		OS:       OSAlpine,
	})
	if err != nil {
		t.Fatal(err)
	}

	a, ok := m.Get("a1")
	if !ok {
		t.Fatal("agent not found")
	}
	if a.MAC != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("MAC not normalized: %s", a.MAC)
	}
	if a.Status != StatusNew {
		t.Fatalf("expected status 'new', got %s", a.Status)
	}
}

func TestDuplicateMAC(t *testing.T) {
	m := NewManager()
	m.Add(Agent{ID: "a1", MAC: "aa:bb:cc:dd:ee:01", Hostname: "agent1", OS: OSAlpine})

	err := m.Add(Agent{ID: "a2", MAC: "AA:BB:CC:DD:EE:01", Hostname: "agent2", OS: OSDebian})
	if err == nil {
		t.Fatal("expected error for duplicate MAC")
	}
}

func TestDuplicateID(t *testing.T) {
	m := NewManager()
	m.Add(Agent{ID: "a1", MAC: "aa:bb:cc:dd:ee:01", Hostname: "agent1", OS: OSAlpine})

	err := m.Add(Agent{ID: "a1", MAC: "aa:bb:cc:dd:ee:02", Hostname: "agent2", OS: OSDebian})
	if err == nil {
		t.Fatal("expected error for duplicate ID")
	}
}

func TestGetByMAC(t *testing.T) {
	m := NewManager()
	m.Add(Agent{ID: "a1", MAC: "aa:bb:cc:dd:ee:01", Hostname: "agent1", OS: OSAlpine})

	a, ok := m.GetByMAC("AA:BB:CC:DD:EE:01")
	if !ok {
		t.Fatal("agent not found by MAC")
	}
	if a.ID != "a1" {
		t.Fatalf("wrong agent: %s", a.ID)
	}
}

func TestDelete(t *testing.T) {
	m := NewManager()
	m.Add(Agent{ID: "a1", MAC: "aa:bb:cc:dd:ee:01", Hostname: "agent1", OS: OSAlpine})

	err := m.Delete("a1")
	if err != nil {
		t.Fatal(err)
	}

	_, ok := m.Get("a1")
	if ok {
		t.Fatal("agent should be deleted")
	}

	_, ok = m.GetByMAC("aa:bb:cc:dd:ee:01")
	if ok {
		t.Fatal("MAC lookup should be gone")
	}
}

func TestUpdate(t *testing.T) {
	m := NewManager()
	m.Add(Agent{ID: "a1", MAC: "aa:bb:cc:dd:ee:01", Hostname: "agent1", OS: OSAlpine})

	err := m.Update(Agent{
		ID:       "a1",
		MAC:      "aa:bb:cc:dd:ee:02",
		Hostname: "agent1-updated",
		OS:       OSDebian,
	})
	if err != nil {
		t.Fatal(err)
	}

	a, _ := m.Get("a1")
	if a.Hostname != "agent1-updated" {
		t.Fatalf("hostname not updated: %s", a.Hostname)
	}
	if a.MAC != "aa:bb:cc:dd:ee:02" {
		t.Fatalf("MAC not updated: %s", a.MAC)
	}

	// Old MAC should not resolve.
	_, ok := m.GetByMAC("aa:bb:cc:dd:ee:01")
	if ok {
		t.Fatal("old MAC should not resolve")
	}

	// New MAC should resolve.
	a2, ok := m.GetByMAC("aa:bb:cc:dd:ee:02")
	if !ok || a2.ID != "a1" {
		t.Fatal("new MAC should resolve to a1")
	}
}

func TestExportLoad(t *testing.T) {
	m := NewManager()
	m.Add(Agent{ID: "a1", MAC: "aa:bb:cc:dd:ee:01", Hostname: "agent1", OS: OSAlpine})
	m.Add(Agent{ID: "a2", MAC: "aa:bb:cc:dd:ee:02", Hostname: "agent2", OS: OSDebian})

	exported := m.ExportAgents()
	if len(exported) != 2 {
		t.Fatalf("expected 2, got %d", len(exported))
	}

	m2 := NewManager()
	m2.LoadAgents(exported)

	if m2.Count() != 2 {
		t.Fatalf("expected 2 loaded, got %d", m2.Count())
	}
}

func TestSetStatus(t *testing.T) {
	m := NewManager()
	m.Add(Agent{ID: "a1", MAC: "aa:bb:cc:dd:ee:01", Hostname: "agent1", OS: OSAlpine})

	m.SetStatus("a1", StatusReady, "files downloaded")
	a, _ := m.Get("a1")
	if a.Status != StatusReady {
		t.Fatalf("expected ready, got %s", a.Status)
	}
	if a.StatusMsg != "files downloaded" {
		t.Fatalf("expected msg, got %s", a.StatusMsg)
	}
}

func TestValidateMAC(t *testing.T) {
	if err := ValidateMAC("aa:bb:cc:dd:ee:ff"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMAC("invalid"); err == nil {
		t.Fatal("expected error for invalid MAC")
	}
}

func TestDefaultOSVersion(t *testing.T) {
	if v := DefaultOSVersion(OSAlpine); v != "3.23" {
		t.Fatalf("expected 3.23, got %s", v)
	}
	if v := DefaultOSVersion(OSDebian); v != "13" {
		t.Fatalf("expected 13, got %s", v)
	}
	if v := DefaultOSVersion(OSUbuntu); v != "24.04" {
		t.Fatalf("expected 24.04, got %s", v)
	}
}
