package logging

import (
	"testing"
	"time"
)

func TestLogger_Add(t *testing.T) {
	l := NewLogger(100)

	e := l.Add(Entry{Method: "GET", Host: "example.com", Status: "allowed"})
	if e.ID != 1 {
		t.Errorf("expected ID 1, got %d", e.ID)
	}
	if e.Timestamp.IsZero() {
		t.Error("timestamp should be set automatically")
	}
}

func TestLogger_AddWithTimestamp(t *testing.T) {
	l := NewLogger(100)
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	e := l.Add(Entry{Timestamp: ts, Method: "GET", Host: "example.com", Status: "allowed"})
	if !e.Timestamp.Equal(ts) {
		t.Error("provided timestamp should be preserved")
	}
}

func TestLogger_Recent(t *testing.T) {
	l := NewLogger(100)
	l.Add(Entry{Method: "GET", Host: "a.com", Status: "allowed"})
	l.Add(Entry{Method: "GET", Host: "b.com", Status: "denied"})
	l.Add(Entry{Method: "POST", Host: "c.com", Status: "allowed"})

	recent := l.Recent(2)
	if len(recent) != 2 {
		t.Fatalf("expected 2 recent entries, got %d", len(recent))
	}
	// Newest first.
	if recent[0].Host != "c.com" {
		t.Errorf("expected c.com first, got %s", recent[0].Host)
	}
	if recent[1].Host != "b.com" {
		t.Errorf("expected b.com second, got %s", recent[1].Host)
	}
}

func TestLogger_RecentAll(t *testing.T) {
	l := NewLogger(100)
	l.Add(Entry{Host: "a.com", Status: "allowed"})

	// Requesting more than available returns all.
	recent := l.Recent(0)
	if len(recent) != 1 {
		t.Errorf("expected 1 entry, got %d", len(recent))
	}
}

func TestLogger_Since(t *testing.T) {
	l := NewLogger(100)
	l.Add(Entry{Host: "a.com", Status: "allowed"})
	l.Add(Entry{Host: "b.com", Status: "denied"})
	l.Add(Entry{Host: "c.com", Status: "allowed"})

	entries := l.Since(1)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries after ID 1, got %d", len(entries))
	}
	if entries[0].Host != "b.com" {
		t.Errorf("expected b.com, got %s", entries[0].Host)
	}
}

func TestLogger_MaxSize(t *testing.T) {
	l := NewLogger(3)
	for i := 0; i < 5; i++ {
		l.Add(Entry{Host: "test.com", Status: "allowed"})
	}

	stats := l.Stats()
	if stats["total"] != 3 {
		t.Errorf("expected 3 entries (trimmed), got %d", stats["total"])
	}
}

func TestLogger_Stats(t *testing.T) {
	l := NewLogger(100)
	l.Add(Entry{Status: "allowed"})
	l.Add(Entry{Status: "allowed"})
	l.Add(Entry{Status: "denied"})
	l.Add(Entry{Status: "error"})

	stats := l.Stats()
	if stats["total"] != 4 {
		t.Errorf("expected total 4, got %d", stats["total"])
	}
	if stats["allowed"] != 2 {
		t.Errorf("expected allowed 2, got %d", stats["allowed"])
	}
	if stats["denied"] != 1 {
		t.Errorf("expected denied 1, got %d", stats["denied"])
	}
}

func TestNewLogger_DefaultMaxSize(t *testing.T) {
	l := NewLogger(0)
	if l.maxSize != 10000 {
		t.Errorf("expected default maxSize 10000, got %d", l.maxSize)
	}
}
