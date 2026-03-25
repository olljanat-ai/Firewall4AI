package tftp

import (
	"testing"
)

func TestParseRRQ(t *testing.T) {
	// filename\0mode\0
	data := []byte("test.bin\x00octet\x00")
	filename, mode := parseRRQ(data)
	if filename != "test.bin" {
		t.Fatalf("expected test.bin, got %s", filename)
	}
	if mode != "octet" {
		t.Fatalf("expected octet, got %s", mode)
	}
}

func TestParseRRQEmpty(t *testing.T) {
	filename, mode := parseRRQ([]byte{})
	if filename != "" || mode != "" {
		t.Fatalf("expected empty, got %s %s", filename, mode)
	}
}

func TestSplitNullStrings(t *testing.T) {
	data := []byte("hello\x00world\x00extra\x00")
	parts := splitNullStrings(data, 3)
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}
	if parts[0] != "hello" || parts[1] != "world" || parts[2] != "extra" {
		t.Fatalf("unexpected parts: %v", parts)
	}

	// Limit to 2.
	parts = splitNullStrings(data, 2)
	if len(parts) != 2 {
		t.Fatalf("expected 2 parts, got %d", len(parts))
	}
}
