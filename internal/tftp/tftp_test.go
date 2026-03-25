package tftp

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// mockReaderFrom captures the data that would be sent via TFTP.
type mockReaderFrom struct {
	buf bytes.Buffer
}

func (m *mockReaderFrom) ReadFrom(r io.Reader) (int64, error) {
	return m.buf.ReadFrom(r)
}

func TestReadHandlerServesFile(t *testing.T) {
	dir := t.TempDir()
	content := []byte("hello PXE boot")
	if err := os.WriteFile(filepath.Join(dir, "test.bin"), content, 0644); err != nil {
		t.Fatal(err)
	}

	s := NewServer(":69", dir)
	rf := &mockReaderFrom{}

	err := s.readHandler("test.bin", rf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(rf.buf.Bytes(), content) {
		t.Fatalf("expected %q, got %q", content, rf.buf.Bytes())
	}
}

func TestReadHandlerFileNotFound(t *testing.T) {
	dir := t.TempDir()
	s := NewServer(":69", dir)
	rf := &mockReaderFrom{}

	err := s.readHandler("nonexistent.bin", rf)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestReadHandlerPathTraversal(t *testing.T) {
	dir := t.TempDir()
	s := NewServer(":69", dir)
	rf := &mockReaderFrom{}

	err := s.readHandler("../../../etc/passwd", rf)
	if err == nil {
		t.Fatal("expected error for path traversal")
	}
}

func TestNewServer(t *testing.T) {
	s := NewServer(":69", "/tmp/tftp")
	if s.ListenAddr != ":69" {
		t.Fatalf("expected :69, got %s", s.ListenAddr)
	}
	if s.RootDir != "/tmp/tftp" {
		t.Fatalf("expected /tmp/tftp, got %s", s.RootDir)
	}
}
