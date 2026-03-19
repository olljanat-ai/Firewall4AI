package store

import (
	"os"
	"path/filepath"
	"testing"
)

type testData struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func TestNew_CreatesFileWithDefaults(t *testing.T) {
	dir := t.TempDir()
	defaults := testData{Name: "default", Count: 0}

	s, err := New[testData](dir, "test.json", defaults)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	got := s.Get()
	if got.Name != "default" {
		t.Errorf("expected name=default, got %s", got.Name)
	}

	// File should exist.
	if _, err := os.Stat(filepath.Join(dir, "test.json")); err != nil {
		t.Error("expected file to be created")
	}
}

func TestNew_LoadsExistingFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.json"), []byte(`{"name":"loaded","count":42}`), 0644)

	s, err := New[testData](dir, "test.json", testData{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	got := s.Get()
	if got.Name != "loaded" || got.Count != 42 {
		t.Errorf("expected loaded/42, got %s/%d", got.Name, got.Count)
	}
}

func TestUpdate_PersistsToFile(t *testing.T) {
	dir := t.TempDir()
	s, err := New[testData](dir, "test.json", testData{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	err = s.Update(func(d *testData) {
		d.Name = "updated"
		d.Count = 10
	})
	if err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	// Verify by reading file directly.
	data, _ := os.ReadFile(filepath.Join(dir, "test.json"))
	if len(data) == 0 {
		t.Fatal("file should not be empty after update")
	}

	// Verify by loading new store from same file.
	s2, err := New[testData](dir, "test.json", testData{})
	if err != nil {
		t.Fatalf("New() error on reload: %v", err)
	}
	got := s2.Get()
	if got.Name != "updated" || got.Count != 10 {
		t.Errorf("expected updated/10, got %s/%d", got.Name, got.Count)
	}
}

func TestNew_CreatesDirIfNeeded(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sub", "dir")
	_, err := New[testData](dir, "test.json", testData{Name: "nested"})
	if err != nil {
		t.Fatalf("New() should create nested dirs: %v", err)
	}
}
