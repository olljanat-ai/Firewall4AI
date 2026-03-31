package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("expected :8080, got %s", cfg.ListenAddr)
	}
	if cfg.AdminAddr != ":80" {
		t.Errorf("expected :80, got %s", cfg.AdminAddr)
	}
	if cfg.MaxLogEntries != 10000 {
		t.Errorf("expected 10000, got %d", cfg.MaxLogEntries)
	}
}

func TestLoad_FileNotExist(t *testing.T) {
	cfg, err := Load("/nonexistent/path/config.json")
	if err != nil {
		t.Fatalf("Load() error for nonexistent: %v", err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("expected defaults, got %s", cfg.ListenAddr)
	}
}

func TestLoad_FromFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(`{"listen_addr":":9090","admin_addr":":9443","max_log_entries":500}`), 0644)

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.ListenAddr != ":9090" {
		t.Errorf("expected :9090, got %s", cfg.ListenAddr)
	}
	if cfg.AdminAddr != ":9443" {
		t.Errorf("expected :9443, got %s", cfg.AdminAddr)
	}
	if cfg.MaxLogEntries != 500 {
		t.Errorf("expected 500, got %d", cfg.MaxLogEntries)
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(`{invalid`), 0644)

	_, err := Load(cfgPath)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestGet(t *testing.T) {
	Load("")
	cfg := Get()
	if cfg.ListenAddr != ":8080" {
		t.Errorf("Get() should return current config")
	}
}
