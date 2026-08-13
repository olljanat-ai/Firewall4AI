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

func TestTransparentTLSPortList_Default(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	ports := cfg.TransparentTLSPortList()

	// 443 alone is not enough: Kubernetes API servers on Oracle OKE, kubeadm
	// and Rancher listen on 6443, and a port that is not redirected never
	// reaches the proxy.
	for _, want := range []int{443, 6443} {
		found := false
		for _, port := range ports {
			if port == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("default transparent TLS ports %v must contain %d", ports, want)
		}
	}
}

func TestTransparentTLSPortList_Configured(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(`{"transparent_tls_ports":[443,6443,443,0,70000,-1]}`), 0644)

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	ports := cfg.TransparentTLSPortList()
	if len(ports) != 2 || ports[0] != 443 || ports[1] != 6443 {
		t.Errorf("TransparentTLSPortList() = %v, want [443 6443] with duplicates and invalid ports dropped", ports)
	}
}

func TestTransparentTLSPortList_AllInvalidFallsBackToDefaults(t *testing.T) {
	cfg := Config{TransparentTLSPorts: []int{0, -5}}
	if got := cfg.TransparentTLSPortList(); len(got) != len(DefaultTransparentTLSPorts) {
		t.Errorf("TransparentTLSPortList() = %v, want the defaults %v", got, DefaultTransparentTLSPorts)
	}
}
