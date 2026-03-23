package config

import (
	"encoding/json"
	"os"
	"sync"
)

// RegistryConfig describes a container registry whose traffic is intercepted
// by the transparent proxy for image-level approval. Hosts lists all
// hostnames associated with this registry (registry API, auth, CDN).
type RegistryConfig struct {
	Name  string   `json:"name"`  // e.g., "docker.io" — used as prefix for image refs
	Hosts []string `json:"hosts"` // all hostnames: registry, auth, CDN endpoints
}

// PackageRepoConfig describes a package repository whose traffic is intercepted
// by the transparent proxy for package-level approval. Type identifies the
// package manager (debian, golang, npm, pypi, nuget).
type PackageRepoConfig struct {
	Name  string   `json:"name"`  // e.g., "proxy.golang.org" — display name
	Type  string   `json:"type"`  // package manager type: debian, golang, npm, pypi, nuget
	Hosts []string `json:"hosts"` // all hostnames associated with this repo
}

// Config holds the main application configuration.
type Config struct {
	ListenAddr         string              `json:"listen_addr"`
	AdminAddr          string              `json:"admin_addr"`
	TransparentTLSAddr string              `json:"transparent_tls_addr"`
	DataDir            string              `json:"data_dir"`
	TLSCertFile        string              `json:"tls_cert_file"`
	TLSKeyFile         string              `json:"tls_key_file"`
	MaxLogEntries      int                 `json:"max_log_entries"`
	Registries         []RegistryConfig    `json:"registries"`
	PackageRepos       []PackageRepoConfig `json:"package_repos"`
}

var (
	defaultConfig = Config{
		ListenAddr:         ":8080",
		AdminAddr:          ":443",
		TransparentTLSAddr: ":8443",
		DataDir:            "./data",
		MaxLogEntries:      10000,
	}
	current Config
	mu      sync.RWMutex
)

// Load reads config from a JSON file or returns defaults.
func Load(path string) (Config, error) {
	mu.Lock()
	defer mu.Unlock()

	current = defaultConfig
	if path == "" {
		return current, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return current, nil
		}
		return current, err
	}
	if err := json.Unmarshal(data, &current); err != nil {
		return current, err
	}
	return current, nil
}

// Get returns the current config.
func Get() Config {
	mu.RLock()
	defer mu.RUnlock()
	return current
}
