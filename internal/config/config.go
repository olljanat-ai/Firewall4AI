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
	AgentAPIAddr       string              `json:"agent_api_addr"`
	TransparentTLSAddr string              `json:"transparent_tls_addr"`
	DataDir            string              `json:"data_dir"`
	TLSCertFile        string              `json:"tls_cert_file"`
	TLSKeyFile         string              `json:"tls_key_file"`
	MaxLogEntries      int                 `json:"max_log_entries"`
	Registries         []RegistryConfig    `json:"registries"`
	OSPackages         []PackageRepoConfig `json:"os_packages"`
	CodeLibraries      []PackageRepoConfig `json:"code_libraries"`
	LearningMode       bool                `json:"learning_mode"`
	DisabledLanguages  []string            `json:"-"` // runtime only, persisted in state.json
	DisabledDistros    []string            `json:"-"` // runtime only, persisted in state.json
	MaxFullLogBody     int                 `json:"-"` // runtime only, persisted in state.json
}

// SetLearningMode updates the learning mode setting at runtime.
func SetLearningMode(enabled bool) {
	mu.Lock()
	defer mu.Unlock()
	current.LearningMode = enabled
}

// SetDisabledLanguages updates the disabled code library types at runtime.
func SetDisabledLanguages(disabled []string) {
	mu.Lock()
	defer mu.Unlock()
	current.DisabledLanguages = append([]string{}, disabled...)
}

// SetDisabledDistros updates the disabled OS distro types at runtime.
func SetDisabledDistros(disabled []string) {
	mu.Lock()
	defer mu.Unlock()
	current.DisabledDistros = append([]string{}, disabled...)
}

// IsLanguageDisabled returns true if the given code library type is disabled.
func IsLanguageDisabled(langType string) bool {
	mu.RLock()
	defer mu.RUnlock()
	for _, d := range current.DisabledLanguages {
		if d == langType {
			return true
		}
	}
	return false
}

// DefaultMaxFullLogBody is the default maximum body size (in bytes) captured in full logging mode.
const DefaultMaxFullLogBody = 256 * 1024 // 256 KB

// SetMaxFullLogBody updates the maximum full log body size at runtime.
func SetMaxFullLogBody(size int) {
	mu.Lock()
	defer mu.Unlock()
	current.MaxFullLogBody = size
}

// GetMaxFullLogBody returns the current maximum full log body size.
func GetMaxFullLogBody() int {
	mu.RLock()
	defer mu.RUnlock()
	if current.MaxFullLogBody <= 0 {
		return DefaultMaxFullLogBody
	}
	return current.MaxFullLogBody
}

// IsDistroDisabled returns true if the given OS distro type is disabled.
func IsDistroDisabled(distroType string) bool {
	mu.RLock()
	defer mu.RUnlock()
	for _, d := range current.DisabledDistros {
		if d == distroType {
			return true
		}
	}
	return false
}

var (
	defaultConfig = Config{
		ListenAddr:         ":8080",
		AdminAddr:          ":443",
		AgentAPIAddr:       "10.255.255.1:80",
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
