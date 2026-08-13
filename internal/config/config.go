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

// GitConfig holds global Git client configuration applied to all disk images.
type GitConfig struct {
	Username string `json:"username"` // git user.name
	Email    string `json:"email"`    // git user.email
}

// Config holds the main application configuration.
type Config struct {
	ListenAddr         string              `json:"listen_addr"`
	AgentAPIAddr       string              `json:"agent_api_addr"`
	TransparentTLSAddr string              `json:"transparent_tls_addr"`
	DataDir            string              `json:"data_dir"`
	TLSCertFile        string              `json:"tls_cert_file"`
	TLSKeyFile         string              `json:"tls_key_file"`
	MaxLogEntries      int                 `json:"max_log_entries"`
	Registries         []RegistryConfig    `json:"registries"`
	HelmRepos          []PackageRepoConfig `json:"helm_repos"`
	OSPackages         []PackageRepoConfig `json:"os_packages"`
	CodeLibraries      []PackageRepoConfig `json:"code_libraries"`
	// TLSPassthroughHosts are tunneled without TLS inspection. Hosts that
	// authenticate clients with certificates (mutual TLS) are detected
	// automatically; this list forces the behaviour for additional hosts.
	// Supports `*.example.com` wildcards.
	TLSPassthroughHosts []string `json:"tls_passthrough_hosts"`
	// TransparentTLSPorts are the destination ports redirected to the
	// transparent TLS listener. HTTPS is not always served on 443: Kubernetes
	// API servers commonly listen on 6443 (kubeadm, Oracle OKE, Rancher) or
	// 8443 (OpenShift, minikube), and traffic to a port that is not redirected
	// never reaches the proxy at all — the agent just gets "connection
	// refused". Empty means DefaultTransparentTLSPorts.
	TransparentTLSPorts []int     `json:"transparent_tls_ports"`
	LearningMode        bool      `json:"learning_mode"`
	DisabledLanguages   []string  `json:"-"` // runtime only, persisted in state.json
	DisabledDistros     []string  `json:"-"` // runtime only, persisted in state.json
	MaxFullLogBody      int       `json:"-"` // runtime only, persisted in state.json
	Git                 GitConfig `json:"-"` // runtime only, persisted in state.json
}

// DefaultTransparentTLSPorts are the destination ports redirected to the
// transparent TLS listener when the config does not list any. Besides plain
// HTTPS these are the ports Kubernetes API servers are commonly published on:
// 6443 (kubeadm, Oracle OKE, Rancher/RKE), 8443 (OpenShift, minikube) and
// 16443 (MicroK8s). Redirecting a port can only widen what agents can reach:
// without a redirect the FORWARD chain rejects the connection outright.
var DefaultTransparentTLSPorts = []int{443, 6443, 8443, 9443, 16443}

// TransparentTLSPortList returns the transparent TLS ports to redirect,
// falling back to DefaultTransparentTLSPorts when none are configured.
// Invalid port numbers are dropped and duplicates removed, so the result can
// be programmed into netfilter as-is.
func (c Config) TransparentTLSPortList() []int {
	ports := c.TransparentTLSPorts
	if len(ports) == 0 {
		ports = DefaultTransparentTLSPorts
	}
	seen := make(map[int]bool, len(ports))
	out := make([]int, 0, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 || seen[port] {
			continue
		}
		seen[port] = true
		out = append(out, port)
	}
	if len(out) == 0 {
		return append([]int{}, DefaultTransparentTLSPorts...)
	}
	return out
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

// SetGitConfig updates the global Git client configuration at runtime.
func SetGitConfig(git GitConfig) {
	mu.Lock()
	defer mu.Unlock()
	current.Git = git
}

// GetGitConfig returns the current Git client configuration.
func GetGitConfig() GitConfig {
	mu.RLock()
	defer mu.RUnlock()
	return current.Git
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
