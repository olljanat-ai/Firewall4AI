// Package agent manages AI agent VM configurations including OS type,
// network boot settings, and extra packages.
package agent

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// OSType represents the operating system for an agent VM.
type OSType string

const (
	OSAlpine OSType = "alpine"
	OSDebian OSType = "debian"
	OSUbuntu OSType = "ubuntu"
)

// Status represents the installation status of an agent VM.
type Status string

const (
	StatusNew         Status = "new"         // Configured, waiting for first boot
	StatusDownloading Status = "downloading" // Downloading netboot files
	StatusReady       Status = "ready"       // Netboot files ready, waiting for VM to PXE boot
	StatusInstalling  Status = "installing"  // VM is PXE booting / installing
	StatusInstalled   Status = "installed"   // Installation complete
	StatusError       Status = "error"       // Error during download or setup
)

// Agent represents an AI agent VM configuration.
type Agent struct {
	ID          string   `json:"id"`
	MAC         string   `json:"mac"`          // MAC address (identifier), e.g., "aa:bb:cc:dd:ee:ff"
	Hostname    string   `json:"hostname"`      // Agent hostname
	IP          string   `json:"ip"`            // Assigned IP address
	OS          OSType   `json:"os"`            // "alpine", "debian", "ubuntu"
	OSVersion   string   `json:"os_version"`    // e.g., "3.23", "13", "24.04"
	Packages    []string `json:"packages"`      // Extra packages to install
	DiskDevice  string   `json:"disk_device"`   // e.g., "/dev/vda" or "/dev/sda"
	Status      Status   `json:"status"`
	StatusMsg   string   `json:"status_msg"`    // Additional status detail (e.g., error message)
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Manager manages agent configurations.
type Manager struct {
	mu     sync.RWMutex
	agents map[string]*Agent // ID -> Agent
	byMAC  map[string]string // MAC -> ID (lowercase MAC)
}

// NewManager creates a new agent manager.
func NewManager() *Manager {
	return &Manager{
		agents: make(map[string]*Agent),
		byMAC:  make(map[string]string),
	}
}

// LoadAgents restores agents from persisted state.
func (m *Manager) LoadAgents(agents []Agent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range agents {
		a := agents[i]
		m.agents[a.ID] = &a
		m.byMAC[normalizeMAC(a.MAC)] = a.ID
	}
}

// ExportAgents returns all agents for persistence.
func (m *Manager) ExportAgents() []Agent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Agent, 0, len(m.agents))
	for _, a := range m.agents {
		out = append(out, *a)
	}
	return out
}

// Add adds a new agent. Returns error if MAC or ID already exists.
func (m *Manager) Add(a Agent) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.agents[a.ID]; exists {
		return fmt.Errorf("agent with ID %q already exists", a.ID)
	}
	mac := normalizeMAC(a.MAC)
	if existingID, exists := m.byMAC[mac]; exists {
		return fmt.Errorf("agent with MAC %s already exists (ID: %s)", a.MAC, existingID)
	}

	a.MAC = mac
	now := time.Now()
	a.CreatedAt = now
	a.UpdatedAt = now
	if a.Status == "" {
		a.Status = StatusNew
	}
	m.agents[a.ID] = &a
	m.byMAC[mac] = a.ID
	return nil
}

// Update updates an existing agent.
func (m *Manager) Update(a Agent) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, ok := m.agents[a.ID]
	if !ok {
		return fmt.Errorf("agent %q not found", a.ID)
	}

	// If MAC changed, update the MAC index.
	oldMAC := normalizeMAC(existing.MAC)
	newMAC := normalizeMAC(a.MAC)
	if oldMAC != newMAC {
		if existingID, exists := m.byMAC[newMAC]; exists && existingID != a.ID {
			return fmt.Errorf("MAC %s already used by agent %s", a.MAC, existingID)
		}
		delete(m.byMAC, oldMAC)
		m.byMAC[newMAC] = a.ID
	}

	a.MAC = newMAC
	a.CreatedAt = existing.CreatedAt
	a.UpdatedAt = time.Now()
	m.agents[a.ID] = &a
	return nil
}

// Delete removes an agent by ID.
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	a, ok := m.agents[id]
	if !ok {
		return fmt.Errorf("agent %q not found", id)
	}
	delete(m.byMAC, normalizeMAC(a.MAC))
	delete(m.agents, id)
	return nil
}

// Get returns an agent by ID.
func (m *Manager) Get(id string) (*Agent, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.agents[id]
	if !ok {
		return nil, false
	}
	cp := *a
	return &cp, true
}

// GetByMAC returns an agent by MAC address.
func (m *Manager) GetByMAC(mac string) (*Agent, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.byMAC[normalizeMAC(mac)]
	if !ok {
		return nil, false
	}
	a := m.agents[id]
	cp := *a
	return &cp, true
}

// List returns all agents.
func (m *Manager) List() []Agent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Agent, 0, len(m.agents))
	for _, a := range m.agents {
		out = append(out, *a)
	}
	return out
}

// SetStatus updates the status of an agent.
func (m *Manager) SetStatus(id string, status Status, msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a, ok := m.agents[id]; ok {
		a.Status = status
		a.StatusMsg = msg
		a.UpdatedAt = time.Now()
	}
}

// Count returns the total number of agents.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.agents)
}

// DefaultOSVersion returns the default version for a given OS type.
func DefaultOSVersion(os OSType) string {
	switch os {
	case OSAlpine:
		return "3.23"
	case OSDebian:
		return "13"
	case OSUbuntu:
		return "24.04"
	default:
		return ""
	}
}

// DefaultDiskDevice returns the default disk device path.
func DefaultDiskDevice() string {
	return "/dev/sda"
}

// ValidateMAC checks if a MAC address is valid.
func ValidateMAC(mac string) error {
	_, err := net.ParseMAC(mac)
	if err != nil {
		return fmt.Errorf("invalid MAC address: %w", err)
	}
	return nil
}

func normalizeMAC(mac string) string {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return strings.ToLower(mac)
	}
	return hw.String()
}
