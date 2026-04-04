// Package credentials manages credential injection for outgoing proxy requests.
package credentials

import (
	"net/http"
	"strings"
	"sync"
)

// InjectionType defines how credentials are injected.
type InjectionType string

const (
	InjectHeader InjectionType = "header"
	InjectBasic  InjectionType = "basic_auth"
	InjectBearer InjectionType = "bearer"
	InjectQuery  InjectionType = "query_param"
)

// Credential represents a credential to inject for a specific host pattern.
type Credential struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	HostPattern   string        `json:"host_pattern"` // exact host or wildcard like *.example.com
	SourceIP      string        `json:"source_ip"`    // empty means global (all VMs), set means VM-specific
	InjectionType InjectionType `json:"injection_type"`
	HeaderName    string        `json:"header_name,omitempty"`  // for header type
	HeaderValue   string        `json:"header_value,omitempty"` // for header type
	Username      string        `json:"username,omitempty"`     // for basic_auth
	Password      string        `json:"password,omitempty"`     // for basic_auth
	Token         string        `json:"token,omitempty"`        // for bearer
	ParamName     string        `json:"param_name,omitempty"`   // for query_param
	ParamValue    string        `json:"param_value,omitempty"`  // for query_param
	Active        bool          `json:"active"`
}

// Manager manages credentials and injects them into outgoing requests.
type Manager struct {
	mu    sync.RWMutex
	creds map[string]*Credential // keyed by ID
}

// NewManager creates a new credential manager.
func NewManager() *Manager {
	return &Manager{
		creds: make(map[string]*Credential),
	}
}

// Add registers a new credential.
func (m *Manager) Add(c Credential) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.creds[c.ID] = &c
}

// Get returns a credential by ID.
func (m *Manager) Get(id string) (*Credential, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.creds[id]
	if !ok {
		return nil, false
	}
	cp := *c
	return &cp, true
}

// Update replaces a credential by ID.
func (m *Manager) Update(c Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.creds[c.ID] = &c
	return nil
}

// Delete removes a credential by ID.
func (m *Manager) Delete(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.creds, id)
}

// List returns all credentials.
func (m *Manager) List() []Credential {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]Credential, 0, len(m.creds))
	for _, c := range m.creds {
		result = append(result, *c)
	}
	return result
}

// matchHost checks if a host matches the credential's pattern.
func matchHost(pattern, host string) bool {
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // e.g., ".example.com"
		return strings.HasSuffix(host, suffix)
	}
	return false
}

// InjectForRequest applies matching credentials to an HTTP request.
// sourceIP is the client VM's IP address for VM-specific credential matching.
func (m *Manager) InjectForRequest(req *http.Request, sourceIP string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	// Strip port if present.
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}

	for _, c := range m.creds {
		if !c.Active {
			continue
		}
		// Global credentials (SourceIP="") apply to all VMs.
		// VM-specific credentials only apply when source IP matches.
		if c.SourceIP != "" && c.SourceIP != sourceIP {
			continue
		}
		if !matchHost(c.HostPattern, host) {
			continue
		}
		m.apply(req, c)
	}
}

func (m *Manager) apply(req *http.Request, c *Credential) {
	switch c.InjectionType {
	case InjectHeader:
		req.Header.Set(c.HeaderName, c.HeaderValue)
	case InjectBasic:
		req.SetBasicAuth(c.Username, c.Password)
	case InjectBearer:
		req.Header.Set("Authorization", "Bearer "+c.Token)
	case InjectQuery:
		q := req.URL.Query()
		q.Set(c.ParamName, c.ParamValue)
		req.URL.RawQuery = q.Encode()
	}
}

// LoadCredentials bulk-loads credentials (used at startup).
func (m *Manager) LoadCredentials(creds []Credential) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.creds = make(map[string]*Credential)
	for i := range creds {
		m.creds[creds[i].ID] = &creds[i]
	}
}
