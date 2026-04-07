// Package approval implements the default-deny host approval system
// with three levels: global, VM-specific (by source IP), and skill-specific.
// Approvals can optionally restrict access to specific URL path prefixes.
package approval

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Status represents the approval state of a host.
type Status string

const (
	StatusPending        Status = "pending"
	StatusApproved       Status = "approved"
	StatusDenied         Status = "denied"
	StatusPendingTimeout Status = "pending_timeout" // timed out waiting for admin decision
)

// HostApproval tracks the approval state for a host at a specific level.
// Three levels exist:
//   - Global:    SkillID="" and SourceIP="" — applies to all agents on all VMs
//   - VM:        SkillID="" and SourceIP set — applies to all agents on that VM
//   - Skill:     SkillID set and SourceIP="" — applies to agents using that skill
//
// PathPrefix optionally restricts the approval to URLs matching the prefix.
// An empty PathPrefix means all paths are covered (backward compatible).
// LoggingMode controls the level of request/response detail captured in logs.
type LoggingMode string

const (
	LoggingModeNormal LoggingMode = "normal"
	LoggingModeFull   LoggingMode = "full"
)

type HostApproval struct {
	Host        string      `json:"host"`
	SkillID     string      `json:"skill_id"`
	SourceIP    string      `json:"source_ip"`
	PathPrefix  string      `json:"path_prefix,omitempty"`
	Category    string      `json:"category,omitempty"`
	LoggingMode LoggingMode `json:"logging_mode,omitempty"`
	Status      Status      `json:"status"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	Note        string      `json:"note"`
}

// key returns the unique key for a host+skill+sourceIP+pathPrefix combination.
func key(host, skillID, sourceIP, pathPrefix string) string {
	return sourceIP + "|" + skillID + "|" + host + "|" + pathPrefix
}

// MatchHost checks if a hostname matches a pattern.
// Supports exact match and wildcard patterns like *.example.com.
func MatchHost(pattern, host string) bool {
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // e.g., ".example.com"
		return strings.HasSuffix(host, suffix)
	}
	return false
}

// MatchPath checks if a request path matches an approval's path prefix.
// An empty pathPrefix matches all paths. An empty requestPath only matches
// an empty pathPrefix (used for CONNECT where path is unknown).
func MatchPath(pathPrefix, requestPath string) bool {
	if pathPrefix == "" {
		return true // no path restriction = matches everything
	}
	if requestPath == "" {
		return false // path restriction set but no path to check
	}
	return strings.HasPrefix(requestPath, pathPrefix)
}

// Manager manages host approval decisions.
type Manager struct {
	mu        sync.RWMutex
	approvals map[string]*HostApproval
	waiters   map[string][]chan Status // channels waiting for approval decision
}

// NewManager creates a new approval manager.
func NewManager() *Manager {
	return &Manager{
		approvals: make(map[string]*HostApproval),
		waiters:   make(map[string][]chan Status),
	}
}

// CheckExisting returns the current status for an exact
// host+skill+sourceIP+pathPrefix without creating a pending entry.
func (m *Manager) CheckExisting(host, skillID, sourceIP, pathPrefix string) (Status, bool) {
	k := key(host, skillID, sourceIP, pathPrefix)
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.approvals[k]
	if !ok {
		return "", false
	}
	return a.Status, true
}

// CheckExistingWithPath checks for an approval matching the host and path.
// It considers both wildcard host patterns and path prefix matching.
// An approval with empty PathPrefix covers all paths. An approval with
// a PathPrefix only covers paths starting with that prefix.
// When multiple approvals match, the most specific (longest PathPrefix) wins.
func (m *Manager) CheckExistingWithPath(host, path, skillID, sourceIP string) (Status, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var bestMatch *HostApproval
	bestLen := -1

	for _, a := range m.approvals {
		if a.SkillID != skillID || a.SourceIP != sourceIP {
			continue
		}
		if !MatchHost(a.Host, host) {
			continue
		}
		if !MatchPath(a.PathPrefix, path) {
			continue
		}
		// Longer PathPrefix = more specific match wins.
		if len(a.PathPrefix) > bestLen {
			bestMatch = a
			bestLen = len(a.PathPrefix)
		}
	}

	if bestMatch != nil {
		return bestMatch.Status, true
	}
	return "", false
}

// CheckExistingForHost checks if any non-pending approval exists for the host
// at the given skill/sourceIP level, regardless of path prefix. This is used
// for CONNECT+MITM to allow tunnels when path-specific approvals exist.
func (m *Manager) CheckExistingForHost(host, skillID, sourceIP string) (Status, bool) {
	// Try exact match with no path prefix first (fast path).
	if status, ok := m.CheckExisting(host, skillID, sourceIP, ""); ok {
		return status, true
	}
	// Scan for any matching approval regardless of path prefix.
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, a := range m.approvals {
		if a.SkillID != skillID || a.SourceIP != sourceIP {
			continue
		}
		if a.Status == StatusPending {
			continue
		}
		if MatchHost(a.Host, host) {
			return a.Status, true
		}
	}
	return "", false
}

// Check returns the current status for a host+skill+sourceIP+pathPrefix,
// or StatusPending if unknown. If the combination is new, it registers
// it as pending.
func (m *Manager) Check(host, skillID, sourceIP, pathPrefix string) Status {
	k := key(host, skillID, sourceIP, pathPrefix)
	m.mu.RLock()
	a, ok := m.approvals[k]
	m.mu.RUnlock()
	if ok {
		return a.Status
	}

	// Register as pending.
	m.mu.Lock()
	defer m.mu.Unlock()
	// Double-check after acquiring write lock.
	if a, ok := m.approvals[k]; ok {
		return a.Status
	}
	m.approvals[k] = &HostApproval{
		Host:       host,
		SkillID:    skillID,
		SourceIP:   sourceIP,
		PathPrefix: pathPrefix,
		Status:     StatusPending,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	return StatusPending
}

// WaitForDecision blocks until a decision is made for the
// host+skill+sourceIP+pathPrefix. Returns the decision status. Caller
// should first call Check to register.
func (m *Manager) WaitForDecision(host, skillID, sourceIP, pathPrefix string, timeout time.Duration) Status {
	k := key(host, skillID, sourceIP, pathPrefix)

	// Check if already decided.
	m.mu.RLock()
	if a, ok := m.approvals[k]; ok && a.Status != StatusPending {
		m.mu.RUnlock()
		return a.Status
	}
	m.mu.RUnlock()

	ch := make(chan Status, 1)
	m.mu.Lock()
	// Check again under write lock.
	if a, ok := m.approvals[k]; ok && a.Status != StatusPending {
		m.mu.Unlock()
		return a.Status
	}
	m.waiters[k] = append(m.waiters[k], ch)
	m.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case status := <-ch:
		return status
	case <-timer.C:
		return StatusPendingTimeout // timeout = still waiting for admin
	}
}

// Decide sets the approval status and notifies waiters. When a broader level
// is approved (e.g. global), it cascades notifications to narrower pending
// entries (e.g. VM-specific or skill-specific waiters for the same host).
// Path cascading: a host-only decision (empty pathPrefix) notifies all
// path-specific waiters; a path-specific decision also notifies host-only
// waiters (CONNECT tunnels) since any path approval implies host access.
func (m *Manager) Decide(host, skillID, sourceIP, pathPrefix string, status Status, note string) {
	k := key(host, skillID, sourceIP, pathPrefix)
	m.mu.Lock()
	defer m.mu.Unlock()

	a, ok := m.approvals[k]
	if !ok {
		a = &HostApproval{
			Host:       host,
			SkillID:    skillID,
			SourceIP:   sourceIP,
			PathPrefix: pathPrefix,
			CreatedAt:  time.Now(),
		}
		m.approvals[k] = a
	}
	a.Status = status
	a.UpdatedAt = time.Now()
	a.Note = note

	// Notify waiters with cascading based on approval level and path.
	isGlobal := skillID == "" && sourceIP == ""
	isVM := skillID == "" && sourceIP != ""

	for wk, waiters := range m.waiters {
		shouldNotify := false

		if wk == k {
			// Exact match — always notify.
			shouldNotify = true
		} else {
			// Parse the waiter key to check host and path matching.
			wHost, wPath := parseHostAndPath(wk)

			// Host must match (exact or wildcard).
			if !MatchHost(host, wHost) {
				continue
			}

			// Level cascading.
			levelMatch := false
			if isGlobal {
				// Global: notify all waiters for this host.
				levelMatch = true
			} else if isVM {
				// VM: notify waiters from same IP for this host.
				levelMatch = strings.HasPrefix(wk, sourceIP+"|")
			} else if skillID != "" {
				// Skill: check if waiter has same skill.
				levelMatch = waiterHasSkill(wk, skillID)
			}

			if !levelMatch {
				continue
			}

			// Path cascading.
			if pathPrefix == "" {
				// Host-only decision covers all paths.
				shouldNotify = true
			} else if wPath == "" {
				// Path-specific decision notifies host-only waiters
				// (e.g., CONNECT tunnels waiting for any host approval).
				shouldNotify = true
			} else if MatchPath(pathPrefix, wPath) {
				// Decision's path prefix covers waiter's path.
				shouldNotify = true
			}
		}

		if shouldNotify {
			for _, ch := range waiters {
				select {
				case ch <- status:
				default:
				}
			}
			delete(m.waiters, wk)
		}
	}
}

// parseHostAndPath extracts host and pathPrefix from a waiter key.
// Key format: sourceIP|skillID|host|pathPrefix
func parseHostAndPath(k string) (host, pathPrefix string) {
	parts := strings.SplitN(k, "|", 4)
	if len(parts) >= 3 {
		host = parts[2]
	}
	if len(parts) >= 4 {
		pathPrefix = parts[3]
	}
	return
}

// waiterHasSkill checks if a waiter key contains the given skillID.
// Key format: sourceIP|skillID|host|pathPrefix
func waiterHasSkill(wk, skillID string) bool {
	parts := strings.SplitN(wk, "|", 4)
	return len(parts) >= 2 && parts[1] == skillID
}

// ListPending returns all pending approvals.
func (m *Manager) ListPending() []HostApproval {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []HostApproval
	for _, a := range m.approvals {
		if a.Status == StatusPending {
			result = append(result, *a)
		}
	}
	return result
}

// ListAll returns all approvals.
func (m *Manager) ListAll() []HostApproval {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]HostApproval, 0, len(m.approvals))
	for _, a := range m.approvals {
		result = append(result, *a)
	}
	return result
}

// LoadApprovals bulk-loads approvals (used at startup).
func (m *Manager) LoadApprovals(approvals []HostApproval) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.approvals = make(map[string]*HostApproval)
	for i := range approvals {
		a := &approvals[i]
		m.approvals[key(a.Host, a.SkillID, a.SourceIP, a.PathPrefix)] = a
	}
}

// CheckExistingWithMatcher is like CheckExisting but uses a
// caller-provided match function instead of MatchHost. This allows the
// registry package to use image-reference-specific pattern matching.
func (m *Manager) CheckExistingWithMatcher(host, skillID, sourceIP string, matcher func(pattern, host string) bool) (Status, bool) {
	// Try exact match first (fast path).
	if status, ok := m.CheckExisting(host, skillID, sourceIP, ""); ok {
		return status, true
	}
	// Scan for patterns using the custom matcher.
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, a := range m.approvals {
		if a.SkillID != skillID || a.SourceIP != sourceIP {
			continue
		}
		if a.Host != host && matcher(a.Host, host) {
			return a.Status, true
		}
	}
	return "", false
}

// GetLoggingMode returns the logging mode for the best matching approval.
// It checks global, VM-specific, and skill-specific levels broadest-first,
// using the same path-matching logic as CheckExistingWithPath.
// Returns LoggingModeNormal if no matching approval is found or if the
// matched approval has no explicit logging mode set.
func (m *Manager) GetLoggingMode(host, path, skillID, sourceIP string) LoggingMode {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check levels broadest-first: global -> VM -> skill.
	levels := []struct{ sid, sip string }{
		{"", ""},
	}
	if sourceIP != "" {
		levels = append(levels, struct{ sid, sip string }{"", sourceIP})
	}
	if skillID != "" {
		levels = append(levels, struct{ sid, sip string }{skillID, ""})
	}

	for _, lvl := range levels {
		var bestMatch *HostApproval
		bestLen := -1
		for _, a := range m.approvals {
			if a.SkillID != lvl.sid || a.SourceIP != lvl.sip {
				continue
			}
			if !MatchHost(a.Host, host) {
				continue
			}
			if !MatchPath(a.PathPrefix, path) {
				continue
			}
			if len(a.PathPrefix) > bestLen {
				bestMatch = a
				bestLen = len(a.PathPrefix)
			}
		}
		if bestMatch != nil && bestMatch.LoggingMode == LoggingModeFull {
			return LoggingModeFull
		}
	}
	return LoggingModeNormal
}

// SetLoggingMode updates the logging mode for an existing approval.
func (m *Manager) SetLoggingMode(host, skillID, sourceIP, pathPrefix string, mode LoggingMode) {
	k := key(host, skillID, sourceIP, pathPrefix)
	m.mu.Lock()
	defer m.mu.Unlock()
	if a, ok := m.approvals[k]; ok {
		a.LoggingMode = mode
		a.UpdatedAt = time.Now()
	}
}

// SetCategory updates the category for an existing approval.
func (m *Manager) SetCategory(host, skillID, sourceIP, pathPrefix, category string) {
	k := key(host, skillID, sourceIP, pathPrefix)
	m.mu.Lock()
	defer m.mu.Unlock()
	if a, ok := m.approvals[k]; ok {
		a.Category = category
		a.UpdatedAt = time.Now()
	}
}

// Delete removes an approval entry.
func (m *Manager) Delete(host, skillID, sourceIP, pathPrefix string) {
	k := key(host, skillID, sourceIP, pathPrefix)
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.approvals, k)
}

// FilterParams specifies optional filters and pagination for ListFiltered.
type FilterParams struct {
	Status   string // filter by status (empty = all)
	Category string // filter by category (empty = all)
	SkillID  string // filter by skill_id (empty = all; use "_empty" for no-skill)
	SourceIP string // filter by source_ip (empty = all; use "_empty" for no-IP)
	Type     string // filter by type prefix in host field, e.g. "golang" (empty = all)
	Offset   int    // pagination offset
	Limit    int    // pagination limit (0 = default 100)
}

// FilteredResult contains a page of approvals and the total matching count.
type FilteredResult struct {
	Items []HostApproval `json:"items"`
	Total int            `json:"total"`
}

// ListFiltered returns approvals matching the given filters with pagination.
func (m *Manager) ListFiltered(p FilterParams) FilteredResult {
	if p.Limit <= 0 {
		p.Limit = 100
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Collect matching items.
	matched := make([]HostApproval, 0)
	for _, a := range m.approvals {
		if p.Status != "" && string(a.Status) != p.Status {
			continue
		}
		if p.Category != "" && a.Category != p.Category {
			continue
		}
		if p.SkillID == "_empty" {
			if a.SkillID != "" {
				continue
			}
		} else if p.SkillID != "" && a.SkillID != p.SkillID {
			continue
		}
		if p.SourceIP == "_empty" {
			if a.SourceIP != "" {
				continue
			}
		} else if p.SourceIP != "" && a.SourceIP != p.SourceIP {
			continue
		}
		if p.Type != "" {
			idx := strings.Index(a.Host, ":")
			if idx < 0 || a.Host[:idx] != p.Type {
				continue
			}
		}
		matched = append(matched, *a)
	}

	total := len(matched)

	// Sort by host for stable pagination.
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].Host < matched[j].Host
	})

	// Apply pagination.
	if p.Offset >= len(matched) {
		return FilteredResult{Items: []HostApproval{}, Total: total}
	}
	end := p.Offset + p.Limit
	if end > len(matched) {
		end = len(matched)
	}
	return FilteredResult{Items: matched[p.Offset:end], Total: total}
}

// PendingCount returns the number of pending approvals.
func (m *Manager) PendingCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := 0
	for _, a := range m.approvals {
		if a.Status == StatusPending {
			count++
		}
	}
	return count
}

// FilterMeta returns the unique values for filter dropdowns.
type FilterMeta struct {
	Categories []string `json:"categories"`
	SkillIDs   []string `json:"skill_ids"`
	SourceIPs  []string `json:"source_ips"`
	Types      []string `json:"types,omitempty"`
}

// GetFilterMeta returns unique filter values across all approvals.
func (m *Manager) GetFilterMeta() FilterMeta {
	m.mu.RLock()
	defer m.mu.RUnlock()
	catSet := make(map[string]bool)
	skillSet := make(map[string]bool)
	ipSet := make(map[string]bool)
	typeSet := make(map[string]bool)
	for _, a := range m.approvals {
		if a.Category != "" {
			catSet[a.Category] = true
		}
		if a.SkillID != "" {
			skillSet[a.SkillID] = true
		}
		if a.SourceIP != "" {
			ipSet[a.SourceIP] = true
		}
		if idx := strings.Index(a.Host, ":"); idx > 0 {
			typeSet[a.Host[:idx]] = true
		}
	}
	meta := FilterMeta{
		Categories: sortedKeys(catSet),
		SkillIDs:   sortedKeys(skillSet),
		SourceIPs:  sortedKeys(ipSet),
		Types:      sortedKeys(typeSet),
	}
	return meta
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return []string{}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Export returns all approvals for persistence.
func (m *Manager) Export() []HostApproval {
	return m.ListAll()
}
