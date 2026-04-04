package approval

import (
	"testing"
	"time"
)

func TestManager_CheckRegistersAndReturns(t *testing.T) {
	m := NewManager()

	// First check should return pending and register.
	status := m.Check("example.com", "skill-1", "", "")
	if status != StatusPending {
		t.Errorf("expected pending, got %s", status)
	}

	// Second check should still return pending.
	status = m.Check("example.com", "skill-1", "", "")
	if status != StatusPending {
		t.Errorf("expected pending on re-check, got %s", status)
	}
}

func TestManager_Decide(t *testing.T) {
	m := NewManager()
	m.Check("example.com", "skill-1", "", "")

	m.Decide("example.com", "skill-1", "", "", StatusApproved, "looks good")

	status := m.Check("example.com", "skill-1", "", "")
	if status != StatusApproved {
		t.Errorf("expected approved, got %s", status)
	}
}

func TestManager_DecideNewHost(t *testing.T) {
	m := NewManager()
	// Decide without prior Check.
	m.Decide("new.com", "skill-1", "", "", StatusDenied, "blocked")

	status := m.Check("new.com", "skill-1", "", "")
	if status != StatusDenied {
		t.Errorf("expected denied, got %s", status)
	}
}

func TestManager_WaitForDecision(t *testing.T) {
	m := NewManager()
	m.Check("example.com", "skill-1", "", "")

	// Decide in background after short delay.
	go func() {
		time.Sleep(50 * time.Millisecond)
		m.Decide("example.com", "skill-1", "", "", StatusApproved, "ok")
	}()

	status := m.WaitForDecision("example.com", "skill-1", "", "", 2*time.Second)
	if status != StatusApproved {
		t.Errorf("expected approved, got %s", status)
	}
}

func TestManager_WaitForDecisionTimeout(t *testing.T) {
	m := NewManager()
	m.Check("slow.com", "skill-1", "", "")

	status := m.WaitForDecision("slow.com", "skill-1", "", "", 50*time.Millisecond)
	if status != StatusPendingTimeout {
		t.Errorf("expected pending_timeout on timeout, got %s", status)
	}
}

func TestManager_WaitForDecisionAlreadyDecided(t *testing.T) {
	m := NewManager()
	m.Check("example.com", "skill-1", "", "")
	m.Decide("example.com", "skill-1", "", "", StatusApproved, "pre-decided")

	status := m.WaitForDecision("example.com", "skill-1", "", "", time.Second)
	if status != StatusApproved {
		t.Errorf("expected approved for already-decided, got %s", status)
	}
}

func TestManager_ListPending(t *testing.T) {
	m := NewManager()
	m.Check("a.com", "skill-1", "", "")
	m.Check("b.com", "skill-1", "", "")
	m.Decide("b.com", "skill-1", "", "", StatusApproved, "ok")

	pending := m.ListPending()
	if len(pending) != 1 {
		t.Errorf("expected 1 pending, got %d", len(pending))
	}
	if pending[0].Host != "a.com" {
		t.Errorf("expected a.com pending, got %s", pending[0].Host)
	}
}

func TestManager_ListAll(t *testing.T) {
	m := NewManager()
	m.Check("a.com", "skill-1", "", "")
	m.Check("b.com", "skill-1", "", "")

	all := m.ListAll()
	if len(all) != 2 {
		t.Errorf("expected 2 total, got %d", len(all))
	}
}

func TestManager_CheckExisting(t *testing.T) {
	m := NewManager()

	// Non-existent entry.
	_, exists := m.CheckExisting("unknown.com", "skill-1", "", "")
	if exists {
		t.Error("expected false for non-existent entry")
	}

	// Register and check.
	m.Check("example.com", "skill-1", "", "")
	status, exists := m.CheckExisting("example.com", "skill-1", "", "")
	if !exists {
		t.Fatal("expected true for existing entry")
	}
	if status != StatusPending {
		t.Errorf("expected pending, got %s", status)
	}

	// Decide and check.
	m.Decide("example.com", "skill-1", "", "", StatusApproved, "ok")
	status, exists = m.CheckExisting("example.com", "skill-1", "", "")
	if !exists || status != StatusApproved {
		t.Errorf("expected approved, got %s (exists=%v)", status, exists)
	}

	// Global approval (empty skillID and sourceIP).
	m.Decide("global.com", "", "", "", StatusApproved, "global")
	status, exists = m.CheckExisting("global.com", "", "", "")
	if !exists || status != StatusApproved {
		t.Errorf("expected global approved, got %s (exists=%v)", status, exists)
	}
}

func TestManager_VMSpecificApproval(t *testing.T) {
	m := NewManager()

	// Register pending from a specific VM.
	m.Check("api.com", "", "10.255.255.10", "")
	status, exists := m.CheckExisting("api.com", "", "10.255.255.10", "")
	if !exists || status != StatusPending {
		t.Fatalf("expected pending VM entry, got %s (exists=%v)", status, exists)
	}

	// Approve for that VM.
	m.Decide("api.com", "", "10.255.255.10", "", StatusApproved, "vm ok")
	status, exists = m.CheckExisting("api.com", "", "10.255.255.10", "")
	if !exists || status != StatusApproved {
		t.Errorf("expected VM approved, got %s", status)
	}

	// Different VM should not be approved.
	_, exists = m.CheckExisting("api.com", "", "10.255.255.11", "")
	if exists {
		t.Error("different VM should not have an approval entry")
	}
}

func TestManager_GlobalCascadesToVM(t *testing.T) {
	m := NewManager()

	// Register pending for a specific VM.
	m.Check("cascade.com", "", "10.255.255.10", "")

	// Decide globally in background.
	go func() {
		time.Sleep(50 * time.Millisecond)
		m.Decide("cascade.com", "", "", "", StatusApproved, "global cascade")
	}()

	// VM-specific waiter should be notified by global decision.
	status := m.WaitForDecision("cascade.com", "", "10.255.255.10", "", 2*time.Second)
	if status != StatusApproved {
		t.Errorf("expected global cascade to approve VM waiter, got %s", status)
	}
}

func TestManager_GlobalCascadesToSkill(t *testing.T) {
	m := NewManager()

	// Register pending for a specific skill.
	m.Check("cascade.com", "skill-1", "", "")

	// Decide globally in background.
	go func() {
		time.Sleep(50 * time.Millisecond)
		m.Decide("cascade.com", "", "", "", StatusApproved, "global cascade")
	}()

	// Skill-specific waiter should be notified by global decision.
	status := m.WaitForDecision("cascade.com", "skill-1", "", "", 2*time.Second)
	if status != StatusApproved {
		t.Errorf("expected global cascade to approve skill waiter, got %s", status)
	}
}

func TestMatchHost(t *testing.T) {
	tests := []struct {
		pattern string
		host    string
		want    bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "other.com", false},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "sub.api.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "other.com", false},
	}
	for _, tt := range tests {
		got := MatchHost(tt.pattern, tt.host)
		if got != tt.want {
			t.Errorf("MatchHost(%q, %q) = %v, want %v", tt.pattern, tt.host, got, tt.want)
		}
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		pathPrefix  string
		requestPath string
		want        bool
	}{
		{"", "/anything", true},     // empty prefix matches everything
		{"", "", true},              // empty prefix matches empty path
		{"/foo/", "/foo/bar", true}, // prefix match
		{"/foo/", "/foo/", true},    // exact prefix match
		{"/foo/", "/foobar", false}, // must match at boundary
		{"/foo/", "", false},        // path restriction but no path
		{"/org/repo", "/org/repo/x", true},
		{"/org/repo", "/org/other", false},
	}
	for _, tt := range tests {
		got := MatchPath(tt.pathPrefix, tt.requestPath)
		if got != tt.want {
			t.Errorf("MatchPath(%q, %q) = %v, want %v", tt.pathPrefix, tt.requestPath, got, tt.want)
		}
	}
}

func TestManager_WildcardApproval(t *testing.T) {
	m := NewManager()

	// Pre-approve a wildcard pattern globally.
	m.Decide("*.example.com", "", "", "", StatusApproved, "wildcard")

	// Exact match should not exist.
	_, exists := m.CheckExisting("api.example.com", "", "", "")
	if exists {
		t.Error("exact match should not exist for wildcard rule")
	}

	// Wildcard-aware check should match.
	status, exists := m.CheckExistingWithWildcards("api.example.com", "", "")
	if !exists || status != StatusApproved {
		t.Errorf("expected wildcard match approved, got %s (exists=%v)", status, exists)
	}

	// Non-matching host should not match.
	_, exists = m.CheckExistingWithWildcards("other.com", "", "")
	if exists {
		t.Error("non-matching host should not match wildcard")
	}
}

func TestManager_WildcardVMApproval(t *testing.T) {
	m := NewManager()

	// Pre-approve wildcard for a specific VM.
	m.Decide("*.github.com", "", "10.255.255.10", "", StatusApproved, "vm wildcard")

	// Should match for that VM.
	status, exists := m.CheckExistingWithWildcards("api.github.com", "", "10.255.255.10")
	if !exists || status != StatusApproved {
		t.Errorf("expected VM wildcard match, got %s (exists=%v)", status, exists)
	}

	// Should not match for different VM.
	_, exists = m.CheckExistingWithWildcards("api.github.com", "", "10.255.255.11")
	if exists {
		t.Error("wildcard should not match different VM")
	}
}

func TestManager_Delete(t *testing.T) {
	m := NewManager()
	m.Decide("example.com", "", "", "", StatusApproved, "ok")

	// Verify it exists.
	status, exists := m.CheckExisting("example.com", "", "", "")
	if !exists || status != StatusApproved {
		t.Fatalf("expected approved, got %s (exists=%v)", status, exists)
	}

	// Delete it.
	m.Delete("example.com", "", "", "")

	// Should be gone.
	_, exists = m.CheckExisting("example.com", "", "", "")
	if exists {
		t.Error("expected entry to be deleted")
	}

	// ListAll should be empty.
	if len(m.ListAll()) != 0 {
		t.Error("expected empty list after delete")
	}
}

func TestManager_LoadAndExport(t *testing.T) {
	m := NewManager()
	m.Check("a.com", "skill-1", "", "")
	m.Decide("a.com", "skill-1", "", "", StatusApproved, "ok")

	exported := m.Export()

	m2 := NewManager()
	m2.LoadApprovals(exported)

	status := m2.Check("a.com", "skill-1", "", "")
	if status != StatusApproved {
		t.Errorf("expected approved after load, got %s", status)
	}
}

// --- Path prefix tests ---

func TestManager_PathPrefixApproval(t *testing.T) {
	m := NewManager()

	// Approve a specific path prefix.
	m.Decide("github.com", "", "", "/olljanat-ai/", StatusApproved, "repo access")

	// CheckExistingWithPath should match paths starting with the prefix.
	status, exists := m.CheckExistingWithPath("github.com", "/olljanat-ai/Firewall4AI/pull/1", "", "")
	if !exists || status != StatusApproved {
		t.Errorf("expected path prefix match, got %s (exists=%v)", status, exists)
	}

	// Non-matching path should not match.
	_, exists = m.CheckExistingWithPath("github.com", "/evil-org/malware", "", "")
	if exists {
		t.Error("non-matching path should not match")
	}

	// Different host should not match.
	_, exists = m.CheckExistingWithPath("gitlab.com", "/olljanat-ai/Firewall4AI", "", "")
	if exists {
		t.Error("different host should not match")
	}
}

func TestManager_HostOnlyApprovalCoversAllPaths(t *testing.T) {
	m := NewManager()

	// Host-only approval (empty PathPrefix) covers all paths.
	m.Decide("example.com", "", "", "", StatusApproved, "all paths")

	status, exists := m.CheckExistingWithPath("example.com", "/any/path", "", "")
	if !exists || status != StatusApproved {
		t.Errorf("host-only approval should cover all paths, got %s (exists=%v)", status, exists)
	}

	status, exists = m.CheckExistingWithPath("example.com", "/another/path", "", "")
	if !exists || status != StatusApproved {
		t.Errorf("host-only approval should cover all paths, got %s (exists=%v)", status, exists)
	}
}

func TestManager_PathPrefixWithWildcardHost(t *testing.T) {
	m := NewManager()

	// Wildcard host + path prefix.
	m.Decide("*.github.com", "", "", "/olljanat-ai/", StatusApproved, "wildcard + path")

	status, exists := m.CheckExistingWithPath("api.github.com", "/olljanat-ai/repo", "", "")
	if !exists || status != StatusApproved {
		t.Errorf("expected wildcard+path match, got %s (exists=%v)", status, exists)
	}

	// Non-matching path on matching host.
	_, exists = m.CheckExistingWithPath("api.github.com", "/other/path", "", "")
	if exists {
		t.Error("non-matching path should not match even with wildcard host")
	}
}

func TestManager_CheckExistingForHost(t *testing.T) {
	m := NewManager()

	// No approvals.
	_, exists := m.CheckExistingForHost("github.com", "", "")
	if exists {
		t.Error("expected false with no approvals")
	}

	// Add path-specific approval.
	m.Decide("github.com", "", "", "/olljanat-ai/", StatusApproved, "path only")

	// CheckExistingForHost should find it even though there's no host-only approval.
	status, exists := m.CheckExistingForHost("github.com", "", "")
	if !exists || status != StatusApproved {
		t.Errorf("expected to find path-specific approval for host, got %s (exists=%v)", status, exists)
	}

	// Pending entries should be skipped.
	m2 := NewManager()
	m2.Check("example.com", "", "", "/some/path")
	_, exists = m2.CheckExistingForHost("example.com", "", "")
	if exists {
		t.Error("pending entries should be skipped by CheckExistingForHost")
	}
}

func TestManager_PathCascadesToHostWaiter(t *testing.T) {
	m := NewManager()

	// Register pending for host (no path) — simulates CONNECT waiter.
	m.Check("github.com", "", "", "")

	// Decide with path prefix in background.
	go func() {
		time.Sleep(50 * time.Millisecond)
		m.Decide("github.com", "", "", "/olljanat-ai/", StatusApproved, "path approval")
	}()

	// Host-only waiter should be notified by path-specific decision.
	status := m.WaitForDecision("github.com", "", "", "", 2*time.Second)
	if status != StatusApproved {
		t.Errorf("expected path decision to cascade to host waiter, got %s", status)
	}
}

func TestManager_HostDecisionCascadesToPathWaiters(t *testing.T) {
	m := NewManager()

	// Register pending with specific path.
	m.Check("github.com", "", "", "/olljanat-ai/repo/file.go")

	// Decide at host level (empty path = all paths) in background.
	go func() {
		time.Sleep(50 * time.Millisecond)
		m.Decide("github.com", "", "", "", StatusApproved, "all paths")
	}()

	// Path-specific waiter should be notified by host-only decision.
	status := m.WaitForDecision("github.com", "", "", "/olljanat-ai/repo/file.go", 2*time.Second)
	if status != StatusApproved {
		t.Errorf("expected host decision to cascade to path waiter, got %s", status)
	}
}

func TestManager_PathPrefixPersistence(t *testing.T) {
	m := NewManager()
	m.Decide("github.com", "", "", "/olljanat-ai/", StatusApproved, "repo")
	m.Decide("github.com", "", "", "", StatusDenied, "deny all else")

	exported := m.Export()

	m2 := NewManager()
	m2.LoadApprovals(exported)

	// Path-specific should be preserved.
	status, exists := m2.CheckExistingWithPath("github.com", "/olljanat-ai/repo", "", "")
	if !exists || status != StatusApproved {
		t.Errorf("expected path-specific approval after load, got %s (exists=%v)", status, exists)
	}

	// Host-only should be preserved.
	status, exists = m2.CheckExisting("github.com", "", "", "")
	if !exists || status != StatusDenied {
		t.Errorf("expected host-only denial after load, got %s (exists=%v)", status, exists)
	}
}
