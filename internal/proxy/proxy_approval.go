// proxy_approval.go contains the three-level approval logic used by the proxy
// to check whether a host+path combination is approved for a given skill and VM.

package proxy

import (
	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/auth"
)

// checkApproval verifies the host+path is approved using three levels:
//  1. Global (skillID="" and sourceIP="") — applies to all agents on all VMs
//  2. VM-specific (skillID="" and sourceIP set) — applies to all agents on that VM
//  3. Skill-specific (skillID set) — applies to agents using that skill
//
// Checks are performed broadest-first. If no existing decision is found,
// a pending entry is registered at the most specific applicable level.
// The path parameter enables fine-grained URL path approval; empty path
// means host-level only (used for blind CONNECT tunnels).
func (p *Proxy) checkApproval(host, path string, skill *auth.Skill, sourceIP string) approval.Status {
	// 1. Check global approval (host+path approved/denied for all agents).
	if globalStatus, exists := p.Approvals.CheckExistingWithPath(host, path, "", ""); exists && globalStatus != approval.StatusPending {
		return globalStatus
	}

	// 2. Check VM-specific approval.
	if sourceIP != "" {
		if vmStatus, exists := p.Approvals.CheckExistingWithPath(host, path, "", sourceIP); exists && vmStatus != approval.StatusPending {
			return vmStatus
		}
	}

	// 3. Check skill-specific approval.
	if skill != nil {
		if skillStatus, exists := p.Approvals.CheckExistingWithPath(host, path, skill.ID, ""); exists && skillStatus != approval.StatusPending {
			return skillStatus
		}
	}

	// No decision found. Register as pending at the most specific level.
	sid := getSkillID(skill)
	pendingIP := sourceIP
	if sid != "" {
		pendingIP = ""
	}
	status := p.Approvals.Check(host, sid, pendingIP, path)
	if status == approval.StatusPending {
		if p.LearningMode {
			return approval.StatusApproved
		}
		status = p.Approvals.WaitForDecision(host, sid, pendingIP, path, p.ApprovalTimeout)
	}
	return status
}

// checkHostApproval checks if any approval (host-only or path-specific)
// exists for the host. Used for CONNECT+MITM where the tunnel must be
// allowed if any path-specific approval exists, since per-request checks
// will enforce path restrictions inside the tunnel.
func (p *Proxy) checkHostApproval(host string, skill *auth.Skill, sourceIP string) approval.Status {
	// 1. Global: any approval for this host.
	if status, exists := p.Approvals.CheckExistingForHost(host, "", ""); exists && status != approval.StatusPending {
		return status
	}

	// 2. VM-specific.
	if sourceIP != "" {
		if status, exists := p.Approvals.CheckExistingForHost(host, "", sourceIP); exists && status != approval.StatusPending {
			return status
		}
	}

	// 3. Skill-specific.
	if skill != nil {
		if status, exists := p.Approvals.CheckExistingForHost(host, skill.ID, ""); exists && status != approval.StatusPending {
			return status
		}
	}

	// No approval found. Register pending at host level (no path) and wait.
	sid := getSkillID(skill)
	pendingIP := sourceIP
	if sid != "" {
		pendingIP = ""
	}
	status := p.Approvals.Check(host, sid, pendingIP, "")
	if status == approval.StatusPending {
		if p.LearningMode {
			return approval.StatusApproved
		}
		status = p.Approvals.WaitForDecision(host, sid, pendingIP, "", p.ApprovalTimeout)
	}
	return status
}

// checkRefApproval performs the standard three-level approval check
// (global → VM-specific → skill-specific) for a named ref such as a
// container image, Helm chart, or code library. The matcher function
// allows caller-defined wildcard or prefix pattern matching.
// This consolidates the formerly duplicated logic in checkImageApproval,
// checkHelmChartApproval, and checkLibraryApproval.
func (p *Proxy) checkRefApproval(mgr *approval.Manager, ref string, skill *auth.Skill, sourceIP string, matcher func(pattern, ref string) bool) approval.Status {
	sid := getSkillID(skill)

	// 1. Global.
	if status, ok := mgr.CheckExistingWithMatcher(ref, "", "", matcher); ok && status != approval.StatusPending {
		return status
	}
	// 2. VM-specific.
	if sourceIP != "" {
		if status, ok := mgr.CheckExistingWithMatcher(ref, "", sourceIP, matcher); ok && status != approval.StatusPending {
			return status
		}
	}
	// 3. Skill-specific.
	if sid != "" {
		if status, ok := mgr.CheckExistingWithMatcher(ref, sid, "", matcher); ok && status != approval.StatusPending {
			return status
		}
	}

	// Register pending at most specific level and wait.
	pendingIP := sourceIP
	if sid != "" {
		pendingIP = ""
	}
	status := mgr.Check(ref, sid, pendingIP, "")
	if status == approval.StatusPending {
		if p.LearningMode {
			return approval.StatusApproved
		}
		return mgr.WaitForDecision(ref, sid, pendingIP, "", p.ApprovalTimeout)
	}
	return status
}
