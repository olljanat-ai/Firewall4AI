package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/config"
	"github.com/olljanat-ai/firewall4ai/internal/library"
)

// AgentHandler serves the agent-facing API on the agent network (eth1).
// It provides policy information and CA certificates to AI agents.
type AgentHandler struct {
	Approvals        *approval.Manager
	ImageApprovals   *approval.Manager
	PackageApprovals *approval.Manager
	LibraryApprovals *approval.Manager
	CACertPEM        []byte // PEM-encoded CA certificate
}

// RegisterAgentRoutes sets up the agent API routes.
func (h *AgentHandler) RegisterAgentRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/policy", h.getPolicy)
	mux.HandleFunc("GET /ca.crt", h.getCACert)
	mux.HandleFunc("GET /", h.index)
}

// policyLanguage describes a programming language/code library type in the policy.
type policyLanguage struct {
	Type     string   `json:"type"`
	Name     string   `json:"name"`
	Enabled  bool     `json:"enabled"`
	Approved []string `json:"approved,omitempty"`
}

// policyDistro describes an OS distro/package type in the policy.
type policyDistro struct {
	Type     string   `json:"type"`
	Name     string   `json:"name"`
	Enabled  bool     `json:"enabled"`
	Approved []string `json:"approved,omitempty"`
}

// policyResponse is the JSON response for the /v1/policy endpoint.
type policyResponse struct {
	LearningMode bool             `json:"learning_mode"`
	Languages    []policyLanguage `json:"languages"`
	OSDistros    []policyDistro   `json:"os_distros"`
	URLs         []policyURL      `json:"urls"`
}

// policyURL describes an approved/denied URL rule.
type policyURL struct {
	Host       string `json:"host"`
	PathPrefix string `json:"path_prefix,omitempty"`
	Status     string `json:"status"`
}

func (h *AgentHandler) getPolicy(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()

	// Build languages list from configured code libraries.
	seen := make(map[string]bool)
	var languages []policyLanguage
	for _, lib := range cfg.CodeLibraries {
		if seen[lib.Type] {
			continue
		}
		seen[lib.Type] = true
		lang := policyLanguage{
			Type:    lib.Type,
			Name:    library.TypeLabel(library.PackageType(lib.Type)),
			Enabled: !config.IsLanguageDisabled(lib.Type),
		}
		if lang.Enabled {
			lang.Approved = collectApproved(h.LibraryApprovals, lib.Type+":")
		}
		languages = append(languages, lang)
	}

	// Build OS distros list from configured OS packages.
	seen = make(map[string]bool)
	var distros []policyDistro
	for _, pkg := range cfg.OSPackages {
		if seen[pkg.Type] {
			continue
		}
		seen[pkg.Type] = true
		distro := policyDistro{
			Type:    pkg.Type,
			Name:    library.TypeLabel(library.PackageType(pkg.Type)),
			Enabled: !config.IsDistroDisabled(pkg.Type),
		}
		if distro.Enabled {
			distro.Approved = collectApproved(h.PackageApprovals, pkg.Type+":")
		}
		distros = append(distros, distro)
	}

	// Build URL approvals list (global only, non-pending).
	var urls []policyURL
	for _, a := range h.Approvals.ListAll() {
		if a.SkillID != "" || a.SourceIP != "" {
			continue // only global approvals
		}
		if a.Status == approval.StatusPending {
			continue
		}
		urls = append(urls, policyURL{
			Host:       a.Host,
			PathPrefix: a.PathPrefix,
			Status:     string(a.Status),
		})
	}

	resp := policyResponse{
		LearningMode: cfg.LearningMode,
		Languages:    languages,
		OSDistros:    distros,
		URLs:         urls,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// collectApproved returns the list of approved package names for a given type prefix.
func collectApproved(mgr *approval.Manager, typePrefix string) []string {
	var approved []string
	for _, a := range mgr.ListAll() {
		if a.Status != approval.StatusApproved {
			continue
		}
		if a.SkillID != "" || a.SourceIP != "" {
			continue // only global approvals
		}
		// Host field contains "type:name", strip the type prefix.
		if len(a.Host) > len(typePrefix) && a.Host[:len(typePrefix)] == typePrefix {
			approved = append(approved, a.Host[len(typePrefix):])
		}
	}
	return approved
}

func (h *AgentHandler) getCACert(w http.ResponseWriter, r *http.Request) {
	if len(h.CACertPEM) == 0 {
		http.Error(w, "CA certificate not available", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=firewall4ai-ca.crt")
	w.Write(h.CACertPEM)
}

func (h *AgentHandler) index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "Firewall4AI Agent API")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Endpoints:")
	fmt.Fprintln(w, "  GET /v1/policy  - Get firewall policy (allowed/disallowed languages, packages, URLs)")
	fmt.Fprintln(w, "  GET /ca.crt     - Download CA certificate for HTTPS inspection")
}
