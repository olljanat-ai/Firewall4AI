package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/olljanat-ai/firewall4ai/internal/agent"
	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/config"
	"github.com/olljanat-ai/firewall4ai/internal/database"
	"github.com/olljanat-ai/firewall4ai/internal/library"
	"github.com/olljanat-ai/firewall4ai/internal/netboot"
)

// AgentHandler serves the agent-facing API on the agent network (eth1).
// It provides policy information, CA certificates, boot files, and database
// query access to AI agents.
type AgentHandler struct {
	Approvals        *approval.Manager
	ImageApprovals   *approval.Manager
	PackageApprovals *approval.Manager
	LibraryApprovals *approval.Manager
	CACertPEM        []byte // PEM-encoded CA certificate
	AgentManager     *agent.Manager
	NetbootManager   *netboot.Manager
	DatabaseManager  *database.Manager
}

// RegisterAgentRoutes sets up the agent API routes.
func (h *AgentHandler) RegisterAgentRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/policy", h.getPolicy)
	mux.HandleFunc("GET /ca.crt", h.getCACert)

	// Special endpoint to serve the Alpine apkovl tarball for netboot installations.
	mux.HandleFunc("GET /boot/apkovl.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		data := h.NetbootManager.GenerateAlpineApkovl()
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Disposition", "attachment; filename=apkovl.tar.gz")
		w.Write(data)
	})

	// Boot endpoints for PXE netboot.
	mux.HandleFunc("GET /boot/ipxe", h.getIPXEScript)
	mux.HandleFunc("GET /boot/preseed/", h.getPreseed)
	mux.HandleFunc("GET /boot/autoinstall/", h.getAutoinstall)
	mux.HandleFunc("GET /boot/postinstall/", h.getPostInstall)
	mux.HandleFunc("GET /boot/", h.serveBootFile)

	// Database query endpoint.
	mux.HandleFunc("POST /v1/db/", h.queryDatabase)

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

// queryDatabase handles POST /v1/db/{name}/query requests from agents.
// Agents send a SQL query and receive results as JSON.
func (h *AgentHandler) queryDatabase(w http.ResponseWriter, r *http.Request) {
	if h.DatabaseManager == nil {
		http.Error(w, "Firewall4AI: database query feature not configured", http.StatusServiceUnavailable)
		return
	}

	// Parse path: /v1/db/{name}/query
	path := strings.TrimPrefix(r.URL.Path, "/v1/db/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 || parts[1] != "query" {
		http.Error(w, "Firewall4AI: invalid database query path, use /v1/db/{name}/query", http.StatusBadRequest)
		return
	}
	dbName := parts[0]
	if dbName == "" {
		http.Error(w, "Firewall4AI: database name is required", http.StatusBadRequest)
		return
	}

	// Look up the database config by API path.
	cfg, ok := h.DatabaseManager.GetByAPIPath(dbName)
	if !ok {
		http.Error(w, "Firewall4AI: database not found or not active: "+dbName, http.StatusNotFound)
		return
	}

	// Parse the query request.
	var req struct {
		Query string        `json:"query"`
		Args  []interface{} `json:"args"`
	}
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Firewall4AI: invalid request body", http.StatusBadRequest)
		return
	}

	if req.Query == "" {
		http.Error(w, "Firewall4AI: query is required", http.StatusBadRequest)
		return
	}

	// Execute the query.
	result := h.DatabaseManager.Query(cfg.ID, req.Query, req.Args)

	w.Header().Set("Content-Type", "application/json")
	if result.Error != "" {
		w.WriteHeader(http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(result)
}

func (h *AgentHandler) index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "Firewall4AI Agent API")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Endpoints:")
	fmt.Fprintln(w, "  GET  /v1/policy               - Get firewall policy (allowed/disallowed languages, packages, URLs)")
	fmt.Fprintln(w, "  POST /v1/db/{name}/query       - Execute SQL query on a configured database")
	fmt.Fprintln(w, "  GET  /ca.crt                   - Download CA certificate for HTTPS inspection")
	fmt.Fprintln(w, "  GET  /boot/ipxe?mac=XX         - iPXE boot script for agent")
	fmt.Fprintln(w, "  GET  /boot/{os}/{ver}/...       - Boot files (kernel, initrd)")
}

// --- Boot endpoints ---

// getIPXEScript serves the iPXE boot script for an agent identified by MAC.
func (h *AgentHandler) getIPXEScript(w http.ResponseWriter, r *http.Request) {
	if h.AgentManager == nil || h.NetbootManager == nil {
		http.Error(w, "netboot not configured", http.StatusServiceUnavailable)
		return
	}

	mac := r.URL.Query().Get("mac")
	if mac == "" {
		http.Error(w, "mac parameter required", http.StatusBadRequest)
		return
	}
	// Normalize MAC: iPXE sends as aa-bb-cc-dd-ee-ff, convert to aa:bb:cc:dd:ee:ff.
	mac = strings.ReplaceAll(mac, "-", ":")

	a, ok := h.AgentManager.GetByMAC(mac)
	if !ok {
		http.Error(w, "unknown agent MAC", http.StatusNotFound)
		return
	}

	// Mark agent as installing.
	h.AgentManager.SetStatus(a.ID, agent.StatusInstalling, "PXE boot in progress")

	script := h.NetbootManager.GenerateIPXEScript(a)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(script))
}

// getPreseed serves the Debian/Ubuntu preseed file for an agent.
func (h *AgentHandler) getPreseed(w http.ResponseWriter, r *http.Request) {
	if h.AgentManager == nil || h.NetbootManager == nil {
		http.Error(w, "netboot not configured", http.StatusServiceUnavailable)
		return
	}

	// Path: /boot/preseed/{agentID}
	agentID := strings.TrimPrefix(r.URL.Path, "/boot/preseed/")
	if agentID == "" {
		http.Error(w, "agent ID required", http.StatusBadRequest)
		return
	}

	a, ok := h.AgentManager.Get(agentID)
	if !ok {
		http.Error(w, "agent not found", http.StatusNotFound)
		return
	}

	preseed := h.NetbootManager.GeneratePreseed(a)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(preseed))
}

// getAutoinstall serves the Alpine answer file for an agent.
func (h *AgentHandler) getAutoinstall(w http.ResponseWriter, r *http.Request) {
	if h.AgentManager == nil || h.NetbootManager == nil {
		http.Error(w, "netboot not configured", http.StatusServiceUnavailable)
		return
	}

	// Path: /boot/autoinstall/{agentID}
	agentID := strings.TrimPrefix(r.URL.Path, "/boot/autoinstall/")
	if agentID == "" {
		http.Error(w, "agent ID required", http.StatusBadRequest)
		return
	}

	a, ok := h.AgentManager.Get(agentID)
	if !ok {
		http.Error(w, "agent not found", http.StatusNotFound)
		return
	}

	answer := h.NetbootManager.GenerateAlpineAnswerFile(a)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(answer))
}

// getPostInstall serves the post-installation script for an agent.
func (h *AgentHandler) getPostInstall(w http.ResponseWriter, r *http.Request) {
	if h.AgentManager == nil || h.NetbootManager == nil {
		http.Error(w, "netboot not configured", http.StatusServiceUnavailable)
		return
	}

	agentID := strings.TrimPrefix(r.URL.Path, "/boot/postinstall/")
	if agentID == "" {
		http.Error(w, "agent ID required", http.StatusBadRequest)
		return
	}

	a, ok := h.AgentManager.Get(agentID)
	if !ok {
		http.Error(w, "agent not found", http.StatusNotFound)
		return
	}

	script := h.NetbootManager.GeneratePostInstallScript(a)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(script))
}

// serveBootFile serves kernel/initrd files from the netboot directory.
// Path: /boot/{os}/{version}/{file}
func (h *AgentHandler) serveBootFile(w http.ResponseWriter, r *http.Request) {
	if h.NetbootManager == nil {
		http.Error(w, "netboot not configured", http.StatusServiceUnavailable)
		return
	}

	// Parse path: /boot/{os}/{version}/{file}
	path := strings.TrimPrefix(r.URL.Path, "/boot/")
	parts := strings.SplitN(path, "/", 3)
	if len(parts) != 3 {
		http.Error(w, "invalid boot path", http.StatusBadRequest)
		return
	}

	osType := parts[0]
	version := parts[1]
	file := parts[2]

	// Validate components to prevent path traversal.
	for _, part := range parts {
		if strings.Contains(part, "..") || strings.Contains(part, "/") {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
	}

	filePath := filepath.Join(h.NetbootManager.OSDir(agent.OSType(osType), version), file)
	data, err := os.ReadFile(filePath)
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}
