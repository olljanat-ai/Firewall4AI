package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/olljanat-ai/firewall4ai/internal/agent"
	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/auth"
	"github.com/olljanat-ai/firewall4ai/internal/config"
	"github.com/olljanat-ai/firewall4ai/internal/database"
	"github.com/olljanat-ai/firewall4ai/internal/image"
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
	Skills           *auth.SkillStore
	CACertPEM        []byte // PEM-encoded CA certificate
	AgentManager     *agent.Manager
	NetbootManager   *netboot.Manager
	ImageManager     *image.Manager
	DatabaseManager  *database.Manager
}

// RegisterAgentRoutes sets up the agent API routes.
func (h *AgentHandler) RegisterAgentRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/policy", h.getPolicy)
	mux.HandleFunc("GET /v1/skills", h.getSkills)
	mux.HandleFunc("GET /ca.crt", h.getCACert)

	// Deploy boot endpoints.
	mux.HandleFunc("GET /boot/deploy/apkovl.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		data := h.NetbootManager.GenerateDeployApkovl()
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Disposition", "attachment; filename=apkovl.tar.gz")
		w.Write(data)
	})
	mux.HandleFunc("GET /boot/ipxe", h.getIPXEScript)
	mux.HandleFunc("GET /boot/deploy-info/", h.getDeployInfo)
	mux.HandleFunc("GET /boot/status/", h.setBootStatus)
	mux.HandleFunc("GET /boot/deploy/", h.serveDeployFile)

	// Image file serving.
	mux.HandleFunc("GET /images/", h.serveImageFile)

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

// agentSkill describes a skill allocated to an agent in the API response.
type agentSkill struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Token       string `json:"token"`
}

func (h *AgentHandler) getSkills(w http.ResponseWriter, r *http.Request) {
	if h.AgentManager == nil || h.Skills == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]agentSkill{})
		return
	}

	// Identify the calling agent by source IP.
	sourceIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		sourceIP = host
	}

	ag, ok := h.AgentManager.GetByIP(sourceIP)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]agentSkill{})
		return
	}

	var skills []agentSkill
	for _, sid := range ag.SkillIDs {
		sk, ok := h.Skills.GetSkill(sid)
		if !ok || !sk.Active {
			continue
		}
		skills = append(skills, agentSkill{
			ID:          sk.ID,
			Name:        sk.Name,
			Description: sk.Description,
			Token:       sk.Token,
		})
	}
	if skills == nil {
		skills = []agentSkill{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(skills)
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

	// Extract source IP for VM-specific filtering.
	sourceIP := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		sourceIP = h
	}

	cfg, ok := h.DatabaseManager.GetByAPIPath(dbName, sourceIP)
	if !ok {
		http.Error(w, "Firewall4AI: database not found or not active: "+dbName, http.StatusNotFound)
		return
	}

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
	fmt.Fprintln(w, "  GET  /v1/policy               - Get firewall policy")
	fmt.Fprintln(w, "  GET  /v1/skills               - Get allocated skills")
	fmt.Fprintln(w, "  POST /v1/db/{name}/query       - Execute SQL query")
	fmt.Fprintln(w, "  GET  /ca.crt                   - Download CA certificate")
	fmt.Fprintln(w, "  GET  /boot/ipxe?mac=XX         - iPXE boot script for deploy")
	fmt.Fprintln(w, "  GET  /boot/deploy/...           - Deploy boot files")
	fmt.Fprintln(w, "  GET  /images/{id}/{ver}/...     - Image files")
}

// --- Boot endpoints ---

// getIPXEScript serves the iPXE boot script for an agent identified by MAC.
func (h *AgentHandler) getIPXEScript(w http.ResponseWriter, r *http.Request) {
	if h.AgentManager == nil || h.NetbootManager == nil || h.ImageManager == nil {
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

	img, ok := h.ImageManager.Get(a.ImageID)
	if !ok {
		http.Error(w, "image not found for agent", http.StatusNotFound)
		return
	}

	// Determine which version to deploy.
	ver := a.ImageVersion
	if ver == 0 {
		ver = img.LatestReadyVersion()
	}
	if ver == 0 {
		http.Error(w, "no ready image version available", http.StatusNotFound)
		return
	}

	if !h.NetbootManager.HasImageBootFiles(a.ImageID, ver) {
		http.Error(w, "image boot files not ready", http.StatusNotFound)
		return
	}

	// Mark agent as deploying.
	h.AgentManager.SetStatus(a.ID, agent.StatusDeploying, "PXE boot in progress")

	script := h.NetbootManager.GenerateDeployIPXEScript(netboot.DeployBootInfo{
		AgentID:      a.ID,
		ImageID:      a.ImageID,
		ImageVersion: ver,
		OSType:       img.OS,
		OSVersion:    img.OSVersion,
	})
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(script))
}

// getDeployInfo returns deployment information for an agent.
// Path: /boot/deploy-info/{agentID}
func (h *AgentHandler) getDeployInfo(w http.ResponseWriter, r *http.Request) {
	if h.AgentManager == nil || h.ImageManager == nil {
		http.Error(w, "not configured", http.StatusServiceUnavailable)
		return
	}

	agentID := strings.TrimPrefix(r.URL.Path, "/boot/deploy-info/")
	if agentID == "" {
		http.Error(w, "agent ID required", http.StatusBadRequest)
		return
	}

	a, ok := h.AgentManager.Get(agentID)
	if !ok {
		http.Error(w, "agent not found", http.StatusNotFound)
		return
	}

	img, ok := h.ImageManager.Get(a.ImageID)
	if !ok {
		http.Error(w, "image not found for agent", http.StatusNotFound)
		return
	}

	// Determine which version to deploy.
	ver := a.ImageVersion
	if ver == 0 {
		ver = img.LatestReadyVersion()
	}
	if ver == 0 {
		http.Error(w, "no ready image version available", http.StatusNotFound)
		return
	}

	disk := a.DiskDevice
	if disk == "" {
		disk = agent.DefaultDiskDevice()
	}

	imageURL := fmt.Sprintf("http://%s/images/%s/%d/rootfs.tar.gz",
		h.NetbootManager.ServerIP, a.ImageID, ver)

	// Return simple key=value format (easy to parse in shell).
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "disk=%s\n", disk)
	fmt.Fprintf(w, "image_url=%s\n", imageURL)
	fmt.Fprintf(w, "hostname=%s\n", a.Hostname)
	fmt.Fprintf(w, "agent_id=%s\n", a.ID)
	fmt.Fprintf(w, "os_type=%s\n", img.OS)
}

// setBootStatus handles status updates from the deploy script.
// Path: /boot/status/{agentID}?status=deploying|installed|error&msg=...
func (h *AgentHandler) setBootStatus(w http.ResponseWriter, r *http.Request) {
	if h.AgentManager == nil {
		http.Error(w, "not configured", http.StatusServiceUnavailable)
		return
	}

	agentID := strings.TrimPrefix(r.URL.Path, "/boot/status/")
	if agentID == "" {
		http.Error(w, "agent ID required", http.StatusBadRequest)
		return
	}

	status := r.URL.Query().Get("status")
	msg := r.URL.Query().Get("msg")

	switch status {
	case "deploying":
		h.AgentManager.SetStatus(agentID, agent.StatusDeploying, "deploying image to disk")
	case "installed":
		h.AgentManager.SetStatus(agentID, agent.StatusInstalled, "deployment complete")
	case "error":
		h.AgentManager.SetStatus(agentID, agent.StatusError, msg)
	default:
		http.Error(w, "invalid status", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// serveDeployFile serves deploy boot files (kernel, initrd).
// Path: /boot/deploy/{file}
func (h *AgentHandler) serveDeployFile(w http.ResponseWriter, r *http.Request) {
	if h.NetbootManager == nil {
		http.Error(w, "netboot not configured", http.StatusServiceUnavailable)
		return
	}

	file := strings.TrimPrefix(r.URL.Path, "/boot/deploy/")
	if file == "" || strings.Contains(file, "..") || strings.Contains(file, "/") {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join(h.NetbootManager.DeployDir(), file)
	data, err := os.ReadFile(filePath)
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

// serveImageFile serves image rootfs files.
// Path: /images/{imageID}/{version}/rootfs.tar.gz
func (h *AgentHandler) serveImageFile(w http.ResponseWriter, r *http.Request) {
	if h.ImageManager == nil {
		http.Error(w, "not configured", http.StatusServiceUnavailable)
		return
	}

	// Parse: /images/{id}/{version}/{file}
	path := strings.TrimPrefix(r.URL.Path, "/images/")
	parts := strings.SplitN(path, "/", 3)
	if len(parts) != 3 {
		http.Error(w, "invalid image path", http.StatusBadRequest)
		return
	}

	for _, part := range parts {
		if strings.Contains(part, "..") {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
	}

	filePath := filepath.Join(h.ImageManager.ImagesDir(), parts[0], parts[1], parts[2])
	f, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		http.Error(w, "file error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))
	http.ServeContent(w, r, parts[2], stat.ModTime(), f)
}
