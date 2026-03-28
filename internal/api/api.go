// Package api provides the admin REST API for managing the proxy.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/olljanat-ai/firewall4ai/internal/agent"
	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/auth"
	"github.com/olljanat-ai/firewall4ai/internal/config"
	"github.com/olljanat-ai/firewall4ai/internal/credentials"
	"github.com/olljanat-ai/firewall4ai/internal/database"
	"github.com/olljanat-ai/firewall4ai/internal/image"
	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
)

// Handler holds dependencies for API endpoints.
type Handler struct {
	Skills           *auth.SkillStore
	Approvals        *approval.Manager
	ImageApprovals   *approval.Manager // image-level approvals for container registry
	PackageApprovals *approval.Manager // OS package approvals (e.g., Debian)
	LibraryApprovals *approval.Manager // code library approvals (e.g., Go, npm, PyPI, NuGet)
	Credentials      *credentials.Manager
	Logger           *proxylog.Logger
	SaveFunc               func() error    // called after state mutations to persist
	SetLearningModeFunc    func(bool)      // called to update learning mode on the proxy
	SetDisabledLanguagesFunc func([]string) // called to update disabled languages
	SetDisabledDistrosFunc   func([]string) // called to update disabled distros
	Version                string          // build version string

	// Database management.
	DatabaseManager   *database.Manager

	// Image management.
	ImageManager      *image.Manager
	BuildImage        func(img *image.DiskImage, version int) // called to build an image version

	// Agent management.
	AgentManager      *agent.Manager
	OnAgentChange     func(a *agent.Agent) // called when agent is created/updated
	OnAgentDelete     func(a *agent.Agent) // called when agent is deleted
	GetLeaseIP        func(mac string) string // returns DHCP lease IP for a MAC address

	catMu      sync.RWMutex
	categories []string

	// Global VM settings.
	vmSettingsMu     sync.RWMutex
	keyboard         string   // keyboard layout, e.g. "us", "fi"
	timezone         string   // timezone, e.g. "UTC", "Europe/Helsinki"
	sshAuthorizedKeys []string // SSH public keys for root login on all agent VMs
}

// RegisterRoutes sets up all API routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Approvals
	mux.HandleFunc("GET /api/approvals", h.listApprovals)
	mux.HandleFunc("GET /api/approvals/pending", h.listPending)
	mux.HandleFunc("POST /api/approvals/decide", h.decideApproval)
	mux.HandleFunc("PUT /api/approvals/category", h.setApprovalCategory)
	mux.HandleFunc("GET /api/approvals/meta", h.approvalMeta)
	mux.HandleFunc("DELETE /api/approvals", h.deleteApproval)

	// Skills
	mux.HandleFunc("GET /api/skills", h.listSkills)
	mux.HandleFunc("POST /api/skills", h.createSkill)
	mux.HandleFunc("PUT /api/skills", h.updateSkill)
	mux.HandleFunc("DELETE /api/skills", h.deleteSkill)

	// Credentials
	mux.HandleFunc("GET /api/credentials", h.listCredentials)
	mux.HandleFunc("POST /api/credentials", h.createCredential)
	mux.HandleFunc("PUT /api/credentials", h.updateCredential)
	mux.HandleFunc("DELETE /api/credentials", h.deleteCredential)

	// Database connections
	mux.HandleFunc("GET /api/databases", h.listDatabases)
	mux.HandleFunc("POST /api/databases", h.createDatabase)
	mux.HandleFunc("PUT /api/databases", h.updateDatabase)
	mux.HandleFunc("DELETE /api/databases", h.deleteDatabase)

	// Image Approvals (container registry)
	mux.HandleFunc("GET /api/images", h.listImageApprovals)
	mux.HandleFunc("GET /api/images/pending", h.listPendingImages)
	mux.HandleFunc("POST /api/images/decide", h.decideImageApproval)
	mux.HandleFunc("PUT /api/images/category", h.setImageCategory)
	mux.HandleFunc("GET /api/images/meta", h.imageMeta)
	mux.HandleFunc("DELETE /api/images", h.deleteImageApproval)

	// OS Package Approvals (e.g., Debian)
	mux.HandleFunc("GET /api/packages", h.listPackageApprovals)
	mux.HandleFunc("GET /api/packages/pending", h.listPendingPackages)
	mux.HandleFunc("POST /api/packages/decide", h.decidePackageApproval)
	mux.HandleFunc("PUT /api/packages/category", h.setPackageCategory)
	mux.HandleFunc("GET /api/packages/meta", h.packageMeta)
	mux.HandleFunc("DELETE /api/packages", h.deletePackageApproval)

	// Code Library Approvals (Go, npm, PyPI, NuGet)
	mux.HandleFunc("GET /api/libraries", h.listLibraryApprovals)
	mux.HandleFunc("GET /api/libraries/pending", h.listPendingLibraries)
	mux.HandleFunc("POST /api/libraries/decide", h.decideLibraryApproval)
	mux.HandleFunc("PUT /api/libraries/category", h.setLibraryCategory)
	mux.HandleFunc("GET /api/libraries/meta", h.libraryMeta)
	mux.HandleFunc("DELETE /api/libraries", h.deleteLibraryApproval)

	// Pending counts (lightweight polling endpoint)
	mux.HandleFunc("GET /api/pending-counts", h.getPendingCounts)

	// Logs
	mux.HandleFunc("GET /api/logs", h.getLogs)
	mux.HandleFunc("GET /api/logs/stats", h.getLogStats)
	mux.HandleFunc("GET /api/logs/detail", h.getLogDetail)

	// Health
	mux.HandleFunc("GET /api/health", h.health)

	// Categories
	mux.HandleFunc("GET /api/categories", h.listCategories)
	mux.HandleFunc("POST /api/categories", h.addCategory)
	mux.HandleFunc("DELETE /api/categories", h.deleteCategory)

	// Version
	mux.HandleFunc("GET /api/version", h.getVersion)

	// System settings
	mux.HandleFunc("GET /api/settings/ssh", h.getSSHStatus)
	mux.HandleFunc("POST /api/settings/ssh", h.setSSHStatus)
	mux.HandleFunc("GET /api/settings/learning-mode", h.getLearningMode)
	mux.HandleFunc("POST /api/settings/learning-mode", h.setLearningMode)
	mux.HandleFunc("GET /api/settings/languages", h.getDisabledLanguages)
	mux.HandleFunc("POST /api/settings/languages", h.setDisabledLanguages)
	mux.HandleFunc("GET /api/settings/distros", h.getDisabledDistros)
	mux.HandleFunc("POST /api/settings/distros", h.setDisabledDistros)
	mux.HandleFunc("GET /api/settings/vm-settings", h.getVMSettings)
	mux.HandleFunc("POST /api/settings/vm-settings", h.setVMSettings)
	mux.HandleFunc("GET /api/system/logs", h.systemLogs)
	mux.HandleFunc("POST /api/system/upgrade", h.systemUpgrade)
	mux.HandleFunc("POST /api/system/reboot", h.systemReboot)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

// --- Approvals ---

// parseFilterParams extracts common filter and pagination query parameters.
func parseFilterParams(r *http.Request) approval.FilterParams {
	p := approval.FilterParams{
		Status:   r.URL.Query().Get("status"),
		Category: r.URL.Query().Get("category"),
		SkillID:  r.URL.Query().Get("skill_id"),
		SourceIP: r.URL.Query().Get("source_ip"),
		Type:     r.URL.Query().Get("type"),
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			p.Offset = n
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			p.Limit = n
		}
	}
	return p
}

func (h *Handler) listApprovals(w http.ResponseWriter, r *http.Request) {
	// If any filter/pagination params are present, use filtered endpoint.
	if r.URL.Query().Has("limit") || r.URL.Query().Has("offset") ||
		r.URL.Query().Has("status") || r.URL.Query().Has("category") ||
		r.URL.Query().Has("skill_id") || r.URL.Query().Has("source_ip") {
		p := parseFilterParams(r)
		writeJSON(w, http.StatusOK, h.Approvals.ListFiltered(p))
		return
	}
	writeJSON(w, http.StatusOK, h.Approvals.ListAll())
}

func (h *Handler) listPending(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.Approvals.ListPending())
}

func (h *Handler) approvalMeta(w http.ResponseWriter, r *http.Request) {
	meta := h.Approvals.GetFilterMeta()
	meta.Categories = h.ListCategoriesSlice()
	writeJSON(w, http.StatusOK, meta)
}

func (h *Handler) imageMeta(w http.ResponseWriter, r *http.Request) {
	meta := h.ImageApprovals.GetFilterMeta()
	meta.Categories = h.ListCategoriesSlice()
	writeJSON(w, http.StatusOK, meta)
}

func (h *Handler) packageMeta(w http.ResponseWriter, r *http.Request) {
	meta := h.PackageApprovals.GetFilterMeta()
	meta.Categories = h.ListCategoriesSlice()
	writeJSON(w, http.StatusOK, meta)
}

func (h *Handler) libraryMeta(w http.ResponseWriter, r *http.Request) {
	meta := h.LibraryApprovals.GetFilterMeta()
	meta.Categories = h.ListCategoriesSlice()
	writeJSON(w, http.StatusOK, meta)
}

func (h *Handler) getPendingCounts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]int{
		"approvals": h.Approvals.PendingCount(),
		"images":    h.ImageApprovals.PendingCount(),
		"packages":  h.PackageApprovals.PendingCount(),
		"libraries": h.LibraryApprovals.PendingCount(),
	})
}

type decisionRequest struct {
	Host        string              `json:"host"`
	SkillID     string              `json:"skill_id"`
	SourceIP    string              `json:"source_ip"`
	PathPrefix  string              `json:"path_prefix"`
	Category    string              `json:"category"`
	LoggingMode approval.LoggingMode `json:"logging_mode"`
	Status      approval.Status     `json:"status"`
	Note        string              `json:"note"`
}

func (h *Handler) decideApproval(w http.ResponseWriter, r *http.Request) {
	var req decisionRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Status != approval.StatusApproved && req.Status != approval.StatusDenied {
		http.Error(w, "status must be 'approved' or 'denied'", http.StatusBadRequest)
		return
	}
	h.Approvals.Decide(req.Host, req.SkillID, req.SourceIP, req.PathPrefix, req.Status, req.Note)
	if req.Category != "" {
		h.Approvals.SetCategory(req.Host, req.SkillID, req.SourceIP, req.PathPrefix, req.Category)
	}
	if req.LoggingMode != "" {
		h.Approvals.SetLoggingMode(req.Host, req.SkillID, req.SourceIP, req.PathPrefix, req.LoggingMode)
	}
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

type deleteApprovalRequest struct {
	Host       string `json:"host"`
	SkillID    string `json:"skill_id"`
	SourceIP   string `json:"source_ip"`
	PathPrefix string `json:"path_prefix"`
}

func (h *Handler) deleteApproval(w http.ResponseWriter, r *http.Request) {
	var req deleteApprovalRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Host == "" {
		http.Error(w, "host is required", http.StatusBadRequest)
		return
	}
	h.Approvals.Delete(req.Host, req.SkillID, req.SourceIP, req.PathPrefix)
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

type setCategoryRequest struct {
	Host       string `json:"host"`
	SkillID    string `json:"skill_id"`
	SourceIP   string `json:"source_ip"`
	PathPrefix string `json:"path_prefix"`
	Category   string `json:"category"`
}

func (h *Handler) setApprovalCategory(w http.ResponseWriter, r *http.Request) {
	var req setCategoryRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	h.Approvals.SetCategory(req.Host, req.SkillID, req.SourceIP, req.PathPrefix, req.Category)
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func (h *Handler) setImageCategory(w http.ResponseWriter, r *http.Request) {
	var req setCategoryRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	h.ImageApprovals.SetCategory(req.Host, req.SkillID, req.SourceIP, "", req.Category)
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// --- Skills ---

// skillResponse is the admin API representation of a skill (no token, no internal ID).
type skillResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Active      bool   `json:"active"`
}

func toSkillResponse(s auth.Skill) skillResponse {
	return skillResponse{
		ID:          s.ID,
		Name:        s.Name,
		Description: s.Description,
		Active:      s.Active,
	}
}

func (h *Handler) listSkills(w http.ResponseWriter, r *http.Request) {
	skills := h.Skills.ListSkills()
	resp := make([]skillResponse, len(skills))
	for i, s := range skills {
		resp[i] = toSkillResponse(s)
	}
	writeJSON(w, http.StatusOK, resp)
}

type createSkillRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (h *Handler) createSkill(w http.ResponseWriter, r *http.Request) {
	var req createSkillRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	token, err := auth.GenerateToken()
	if err != nil {
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}
	skill := auth.Skill{
		ID:          auth.GenerateGUID(),
		Name:        req.Name,
		Description: req.Description,
		Token:       token,
		Active:      true,
	}
	if err := h.Skills.AddSkill(skill); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	h.save()
	writeJSON(w, http.StatusCreated, toSkillResponse(skill))
}

func (h *Handler) updateSkill(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Active      bool   `json:"active"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	existing, ok := h.Skills.GetSkill(req.ID)
	if !ok {
		http.Error(w, fmt.Sprintf("skill %q not found", req.ID), http.StatusNotFound)
		return
	}
	// Preserve token and allowed hosts (internal fields).
	updated := auth.Skill{
		ID:          existing.ID,
		Name:        req.Name,
		Description: req.Description,
		Token:       existing.Token,
		AllowedHost: existing.AllowedHost,
		Active:      req.Active,
	}
	if err := h.Skills.UpdateSkill(updated); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	h.save()
	writeJSON(w, http.StatusOK, toSkillResponse(updated))
}

func (h *Handler) deleteSkill(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id parameter required", http.StatusBadRequest)
		return
	}
	if err := h.Skills.DeleteSkill(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// --- Credentials ---

func (h *Handler) listCredentials(w http.ResponseWriter, r *http.Request) {
	creds := h.Credentials.List()
	// Mask sensitive fields in response.
	masked := make([]credentials.Credential, len(creds))
	for i, c := range creds {
		masked[i] = c
		if c.Password != "" {
			masked[i].Password = "********"
		}
		if c.Token != "" {
			masked[i].Token = "********"
		}
		if c.HeaderValue != "" {
			masked[i].HeaderValue = "********"
		}
		if c.ParamValue != "" {
			masked[i].ParamValue = "********"
		}
	}
	writeJSON(w, http.StatusOK, masked)
}

func (h *Handler) createCredential(w http.ResponseWriter, r *http.Request) {
	var cred credentials.Credential
	if err := readJSON(r, &cred); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if cred.ID == "" {
		cred.ID = fmt.Sprintf("cred-%d", time.Now().UnixNano())
	}
	h.Credentials.Add(cred)
	h.save()
	writeJSON(w, http.StatusCreated, map[string]string{"id": cred.ID})
}

func (h *Handler) updateCredential(w http.ResponseWriter, r *http.Request) {
	var cred credentials.Credential
	if err := readJSON(r, &cred); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	// Preserve existing secret values when empty (secrets are never exposed via API).
	if existing, ok := h.Credentials.Get(cred.ID); ok {
		switch cred.InjectionType {
		case credentials.InjectHeader:
			if cred.HeaderValue == "" {
				cred.HeaderValue = existing.HeaderValue
			}
		case credentials.InjectBasic:
			if cred.Password == "" {
				cred.Password = existing.Password
			}
		case credentials.InjectBearer:
			if cred.Token == "" {
				cred.Token = existing.Token
			}
		case credentials.InjectQuery:
			if cred.ParamValue == "" {
				cred.ParamValue = existing.ParamValue
			}
		}
	}
	if err := h.Credentials.Update(cred); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func (h *Handler) deleteCredential(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id parameter required", http.StatusBadRequest)
		return
	}
	h.Credentials.Delete(id)
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// --- Databases ---

func (h *Handler) listDatabases(w http.ResponseWriter, r *http.Request) {
	if h.DatabaseManager == nil {
		writeJSON(w, http.StatusOK, []database.DatabaseConfig{})
		return
	}
	dbs := h.DatabaseManager.List()
	// Mask passwords in response.
	masked := make([]database.DatabaseConfig, len(dbs))
	for i, db := range dbs {
		masked[i] = db
		if db.Password != "" {
			masked[i].Password = "********"
		}
	}
	writeJSON(w, http.StatusOK, masked)
}

func (h *Handler) createDatabase(w http.ResponseWriter, r *http.Request) {
	if h.DatabaseManager == nil {
		http.Error(w, "database feature not configured", http.StatusServiceUnavailable)
		return
	}
	var db database.DatabaseConfig
	if err := readJSON(r, &db); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if db.ID == "" {
		db.ID = fmt.Sprintf("db-%d", time.Now().UnixNano())
	}
	if db.APIPath == "" {
		http.Error(w, "api_path is required", http.StatusBadRequest)
		return
	}
	// Check for duplicate API path.
	if h.DatabaseManager.APIPathExists(db.APIPath, db.ID) {
		http.Error(w, "api_path already in use", http.StatusConflict)
		return
	}
	h.DatabaseManager.Add(db)
	h.save()
	writeJSON(w, http.StatusCreated, map[string]string{"id": db.ID})
}

func (h *Handler) updateDatabase(w http.ResponseWriter, r *http.Request) {
	if h.DatabaseManager == nil {
		http.Error(w, "database feature not configured", http.StatusServiceUnavailable)
		return
	}
	var db database.DatabaseConfig
	if err := readJSON(r, &db); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	// Preserve existing password when empty (secrets are never exposed via API).
	if existing, ok := h.DatabaseManager.Get(db.ID); ok {
		if db.Password == "" {
			db.Password = existing.Password
		}
	}
	// Check for duplicate API path.
	if h.DatabaseManager.APIPathExists(db.APIPath, db.ID) {
		http.Error(w, "api_path already in use", http.StatusConflict)
		return
	}
	if err := h.DatabaseManager.Update(db); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func (h *Handler) deleteDatabase(w http.ResponseWriter, r *http.Request) {
	if h.DatabaseManager == nil {
		http.Error(w, "database feature not configured", http.StatusServiceUnavailable)
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id parameter required", http.StatusBadRequest)
		return
	}
	h.DatabaseManager.Delete(id)
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// --- Image Approvals ---

func (h *Handler) listImageApprovals(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Has("limit") || r.URL.Query().Has("offset") ||
		r.URL.Query().Has("status") || r.URL.Query().Has("category") ||
		r.URL.Query().Has("skill_id") || r.URL.Query().Has("source_ip") {
		p := parseFilterParams(r)
		writeJSON(w, http.StatusOK, h.ImageApprovals.ListFiltered(p))
		return
	}
	writeJSON(w, http.StatusOK, h.ImageApprovals.ListAll())
}

func (h *Handler) listPendingImages(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.ImageApprovals.ListPending())
}

func (h *Handler) decideImageApproval(w http.ResponseWriter, r *http.Request) {
	var req decisionRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Status != approval.StatusApproved && req.Status != approval.StatusDenied {
		http.Error(w, "status must be 'approved' or 'denied'", http.StatusBadRequest)
		return
	}
	h.ImageApprovals.Decide(req.Host, req.SkillID, req.SourceIP, "", req.Status, req.Note)
	if req.Category != "" {
		h.ImageApprovals.SetCategory(req.Host, req.SkillID, req.SourceIP, "", req.Category)
	}
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func (h *Handler) deleteImageApproval(w http.ResponseWriter, r *http.Request) {
	var req deleteApprovalRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Host == "" {
		http.Error(w, "host is required", http.StatusBadRequest)
		return
	}
	h.ImageApprovals.Delete(req.Host, req.SkillID, req.SourceIP, "")
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// --- OS Package Approvals ---

func (h *Handler) listPackageApprovals(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Has("limit") || r.URL.Query().Has("offset") ||
		r.URL.Query().Has("status") || r.URL.Query().Has("category") ||
		r.URL.Query().Has("skill_id") || r.URL.Query().Has("source_ip") ||
		r.URL.Query().Has("type") {
		p := parseFilterParams(r)
		writeJSON(w, http.StatusOK, h.PackageApprovals.ListFiltered(p))
		return
	}
	writeJSON(w, http.StatusOK, h.PackageApprovals.ListAll())
}

func (h *Handler) listPendingPackages(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.PackageApprovals.ListPending())
}

func (h *Handler) decidePackageApproval(w http.ResponseWriter, r *http.Request) {
	var req decisionRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Status != approval.StatusApproved && req.Status != approval.StatusDenied {
		http.Error(w, "status must be 'approved' or 'denied'", http.StatusBadRequest)
		return
	}
	h.PackageApprovals.Decide(req.Host, req.SkillID, req.SourceIP, "", req.Status, req.Note)
	if req.Category != "" {
		h.PackageApprovals.SetCategory(req.Host, req.SkillID, req.SourceIP, "", req.Category)
	}
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func (h *Handler) setPackageCategory(w http.ResponseWriter, r *http.Request) {
	var req setCategoryRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	h.PackageApprovals.SetCategory(req.Host, req.SkillID, req.SourceIP, "", req.Category)
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func (h *Handler) deletePackageApproval(w http.ResponseWriter, r *http.Request) {
	var req deleteApprovalRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Host == "" {
		http.Error(w, "host is required", http.StatusBadRequest)
		return
	}
	h.PackageApprovals.Delete(req.Host, req.SkillID, req.SourceIP, "")
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// --- Code Library Approvals ---

func (h *Handler) listLibraryApprovals(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Has("limit") || r.URL.Query().Has("offset") ||
		r.URL.Query().Has("status") || r.URL.Query().Has("category") ||
		r.URL.Query().Has("skill_id") || r.URL.Query().Has("source_ip") ||
		r.URL.Query().Has("type") {
		p := parseFilterParams(r)
		writeJSON(w, http.StatusOK, h.LibraryApprovals.ListFiltered(p))
		return
	}
	writeJSON(w, http.StatusOK, h.LibraryApprovals.ListAll())
}

func (h *Handler) listPendingLibraries(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.LibraryApprovals.ListPending())
}

func (h *Handler) decideLibraryApproval(w http.ResponseWriter, r *http.Request) {
	var req decisionRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Status != approval.StatusApproved && req.Status != approval.StatusDenied {
		http.Error(w, "status must be 'approved' or 'denied'", http.StatusBadRequest)
		return
	}
	h.LibraryApprovals.Decide(req.Host, req.SkillID, req.SourceIP, "", req.Status, req.Note)
	if req.Category != "" {
		h.LibraryApprovals.SetCategory(req.Host, req.SkillID, req.SourceIP, "", req.Category)
	}
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func (h *Handler) setLibraryCategory(w http.ResponseWriter, r *http.Request) {
	var req setCategoryRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	h.LibraryApprovals.SetCategory(req.Host, req.SkillID, req.SourceIP, "", req.Category)
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func (h *Handler) deleteLibraryApproval(w http.ResponseWriter, r *http.Request) {
	var req deleteApprovalRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Host == "" {
		http.Error(w, "host is required", http.StatusBadRequest)
		return
	}
	h.LibraryApprovals.Delete(req.Host, req.SkillID, req.SourceIP, "")
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// --- Logs ---

func (h *Handler) getLogs(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
			limit = n
		}
	}

	afterStr := r.URL.Query().Get("after")
	if afterStr != "" {
		if afterID, err := strconv.Atoi(afterStr); err == nil {
			writeJSON(w, http.StatusOK, h.Logger.Since(afterID))
			return
		}
	}

	writeJSON(w, http.StatusOK, h.Logger.Recent(limit))
}

func (h *Handler) getLogStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.Logger.Stats())
}

func (h *Handler) getLogDetail(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "id parameter required", http.StatusBadRequest)
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	entry, ok := h.Logger.GetByID(id)
	if !ok {
		http.Error(w, "log entry not found", http.StatusNotFound)
		return
	}
	if entry.FullDetail == nil {
		http.Error(w, "no full detail available for this entry", http.StatusNotFound)
		return
	}
	// Return the full entry including detail.
	type detailResponse struct {
		ID              int                 `json:"id"`
		Method          string              `json:"method"`
		Host            string              `json:"host"`
		Path            string              `json:"path"`
		Status          string              `json:"status"`
		Detail          string              `json:"detail"`
		RequestHeaders  map[string][]string `json:"request_headers"`
		RequestBody     string              `json:"request_body"`
		ResponseHeaders map[string][]string `json:"response_headers"`
		ResponseBody    string              `json:"response_body"`
		ResponseStatus  int                 `json:"response_status"`
	}
	writeJSON(w, http.StatusOK, detailResponse{
		ID:              entry.ID,
		Method:          entry.Method,
		Host:            entry.Host,
		Path:            entry.Path,
		Status:          entry.Status,
		Detail:          entry.Detail,
		RequestHeaders:  entry.FullDetail.RequestHeaders,
		RequestBody:     entry.FullDetail.RequestBody,
		ResponseHeaders: entry.FullDetail.ResponseHeaders,
		ResponseBody:    entry.FullDetail.ResponseBody,
		ResponseStatus:  entry.FullDetail.ResponseStatus,
	})
}

// --- Health ---

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- Categories ---

// LoadCategories loads persisted categories at startup.
func (h *Handler) LoadCategories(cats []string) {
	h.catMu.Lock()
	defer h.catMu.Unlock()
	h.categories = append([]string{}, cats...)
}

// ListCategoriesSlice returns a copy of the categories for persistence.
func (h *Handler) ListCategoriesSlice() []string {
	h.catMu.RLock()
	defer h.catMu.RUnlock()
	out := make([]string, len(h.categories))
	copy(out, h.categories)
	return out
}

func (h *Handler) listCategories(w http.ResponseWriter, r *http.Request) {
	h.catMu.RLock()
	cats := make([]string, len(h.categories))
	copy(cats, h.categories)
	h.catMu.RUnlock()
	writeJSON(w, http.StatusOK, cats)
}

func (h *Handler) addCategory(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	h.catMu.Lock()
	for _, c := range h.categories {
		if c == name {
			h.catMu.Unlock()
			http.Error(w, "category already exists", http.StatusConflict)
			return
		}
	}
	h.categories = append(h.categories, name)
	sort.Strings(h.categories)
	h.catMu.Unlock()
	h.save()
	writeJSON(w, http.StatusCreated, map[string]string{"result": "ok"})
}

func (h *Handler) deleteCategory(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "name parameter required", http.StatusBadRequest)
		return
	}
	h.catMu.Lock()
	found := false
	for i, c := range h.categories {
		if c == name {
			h.categories = append(h.categories[:i], h.categories[i+1:]...)
			found = true
			break
		}
	}
	h.catMu.Unlock()
	if !found {
		http.Error(w, "category not found", http.StatusNotFound)
		return
	}
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// --- Version ---

func (h *Handler) getVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": h.Version})
}

// --- System Settings ---

func (h *Handler) getSSHStatus(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("systemctl", "is-active", "ssh").Output()
	status := strings.TrimSpace(string(out))
	enabled := status == "active"
	if err != nil && status == "" {
		status = "inactive"
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": enabled, "status": status})
}

func (h *Handler) setSSHStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	action := "stop"
	if req.Enabled {
		action = "start"
	}
	if out, err := exec.Command("systemctl", action, "ssh").CombinedOutput(); err != nil {
		http.Error(w, fmt.Sprintf("failed to %s ssh: %s", action, string(out)), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": req.Enabled})
}

// allowedServices is the whitelist of systemd services whose logs can be viewed.
var allowedServices = map[string]bool{
	"firewall4ai":      true,
	"iptables":         true,
	"systemd-networkd": true,
	"ssh":              true,
}

func (h *Handler) systemLogs(w http.ResponseWriter, r *http.Request) {
	service := r.URL.Query().Get("service")
	if service == "" {
		service = "firewall4ai"
	}
	if !allowedServices[service] {
		http.Error(w, "service not allowed", http.StatusBadRequest)
		return
	}
	lines := "200"
	if v := r.URL.Query().Get("lines"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			lines = strconv.Itoa(n)
		}
	}
	out, err := exec.Command("journalctl", "-u", service, "-n", lines, "--no-pager", "--output=short-iso").CombinedOutput()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"logs": "Error reading logs: " + string(out)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"logs": string(out)})
}

func (h *Handler) systemUpgrade(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Image string `json:"image"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	image := strings.TrimSpace(req.Image)
	if image == "" {
		image = "ghcr.io/olljanat-ai/firewall4ai:latest"
	}
	// Run upgrade in background since it will reboot.
	go func() {
		exec.Command("mount", "-o", "remount,rw", "/.snapshots").Run()
		exec.Command("elemental", "upgrade", "--reboot", "--system", "oci:"+image).Run()
	}()
	writeJSON(w, http.StatusOK, map[string]string{"result": "upgrade started"})
}

func (h *Handler) systemReboot(w http.ResponseWriter, r *http.Request) {
	// Send response before rebooting.
	writeJSON(w, http.StatusOK, map[string]string{"result": "rebooting"})
	go func() {
		time.Sleep(1 * time.Second)
		exec.Command("reboot").Run()
	}()
}

// --- Learning Mode ---

func (h *Handler) getLearningMode(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": cfg.LearningMode})
}

func (h *Handler) setLearningMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	config.SetLearningMode(req.Enabled)
	if h.SetLearningModeFunc != nil {
		h.SetLearningModeFunc(req.Enabled)
	}
	h.save()
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": req.Enabled})
}

// --- Language/Distro Settings ---

func (h *Handler) getDisabledLanguages(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	writeJSON(w, http.StatusOK, map[string][]string{"disabled": cfg.DisabledLanguages})
}

func (h *Handler) setDisabledLanguages(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Disabled []string `json:"disabled"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	config.SetDisabledLanguages(req.Disabled)
	if h.SetDisabledLanguagesFunc != nil {
		h.SetDisabledLanguagesFunc(req.Disabled)
	}
	h.save()
	writeJSON(w, http.StatusOK, map[string][]string{"disabled": req.Disabled})
}

func (h *Handler) getDisabledDistros(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	writeJSON(w, http.StatusOK, map[string][]string{"disabled": cfg.DisabledDistros})
}

func (h *Handler) setDisabledDistros(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Disabled []string `json:"disabled"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	config.SetDisabledDistros(req.Disabled)
	if h.SetDisabledDistrosFunc != nil {
		h.SetDisabledDistrosFunc(req.Disabled)
	}
	h.save()
	writeJSON(w, http.StatusOK, map[string][]string{"disabled": req.Disabled})
}

// LoadVMSettings restores VM settings from persisted state.
func (h *Handler) LoadVMSettings(keyboard, timezone string, sshKeys []string) {
	h.vmSettingsMu.Lock()
	defer h.vmSettingsMu.Unlock()
	h.keyboard = keyboard
	h.timezone = timezone
	h.sshAuthorizedKeys = sshKeys
}

// GetVMSettings returns the current keyboard and timezone settings.
func (h *Handler) GetVMSettings() (keyboard, timezone string) {
	h.vmSettingsMu.RLock()
	defer h.vmSettingsMu.RUnlock()
	return h.keyboard, h.timezone
}

// GetSSHAuthorizedKeys returns the global SSH authorized keys.
func (h *Handler) GetSSHAuthorizedKeys() []string {
	h.vmSettingsMu.RLock()
	defer h.vmSettingsMu.RUnlock()
	return append([]string{}, h.sshAuthorizedKeys...)
}

func (h *Handler) getVMSettings(w http.ResponseWriter, r *http.Request) {
	h.vmSettingsMu.RLock()
	defer h.vmSettingsMu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"keyboard":            h.keyboard,
		"timezone":            h.timezone,
		"ssh_authorized_keys": h.sshAuthorizedKeys,
	})
}

func (h *Handler) setVMSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Keyboard          string   `json:"keyboard"`
		Timezone          string   `json:"timezone"`
		SSHAuthorizedKeys []string `json:"ssh_authorized_keys"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	h.vmSettingsMu.Lock()
	h.keyboard = req.Keyboard
	h.timezone = req.Timezone
	h.sshAuthorizedKeys = req.SSHAuthorizedKeys
	h.vmSettingsMu.Unlock()
	h.save()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"keyboard":            req.Keyboard,
		"timezone":            req.Timezone,
		"ssh_authorized_keys": req.SSHAuthorizedKeys,
	})
}

func (h *Handler) save() {
	if h.SaveFunc != nil {
		if err := h.SaveFunc(); err != nil {
			fmt.Printf("error saving state: %v\n", err)
		}
	}
}
