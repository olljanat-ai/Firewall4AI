// Package api provides the admin REST API for managing the proxy.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"

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
	Skills                   *auth.SkillStore
	Approvals                *approval.Manager
	ImageApprovals           *approval.Manager // image-level approvals for container registry
	HelmChartApprovals       *approval.Manager // Helm chart approvals
	PackageApprovals         *approval.Manager // OS Packages (e.g., Debian)
	LibraryApprovals         *approval.Manager // Code Libraries (e.g., Go, npm, PyPI, NuGet)
	Credentials              *credentials.Manager
	Logger                   *proxylog.Logger
	SaveFunc                 func() error           // called after state mutations to persist
	SetLearningModeFunc      func(bool)             // called to update learning mode on the proxy
	SetDisabledLanguagesFunc func([]string)         // called to update disabled languages
	SetDisabledDistrosFunc   func([]string)         // called to update disabled distros
	Version                  string                 // build version string
	GetBackupData            func() ([]byte, error) // returns state.json contents for backup
	RestoreBackupData        func([]byte) error     // restores state from backup data

	// Database management.
	DatabaseManager *database.Manager

	// Image management.
	ImageManager *image.Manager
	BuildImage   func(img *image.DiskImage, version int) // called to build an image version

	// Agent management.
	AgentManager  *agent.Manager
	OnAgentChange func(a *agent.Agent)    // called when agent is created/updated
	OnAgentDelete func(a *agent.Agent)    // called when agent is deleted
	GetLeaseIP    func(mac string) string // returns DHCP lease IP for a MAC address
	GetDHCPLeases func() []DHCPLeaseInfo  // returns all current DHCP leases

	catMu      sync.RWMutex
	categories []string

	templates templateStore

	// Global VM settings.
	vmSettingsMu      sync.RWMutex
	keyboard          string            // keyboard layout, e.g. "us", "fi"
	timezone          string            // timezone, e.g. "UTC", "Europe/Helsinki"
	sshAuthorizedKeys map[string]string // SSH public keys for root login on all agent VMs (name -> key)
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

	// Container Images (container registry)
	mux.HandleFunc("GET /api/images", h.listImageApprovals)
	mux.HandleFunc("GET /api/images/pending", h.listPendingImages)
	mux.HandleFunc("POST /api/images/decide", h.decideImageApproval)
	mux.HandleFunc("PUT /api/images/category", h.setImageCategory)
	mux.HandleFunc("GET /api/images/meta", h.imageMeta)
	mux.HandleFunc("DELETE /api/images", h.deleteImageApproval)

	// Helm Charts
	mux.HandleFunc("GET /api/helm-charts", h.listHelmChartApprovals)
	mux.HandleFunc("GET /api/helm-charts/pending", h.listPendingHelmCharts)
	mux.HandleFunc("POST /api/helm-charts/decide", h.decideHelmChartApproval)
	mux.HandleFunc("PUT /api/helm-charts/category", h.setHelmChartCategory)
	mux.HandleFunc("GET /api/helm-charts/meta", h.helmChartMeta)
	mux.HandleFunc("DELETE /api/helm-charts", h.deleteHelmChartApproval)

	// OS Packages (e.g., Debian)
	mux.HandleFunc("GET /api/packages", h.listPackageApprovals)
	mux.HandleFunc("GET /api/packages/pending", h.listPendingPackages)
	mux.HandleFunc("POST /api/packages/decide", h.decidePackageApproval)
	mux.HandleFunc("PUT /api/packages/category", h.setPackageCategory)
	mux.HandleFunc("GET /api/packages/meta", h.packageMeta)
	mux.HandleFunc("DELETE /api/packages", h.deletePackageApproval)

	// Code Libraries (Go, npm, PyPI, NuGet)
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
	mux.HandleFunc("GET /api/settings/max-full-log-body", h.getMaxFullLogBody)
	mux.HandleFunc("POST /api/settings/max-full-log-body", h.setMaxFullLogBody)
	mux.HandleFunc("GET /api/settings/git-config", h.getGitConfig)
	mux.HandleFunc("POST /api/settings/git-config", h.setGitConfig)
	mux.HandleFunc("GET /api/system/logs", h.systemLogs)
	mux.HandleFunc("POST /api/system/upgrade", h.systemUpgrade)
	mux.HandleFunc("POST /api/system/reboot", h.systemReboot)

	// DHCP leases
	mux.HandleFunc("GET /api/dhcp/leases", h.listDHCPLeases)

	// Backup/Restore
	mux.HandleFunc("GET /api/backup", h.downloadBackup)
	mux.HandleFunc("POST /api/restore", h.uploadRestore)
}

// --- Shared helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

func (h *Handler) save() {
	if h.SaveFunc != nil {
		if err := h.SaveFunc(); err != nil {
			fmt.Printf("error saving state: %v\n", err)
		}
	}
}

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

// --- Shared request types used by multiple domain files ---

type decisionRequest struct {
	Host        string               `json:"host"`
	SkillID     string               `json:"skill_id"`
	SourceIP    string               `json:"source_ip"`
	PathPrefix  string               `json:"path_prefix"`
	Category    string               `json:"category"`
	LoggingMode approval.LoggingMode `json:"logging_mode"`
	Status      approval.Status      `json:"status"`
	Note        string               `json:"note"`
}

type deleteApprovalRequest struct {
	Host       string `json:"host"`
	SkillID    string `json:"skill_id"`
	SourceIP   string `json:"source_ip"`
	PathPrefix string `json:"path_prefix"`
}

type setCategoryRequest struct {
	Host       string `json:"host"`
	SkillID    string `json:"skill_id"`
	SourceIP   string `json:"source_ip"`
	PathPrefix string `json:"path_prefix"`
	Category   string `json:"category"`
}

// Ensure unused imports don't cause errors — these packages provide types used by
// the Handler struct and sub-files in this package.
var _ = config.Get
