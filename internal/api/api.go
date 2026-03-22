// Package api provides the admin REST API for managing the proxy.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/auth"
	"github.com/olljanat-ai/firewall4ai/internal/credentials"
	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
)

// Handler holds dependencies for API endpoints.
type Handler struct {
	Skills         *auth.SkillStore
	Approvals      *approval.Manager
	ImageApprovals *approval.Manager // image-level approvals for container registry
	Credentials    *credentials.Manager
	Logger         *proxylog.Logger
	SaveFunc       func() error // called after state mutations to persist
}

// RegisterRoutes sets up all API routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Approvals
	mux.HandleFunc("GET /api/approvals", h.listApprovals)
	mux.HandleFunc("GET /api/approvals/pending", h.listPending)
	mux.HandleFunc("POST /api/approvals/decide", h.decideApproval)
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

	// Image Approvals (container registry)
	mux.HandleFunc("GET /api/images", h.listImageApprovals)
	mux.HandleFunc("GET /api/images/pending", h.listPendingImages)
	mux.HandleFunc("POST /api/images/decide", h.decideImageApproval)
	mux.HandleFunc("DELETE /api/images", h.deleteImageApproval)

	// Logs
	mux.HandleFunc("GET /api/logs", h.getLogs)
	mux.HandleFunc("GET /api/logs/stats", h.getLogStats)

	// Health
	mux.HandleFunc("GET /api/health", h.health)
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

func (h *Handler) listApprovals(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.Approvals.ListAll())
}

func (h *Handler) listPending(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.Approvals.ListPending())
}

type decisionRequest struct {
	Host       string          `json:"host"`
	SkillID    string          `json:"skill_id"`
	SourceIP   string          `json:"source_ip"`
	PathPrefix string          `json:"path_prefix"`
	Status     approval.Status `json:"status"`
	Note       string          `json:"note"`
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

// --- Skills ---

func (h *Handler) listSkills(w http.ResponseWriter, r *http.Request) {
	skills := h.Skills.ListSkills()
	for i := range skills {
		skills[i].Token = "********"
	}
	writeJSON(w, http.StatusOK, skills)
}

type createSkillRequest struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	AllowedHost []string `json:"allowed_hosts"`
}

func (h *Handler) createSkill(w http.ResponseWriter, r *http.Request) {
	var req createSkillRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.ID == "" {
		req.ID = auth.GenerateGUID()
	}
	token, err := auth.GenerateToken()
	if err != nil {
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}
	skill := auth.Skill{
		ID:          req.ID,
		Name:        req.Name,
		Token:       token,
		AllowedHost: req.AllowedHost,
		Active:      true,
	}
	if err := h.Skills.AddSkill(skill); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	h.save()
	writeJSON(w, http.StatusCreated, skill)
}

func (h *Handler) updateSkill(w http.ResponseWriter, r *http.Request) {
	var skill auth.Skill
	if err := readJSON(r, &skill); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	// Always preserve the existing token (never exposed via API).
	existing, ok := h.Skills.GetSkill(skill.ID)
	if !ok {
		http.Error(w, fmt.Sprintf("skill %q not found", skill.ID), http.StatusNotFound)
		return
	}
	skill.Token = existing.Token
	if err := h.Skills.UpdateSkill(skill); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	h.save()
	// Return masked token.
	skill.Token = "********"
	writeJSON(w, http.StatusOK, skill)
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

// --- Image Approvals ---

func (h *Handler) listImageApprovals(w http.ResponseWriter, r *http.Request) {
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

// --- Health ---

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) save() {
	if h.SaveFunc != nil {
		if err := h.SaveFunc(); err != nil {
			fmt.Printf("error saving state: %v\n", err)
		}
	}
}
