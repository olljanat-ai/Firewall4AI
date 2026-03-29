package api

import (
	"net/http"
	"sync"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/auth"
)

// TemplateApplication records where a template has been applied.
type TemplateApplication struct {
	SourceIP string `json:"source_ip,omitempty"`
	SkillID  string `json:"skill_id,omitempty"`
}

// ApprovalTemplate is a named set of approval rules that can be applied in bulk.
type ApprovalTemplate struct {
	ID        string                `json:"id"`
	Name      string                `json:"name"`
	Rules     []ApprovalTemplateRule `json:"rules"`
	AppliedTo []TemplateApplication  `json:"applied_to,omitempty"`
}

// ApprovalTemplateRule is a single rule within a template.
type ApprovalTemplateRule struct {
	Type       string `json:"type"`        // "url", "image", "package", "library"
	Host       string `json:"host"`        // host pattern or package/library name
	PathPrefix string `json:"path_prefix"` // for URL rules only
	Status     string `json:"status"`      // "approved" or "denied"
	Category   string `json:"category"`
	Note       string `json:"note"`
}

// templateStore manages approval templates.
type templateStore struct {
	mu        sync.RWMutex
	templates []ApprovalTemplate
}

func (ts *templateStore) list() []ApprovalTemplate {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	out := make([]ApprovalTemplate, len(ts.templates))
	copy(out, ts.templates)
	return out
}

func (ts *templateStore) get(id string) (*ApprovalTemplate, bool) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	for i := range ts.templates {
		if ts.templates[i].ID == id {
			cp := ts.templates[i]
			return &cp, true
		}
	}
	return nil, false
}

func (ts *templateStore) add(t ApprovalTemplate) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.templates = append(ts.templates, t)
}

func (ts *templateStore) update(t ApprovalTemplate) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for i := range ts.templates {
		if ts.templates[i].ID == t.ID {
			ts.templates[i] = t
			return true
		}
	}
	return false
}

func (ts *templateStore) addApplication(id string, app TemplateApplication) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for i := range ts.templates {
		if ts.templates[i].ID == id {
			// Avoid duplicate entries.
			for _, existing := range ts.templates[i].AppliedTo {
				if existing.SourceIP == app.SourceIP && existing.SkillID == app.SkillID {
					return
				}
			}
			ts.templates[i].AppliedTo = append(ts.templates[i].AppliedTo, app)
			return
		}
	}
}

func (ts *templateStore) removeApplication(id string, app TemplateApplication) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for i := range ts.templates {
		if ts.templates[i].ID == id {
			for j, existing := range ts.templates[i].AppliedTo {
				if existing.SourceIP == app.SourceIP && existing.SkillID == app.SkillID {
					ts.templates[i].AppliedTo = append(ts.templates[i].AppliedTo[:j], ts.templates[i].AppliedTo[j+1:]...)
					return true
				}
			}
			return false
		}
	}
	return false
}

func (ts *templateStore) delete(id string) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for i := range ts.templates {
		if ts.templates[i].ID == id {
			ts.templates = append(ts.templates[:i], ts.templates[i+1:]...)
			return true
		}
	}
	return false
}

func (ts *templateStore) export() []ApprovalTemplate {
	return ts.list()
}

func (ts *templateStore) load(templates []ApprovalTemplate) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.templates = templates
}

// RegisterTemplateRoutes sets up approval template API routes.
func (h *Handler) RegisterTemplateRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/templates", h.listTemplates)
	mux.HandleFunc("POST /api/templates", h.createTemplate)
	mux.HandleFunc("PUT /api/templates", h.updateTemplate)
	mux.HandleFunc("DELETE /api/templates", h.deleteTemplate)
	mux.HandleFunc("POST /api/templates/apply", h.applyTemplate)
	mux.HandleFunc("POST /api/templates/unapply", h.unapplyTemplate)
}

func (h *Handler) listTemplates(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.templates.list())
}

func (h *Handler) createTemplate(w http.ResponseWriter, r *http.Request) {
	var req ApprovalTemplate
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	req.ID = auth.GenerateGUID()
	h.templates.add(req)
	h.save()
	writeJSON(w, http.StatusCreated, req)
}

func (h *Handler) updateTemplate(w http.ResponseWriter, r *http.Request) {
	var req ApprovalTemplate
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.ID == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}
	if !h.templates.update(req) {
		http.Error(w, "template not found", http.StatusNotFound)
		return
	}
	h.save()
	writeJSON(w, http.StatusOK, req)
}

func (h *Handler) deleteTemplate(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id parameter required", http.StatusBadRequest)
		return
	}
	if !h.templates.delete(id) {
		http.Error(w, "template not found", http.StatusNotFound)
		return
	}
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func (h *Handler) applyTemplate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       string `json:"id"`
		SourceIP string `json:"source_ip"` // optional: apply as VM-specific
		SkillID  string `json:"skill_id"`  // optional: apply as skill-specific
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	tmpl, ok := h.templates.get(req.ID)
	if !ok {
		http.Error(w, "template not found", http.StatusNotFound)
		return
	}

	applied := 0
	for _, rule := range tmpl.Rules {
		mgr := h.managerForType(rule.Type)
		if mgr == nil {
			continue
		}
		mgr.Decide(rule.Host, req.SkillID, req.SourceIP, rule.PathPrefix,
			approval.Status(rule.Status), rule.Note)
		if rule.Category != "" {
			mgr.SetCategory(rule.Host, req.SkillID, req.SourceIP, rule.PathPrefix, rule.Category)
		}
		applied++
	}

	h.templates.addApplication(req.ID, TemplateApplication{
		SourceIP: req.SourceIP,
		SkillID:  req.SkillID,
	})

	h.save()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"result":  "ok",
		"applied": applied,
	})
}

func (h *Handler) unapplyTemplate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       string `json:"id"`
		SourceIP string `json:"source_ip"`
		SkillID  string `json:"skill_id"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	tmpl, ok := h.templates.get(req.ID)
	if !ok {
		http.Error(w, "template not found", http.StatusNotFound)
		return
	}

	// Delete the approval rules that were created by this application.
	removed := 0
	for _, rule := range tmpl.Rules {
		mgr := h.managerForType(rule.Type)
		if mgr == nil {
			continue
		}
		mgr.Delete(rule.Host, req.SkillID, req.SourceIP, rule.PathPrefix)
		removed++
	}

	h.templates.removeApplication(req.ID, TemplateApplication{
		SourceIP: req.SourceIP,
		SkillID:  req.SkillID,
	})

	h.save()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"result":  "ok",
		"removed": removed,
	})
}

// managerForType returns the approval manager for a given rule type.
func (h *Handler) managerForType(ruleType string) *approval.Manager {
	switch ruleType {
	case "url":
		return h.Approvals
	case "image":
		return h.ImageApprovals
	case "package":
		return h.PackageApprovals
	case "library":
		return h.LibraryApprovals
	default:
		return nil
	}
}

// LoadTemplates restores templates from persisted state.
func (h *Handler) LoadTemplates(templates []ApprovalTemplate) {
	h.templates.load(templates)
}

// ExportTemplates returns templates for persistence.
func (h *Handler) ExportTemplates() []ApprovalTemplate {
	return h.templates.export()
}
