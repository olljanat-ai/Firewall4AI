package api

import (
	"net/http"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
)

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

func (h *Handler) imageMeta(w http.ResponseWriter, r *http.Request) {
	meta := h.ImageApprovals.GetFilterMeta()
	meta.Categories = h.ListCategoriesSlice()
	writeJSON(w, http.StatusOK, meta)
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
