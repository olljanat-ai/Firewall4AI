// api_approvals.go contains admin API handlers for managing URL/host approval
// entries: listing, deciding (approve/deny), deleting, and categorizing.

package api

import (
	"net/http"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
)

func (h *Handler) listApprovals(w http.ResponseWriter, r *http.Request) {
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

func (h *Handler) getPendingCounts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]int{
		"approvals":   h.Approvals.PendingCount(),
		"images":      h.ImageApprovals.PendingCount(),
		"helm_charts": h.HelmChartApprovals.PendingCount(),
		"packages":    h.PackageApprovals.PendingCount(),
		"libraries":   h.LibraryApprovals.PendingCount(),
	})
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
