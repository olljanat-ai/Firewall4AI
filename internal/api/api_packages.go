// api_packages.go contains admin API handlers for OS package and code library
// approval management: listing, deciding, deleting, and categorizing for both
// OS-level packages (e.g., Debian APT) and language-level libraries (e.g., npm, PyPI).

package api

import (
	"net/http"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
)

// --- OS Packages ---

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

func (h *Handler) packageMeta(w http.ResponseWriter, r *http.Request) {
	meta := h.PackageApprovals.GetFilterMeta()
	meta.Categories = h.ListCategoriesSlice()
	writeJSON(w, http.StatusOK, meta)
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

// --- Code Libraries ---

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

func (h *Handler) libraryMeta(w http.ResponseWriter, r *http.Request) {
	meta := h.LibraryApprovals.GetFilterMeta()
	meta.Categories = h.ListCategoriesSlice()
	writeJSON(w, http.StatusOK, meta)
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
