package api

import (
	"net/http"
	"strconv"
)

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
	type detailResponse struct {
		ID              int                 `json:"id"`
		Method          string              `json:"method"`
		Host            string              `json:"host"`
		Path            string              `json:"path"`
		Status          string              `json:"status"`
		Detail          string              `json:"detail"`
		RequestHeaders  map[string][]string `json:"request_headers"`
		InjectedHeaders map[string][]string `json:"injected_headers"`
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
		InjectedHeaders: entry.FullDetail.InjectedHeaders,
		RequestBody:     entry.FullDetail.RequestBody,
		ResponseHeaders: entry.FullDetail.ResponseHeaders,
		ResponseBody:    entry.FullDetail.ResponseBody,
		ResponseStatus:  entry.FullDetail.ResponseStatus,
	})
}
