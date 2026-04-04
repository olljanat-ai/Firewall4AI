package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/olljanat-ai/firewall4ai/internal/database"
)

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
