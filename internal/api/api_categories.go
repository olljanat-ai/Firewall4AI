package api

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
)

// --- Health ---

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- Version ---

func (h *Handler) getVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": h.Version})
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

// --- DHCP Leases ---

// DHCPLeaseInfo represents a DHCP lease for the admin UI.
type DHCPLeaseInfo struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Expiry   string `json:"expiry"` // formatted expiry or "permanent"
}

func (h *Handler) listDHCPLeases(w http.ResponseWriter, r *http.Request) {
	if h.GetDHCPLeases == nil {
		writeJSON(w, http.StatusOK, []DHCPLeaseInfo{})
		return
	}
	writeJSON(w, http.StatusOK, h.GetDHCPLeases())
}

// --- Backup/Restore ---

func (h *Handler) downloadBackup(w http.ResponseWriter, r *http.Request) {
	if h.GetBackupData == nil {
		http.Error(w, "backup not available", http.StatusInternalServerError)
		return
	}
	data, err := h.GetBackupData()
	if err != nil {
		http.Error(w, "backup failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=firewall4ai-backup.json")
	w.Write(data)
}

func (h *Handler) uploadRestore(w http.ResponseWriter, r *http.Request) {
	if h.RestoreBackupData == nil {
		http.Error(w, "restore not available", http.StatusInternalServerError)
		return
	}

	// Limit body to 50MB.
	r.Body = http.MaxBytesReader(w, r.Body, 50<<20)

	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	// Validate it's valid JSON.
	if !json.Valid(data) {
		http.Error(w, "invalid JSON data", http.StatusBadRequest)
		return
	}

	if err := h.RestoreBackupData(data); err != nil {
		http.Error(w, "restore failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"result": "restored"})
}
