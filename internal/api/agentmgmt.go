package api

import (
	"fmt"
	"net/http"

	"github.com/olljanat-ai/firewall4ai/internal/agent"
	"github.com/olljanat-ai/firewall4ai/internal/auth"
)

// RegisterAgentMgmtRoutes sets up the agent management API routes on the admin server.
func (h *Handler) RegisterAgentMgmtRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/agents", h.listAgents)
	mux.HandleFunc("POST /api/agents", h.createAgent)
	mux.HandleFunc("PUT /api/agents", h.updateAgent)
	mux.HandleFunc("DELETE /api/agents", h.deleteAgent)
	mux.HandleFunc("POST /api/agents/download", h.downloadAgentBootFiles)
}

func (h *Handler) listAgents(w http.ResponseWriter, r *http.Request) {
	if h.AgentManager == nil {
		writeJSON(w, http.StatusOK, []agent.Agent{})
		return
	}
	writeJSON(w, http.StatusOK, h.AgentManager.List())
}

type createAgentRequest struct {
	MAC        string         `json:"mac"`
	Hostname   string         `json:"hostname"`
	IP         string         `json:"ip"`
	OS         agent.OSType   `json:"os"`
	OSVersion  string         `json:"os_version"`
	Packages   []string       `json:"packages"`
	DiskDevice string         `json:"disk_device"`
}

func (h *Handler) createAgent(w http.ResponseWriter, r *http.Request) {
	var req createAgentRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.MAC == "" {
		http.Error(w, "mac is required", http.StatusBadRequest)
		return
	}
	if err := agent.ValidateMAC(req.MAC); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Hostname == "" {
		http.Error(w, "hostname is required", http.StatusBadRequest)
		return
	}
	if req.OS == "" {
		http.Error(w, "os is required (alpine, debian, ubuntu)", http.StatusBadRequest)
		return
	}
	if req.OS != agent.OSAlpine && req.OS != agent.OSDebian && req.OS != agent.OSUbuntu {
		http.Error(w, "os must be alpine, debian, or ubuntu", http.StatusBadRequest)
		return
	}

	if req.OSVersion == "" {
		req.OSVersion = agent.DefaultOSVersion(req.OS)
	}
	if req.DiskDevice == "" {
		req.DiskDevice = agent.DefaultDiskDevice()
	}

	a := agent.Agent{
		ID:         auth.GenerateGUID(),
		MAC:        req.MAC,
		Hostname:   req.Hostname,
		IP:         req.IP,
		OS:         req.OS,
		OSVersion:  req.OSVersion,
		Packages:   req.Packages,
		DiskDevice: req.DiskDevice,
		Status:     agent.StatusNew,
	}

	if err := h.AgentManager.Add(a); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	// Set static DHCP lease if IP is provided.
	if h.OnAgentChange != nil {
		h.OnAgentChange(&a)
	}

	h.save()

	// Start downloading boot files in background.
	if h.DownloadBootFiles != nil {
		go h.DownloadBootFiles(&a)
	}

	writeJSON(w, http.StatusCreated, a)
}

func (h *Handler) updateAgent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID         string         `json:"id"`
		MAC        string         `json:"mac"`
		Hostname   string         `json:"hostname"`
		IP         string         `json:"ip"`
		OS         agent.OSType   `json:"os"`
		OSVersion  string         `json:"os_version"`
		Packages   []string       `json:"packages"`
		DiskDevice string         `json:"disk_device"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.ID == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}

	existing, ok := h.AgentManager.Get(req.ID)
	if !ok {
		http.Error(w, fmt.Sprintf("agent %q not found", req.ID), http.StatusNotFound)
		return
	}

	// Apply changes.
	if req.MAC != "" {
		if err := agent.ValidateMAC(req.MAC); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		existing.MAC = req.MAC
	}
	if req.Hostname != "" {
		existing.Hostname = req.Hostname
	}
	if req.IP != "" {
		existing.IP = req.IP
	}
	if req.OS != "" {
		existing.OS = req.OS
	}
	if req.OSVersion != "" {
		existing.OSVersion = req.OSVersion
	}
	if req.Packages != nil {
		existing.Packages = req.Packages
	}
	if req.DiskDevice != "" {
		existing.DiskDevice = req.DiskDevice
	}

	if err := h.AgentManager.Update(*existing); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	if h.OnAgentChange != nil {
		h.OnAgentChange(existing)
	}

	h.save()
	writeJSON(w, http.StatusOK, existing)
}

func (h *Handler) deleteAgent(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id parameter required", http.StatusBadRequest)
		return
	}

	existing, ok := h.AgentManager.Get(id)
	if !ok {
		http.Error(w, fmt.Sprintf("agent %q not found", id), http.StatusNotFound)
		return
	}

	if err := h.AgentManager.Delete(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if h.OnAgentDelete != nil {
		h.OnAgentDelete(existing)
	}

	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func (h *Handler) downloadAgentBootFiles(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.ID == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}

	a, ok := h.AgentManager.Get(req.ID)
	if !ok {
		http.Error(w, fmt.Sprintf("agent %q not found", req.ID), http.StatusNotFound)
		return
	}

	if h.DownloadBootFiles != nil {
		go h.DownloadBootFiles(a)
	}

	writeJSON(w, http.StatusOK, map[string]string{"result": "download started"})
}
