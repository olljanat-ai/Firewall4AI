package api

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/olljanat-ai/firewall4ai/internal/agent"
	"github.com/olljanat-ai/firewall4ai/internal/auth"
	"github.com/olljanat-ai/firewall4ai/internal/image"
)

// RegisterImageMgmtRoutes sets up the disk image management API routes on the admin server.
func (h *Handler) RegisterImageMgmtRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/disk-images", h.listDiskImages)
	mux.HandleFunc("POST /api/disk-images", h.createDiskImage)
	mux.HandleFunc("PUT /api/disk-images", h.updateDiskImage)
	mux.HandleFunc("DELETE /api/disk-images", h.deleteDiskImage)
	mux.HandleFunc("POST /api/disk-images/build", h.buildDiskImage)
	mux.HandleFunc("DELETE /api/disk-images/version", h.deleteDiskImageVersion)
	mux.HandleFunc("GET /api/disk-images/build-log", h.getDiskImageBuildLog)
}

func (h *Handler) listDiskImages(w http.ResponseWriter, r *http.Request) {
	if h.ImageManager == nil {
		writeJSON(w, http.StatusOK, []image.DiskImage{})
		return
	}
	images := h.ImageManager.List()
	// Strip build logs from list response (fetch individually via build-log endpoint).
	for i := range images {
		for j := range images[i].Versions {
			if images[i].Versions[j].BuildLog != "" {
				images[i].Versions[j].BuildLog = "(available)"
			}
		}
	}
	writeJSON(w, http.StatusOK, images)
}

type createDiskImageRequest struct {
	Name           string              `json:"name"`
	OS             agent.OSType        `json:"os"`
	OSVersion      string              `json:"os_version"`
	Packages       []string            `json:"packages"`
	AITools        []image.AITool      `json:"ai_tools"`
	ContainerTools []image.ContainerTool `json:"container_tools"`
	Scripts        []string            `json:"scripts"`
}

func (h *Handler) createDiskImage(w http.ResponseWriter, r *http.Request) {
	var req createDiskImageRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
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

	img := image.DiskImage{
		ID:             auth.GenerateGUID(),
		Name:           req.Name,
		OS:             req.OS,
		OSVersion:      req.OSVersion,
		Packages:       req.Packages,
		AITools:        req.AITools,
		ContainerTools: req.ContainerTools,
		Scripts:        req.Scripts,
	}

	if err := h.ImageManager.Add(img); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	h.save()
	writeJSON(w, http.StatusCreated, img)
}

func (h *Handler) updateDiskImage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID             string              `json:"id"`
		Name           string              `json:"name"`
		OS             agent.OSType        `json:"os"`
		OSVersion      string              `json:"os_version"`
		Packages       []string            `json:"packages"`
		AITools        []image.AITool      `json:"ai_tools"`
		ContainerTools []image.ContainerTool `json:"container_tools"`
		Scripts        []string            `json:"scripts"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.ID == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}

	existing, ok := h.ImageManager.Get(req.ID)
	if !ok {
		http.Error(w, fmt.Sprintf("image %q not found", req.ID), http.StatusNotFound)
		return
	}

	if req.Name != "" {
		existing.Name = req.Name
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
	if req.AITools != nil {
		existing.AITools = req.AITools
	}
	if req.ContainerTools != nil {
		existing.ContainerTools = req.ContainerTools
	}
	if req.Scripts != nil {
		existing.Scripts = req.Scripts
	}

	if err := h.ImageManager.Update(*existing); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	h.save()
	updated, _ := h.ImageManager.Get(req.ID)
	writeJSON(w, http.StatusOK, updated)
}

func (h *Handler) deleteDiskImage(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id parameter required", http.StatusBadRequest)
		return
	}

	if _, ok := h.ImageManager.Get(id); !ok {
		http.Error(w, fmt.Sprintf("image %q not found", id), http.StatusNotFound)
		return
	}

	if err := h.ImageManager.Delete(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func (h *Handler) buildDiskImage(w http.ResponseWriter, r *http.Request) {
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

	img, ok := h.ImageManager.Get(req.ID)
	if !ok {
		http.Error(w, fmt.Sprintf("image %q not found", req.ID), http.StatusNotFound)
		return
	}

	// Create new version entry.
	ver := img.NextVersion()
	if err := h.ImageManager.AddVersion(req.ID, image.ImageVersion{
		Version: ver,
		Status:  image.BuildStatusPending,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.save()

	// Start build in background.
	if h.BuildImage != nil {
		go h.BuildImage(img, ver)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"result":  "build started",
		"version": ver,
	})
}

func (h *Handler) deleteDiskImageVersion(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	versionStr := r.URL.Query().Get("version")
	if id == "" || versionStr == "" {
		http.Error(w, "id and version parameters required", http.StatusBadRequest)
		return
	}

	version, err := strconv.Atoi(versionStr)
	if err != nil {
		http.Error(w, "version must be a number", http.StatusBadRequest)
		return
	}

	if err := h.ImageManager.DeleteVersion(id, version); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func (h *Handler) getDiskImageBuildLog(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	versionStr := r.URL.Query().Get("version")
	if id == "" || versionStr == "" {
		http.Error(w, "id and version parameters required", http.StatusBadRequest)
		return
	}

	version, err := strconv.Atoi(versionStr)
	if err != nil {
		http.Error(w, "version must be a number", http.StatusBadRequest)
		return
	}

	img, ok := h.ImageManager.Get(id)
	if !ok {
		http.Error(w, fmt.Sprintf("image %q not found", id), http.StatusNotFound)
		return
	}

	for _, v := range img.Versions {
		if v.Version == version {
			writeJSON(w, http.StatusOK, map[string]string{
				"log": v.BuildLog,
			})
			return
		}
	}

	http.Error(w, "version not found", http.StatusNotFound)
}
