package api

import (
	"fmt"
	"log"
	"math"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/olljanat-ai/firewall4ai/internal/config"
)

func (h *Handler) getSSHStatus(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("systemctl", "is-active", "ssh").Output()
	status := strings.TrimSpace(string(out))
	enabled := status == "active"
	if err != nil && status == "" {
		status = "inactive"
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": enabled, "status": status})
}

func (h *Handler) setSSHStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	action := "stop"
	if req.Enabled {
		action = "start"
	}
	if out, err := exec.Command("systemctl", action, "ssh").CombinedOutput(); err != nil {
		http.Error(w, fmt.Sprintf("failed to %s ssh: %s", action, string(out)), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": req.Enabled})
}

// allowedServices is the whitelist of systemd services whose logs can be viewed.
var allowedServices = map[string]bool{
	"firewall4ai":      true,
	"iptables":         true,
	"systemd-networkd": true,
	"ssh":              true,
}

func (h *Handler) systemLogs(w http.ResponseWriter, r *http.Request) {
	service := r.URL.Query().Get("service")
	if service == "" {
		service = "firewall4ai"
	}
	if !allowedServices[service] {
		http.Error(w, "service not allowed", http.StatusBadRequest)
		return
	}
	lines := "200"
	if v := r.URL.Query().Get("lines"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			lines = strconv.Itoa(n)
		}
	}
	out, err := exec.Command("journalctl", "-u", service, "-n", lines, "--no-pager", "--output=short-iso").CombinedOutput()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"logs": "Error reading logs: " + string(out)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"logs": string(out)})
}

func (h *Handler) systemUpgrade(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Image string `json:"image"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	image := strings.TrimSpace(req.Image)
	if image == "" {
		image = "ghcr.io/olljanat-ai/firewall4ai:latest"
	}
	log.Printf("System upgrade requested with image: %s", image)
	// Run upgrade in background since it will reboot.
	go func() {
		log.Printf("Remounting /.snapshots as read-write for upgrade")
		if out, err := exec.Command("mount", "-o", "remount,rw", "/.snapshots").CombinedOutput(); err != nil {
			log.Printf("Warning: failed to remount /.snapshots: %v: %s", err, string(out))
		}
		log.Printf("Starting elemental upgrade with image: oci:%s", image)
		if out, err := exec.Command("elemental", "upgrade", "--reboot", "--system", "oci:"+image).CombinedOutput(); err != nil {
			log.Printf("Upgrade failed: %v: %s", err, string(out))
		}
	}()
	writeJSON(w, http.StatusOK, map[string]string{"result": "upgrade started"})
}

func (h *Handler) systemReboot(w http.ResponseWriter, r *http.Request) {
	// Send response before rebooting.
	writeJSON(w, http.StatusOK, map[string]string{"result": "rebooting"})
	go func() {
		time.Sleep(1 * time.Second)
		exec.Command("reboot").Run()
	}()
}

// --- Learning Mode ---

func (h *Handler) getLearningMode(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": cfg.LearningMode})
}

func (h *Handler) setLearningMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	config.SetLearningMode(req.Enabled)
	if h.SetLearningModeFunc != nil {
		h.SetLearningModeFunc(req.Enabled)
	}
	h.save()
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": req.Enabled})
}

// --- Max Full Log Body ---

func (h *Handler) getMaxFullLogBody(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]int{"max_full_log_body": config.GetMaxFullLogBody()})
}

func (h *Handler) setMaxFullLogBody(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MaxFullLogBody int `json:"max_full_log_body"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.MaxFullLogBody <= 0 || req.MaxFullLogBody > math.MaxInt32 {
		http.Error(w, "max_full_log_body must be a positive integer not exceeding 2147483647", http.StatusBadRequest)
		return
	}
	config.SetMaxFullLogBody(req.MaxFullLogBody)
	h.save()
	writeJSON(w, http.StatusOK, map[string]int{"max_full_log_body": req.MaxFullLogBody})
}

// --- Language/Distro Settings ---

func (h *Handler) getDisabledLanguages(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	writeJSON(w, http.StatusOK, map[string][]string{"disabled": cfg.DisabledLanguages})
}

func (h *Handler) setDisabledLanguages(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Disabled []string `json:"disabled"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	config.SetDisabledLanguages(req.Disabled)
	if h.SetDisabledLanguagesFunc != nil {
		h.SetDisabledLanguagesFunc(req.Disabled)
	}
	h.save()
	writeJSON(w, http.StatusOK, map[string][]string{"disabled": req.Disabled})
}

func (h *Handler) getDisabledDistros(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	writeJSON(w, http.StatusOK, map[string][]string{"disabled": cfg.DisabledDistros})
}

func (h *Handler) setDisabledDistros(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Disabled []string `json:"disabled"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	config.SetDisabledDistros(req.Disabled)
	if h.SetDisabledDistrosFunc != nil {
		h.SetDisabledDistrosFunc(req.Disabled)
	}
	h.save()
	writeJSON(w, http.StatusOK, map[string][]string{"disabled": req.Disabled})
}

// --- VM Settings ---

// LoadVMSettings restores VM settings from persisted state.
func (h *Handler) LoadVMSettings(keyboard, timezone string, sshKeys map[string]string) {
	h.vmSettingsMu.Lock()
	defer h.vmSettingsMu.Unlock()
	h.keyboard = keyboard
	h.timezone = timezone
	h.sshAuthorizedKeys = sshKeys
}

// GetVMSettings returns the current keyboard and timezone settings.
func (h *Handler) GetVMSettings() (keyboard, timezone string) {
	h.vmSettingsMu.RLock()
	defer h.vmSettingsMu.RUnlock()
	return h.keyboard, h.timezone
}

// GetSSHAuthorizedKeys returns the global SSH authorized key values.
func (h *Handler) GetSSHAuthorizedKeys() []string {
	h.vmSettingsMu.RLock()
	defer h.vmSettingsMu.RUnlock()
	keys := make([]string, 0, len(h.sshAuthorizedKeys))
	for _, key := range h.sshAuthorizedKeys {
		keys = append(keys, key)
	}
	return keys
}

// GetSSHAuthorizedKeysMap returns the global SSH authorized keys as a name->key map.
func (h *Handler) GetSSHAuthorizedKeysMap() map[string]string {
	h.vmSettingsMu.RLock()
	defer h.vmSettingsMu.RUnlock()
	result := make(map[string]string, len(h.sshAuthorizedKeys))
	for name, key := range h.sshAuthorizedKeys {
		result[name] = key
	}
	return result
}

func (h *Handler) getVMSettings(w http.ResponseWriter, r *http.Request) {
	h.vmSettingsMu.RLock()
	defer h.vmSettingsMu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"keyboard":            h.keyboard,
		"timezone":            h.timezone,
		"ssh_authorized_keys": h.sshAuthorizedKeys,
	})
}

func (h *Handler) setVMSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Keyboard          string            `json:"keyboard"`
		Timezone          string            `json:"timezone"`
		SSHAuthorizedKeys map[string]string `json:"ssh_authorized_keys"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	h.vmSettingsMu.Lock()
	h.keyboard = req.Keyboard
	h.timezone = req.Timezone
	h.sshAuthorizedKeys = req.SSHAuthorizedKeys
	h.vmSettingsMu.Unlock()
	h.save()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"keyboard":            req.Keyboard,
		"timezone":            req.Timezone,
		"ssh_authorized_keys": req.SSHAuthorizedKeys,
	})
}

// --- Git Config ---

func (h *Handler) getGitConfig(w http.ResponseWriter, r *http.Request) {
	git := config.GetGitConfig()
	writeJSON(w, http.StatusOK, map[string]string{
		"username": git.Username,
		"email":    git.Email,
	})
}

func (h *Handler) setGitConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	config.SetGitConfig(config.GitConfig{
		Username: req.Username,
		Email:    req.Email,
	})
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{
		"username": req.Username,
		"email":    req.Email,
	})
}
