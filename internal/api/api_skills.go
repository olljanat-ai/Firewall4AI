// api_skills.go contains admin API handlers for skill (AI agent token)
// management: CRUD operations and token generation.

package api

import (
	"fmt"
	"net/http"

	"github.com/olljanat-ai/firewall4ai/internal/auth"
)

// skillResponse is the admin API representation of a skill (no token, no internal ID).
type skillResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Active      bool   `json:"active"`
}

func toSkillResponse(s auth.Skill) skillResponse {
	return skillResponse{
		ID:          s.ID,
		Name:        s.Name,
		Description: s.Description,
		Active:      s.Active,
	}
}

func (h *Handler) listSkills(w http.ResponseWriter, r *http.Request) {
	skills := h.Skills.ListSkills()
	resp := make([]skillResponse, len(skills))
	for i, s := range skills {
		resp[i] = toSkillResponse(s)
	}
	writeJSON(w, http.StatusOK, resp)
}

type createSkillRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (h *Handler) createSkill(w http.ResponseWriter, r *http.Request) {
	var req createSkillRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	token, err := auth.GenerateToken()
	if err != nil {
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}
	skill := auth.Skill{
		ID:          auth.GenerateGUID(),
		Name:        req.Name,
		Description: req.Description,
		Token:       token,
		Active:      true,
	}
	if err := h.Skills.AddSkill(skill); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	h.save()
	writeJSON(w, http.StatusCreated, toSkillResponse(skill))
}

func (h *Handler) updateSkill(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Active      bool   `json:"active"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	existing, ok := h.Skills.GetSkill(req.ID)
	if !ok {
		http.Error(w, fmt.Sprintf("skill %q not found", req.ID), http.StatusNotFound)
		return
	}
	// Preserve token and allowed hosts (internal fields).
	updated := auth.Skill{
		ID:          existing.ID,
		Name:        req.Name,
		Description: req.Description,
		Token:       existing.Token,
		AllowedHost: existing.AllowedHost,
		Active:      req.Active,
	}
	if err := h.Skills.UpdateSkill(updated); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	h.save()
	writeJSON(w, http.StatusOK, toSkillResponse(updated))
}

func (h *Handler) deleteSkill(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id parameter required", http.StatusBadRequest)
		return
	}
	if err := h.Skills.DeleteSkill(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}
