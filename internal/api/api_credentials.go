// api_credentials.go contains admin API handlers for credential management:
// CRUD operations with password/token masking in responses and preservation
// of existing secrets on partial updates.

package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/olljanat-ai/firewall4ai/internal/credentials"
)

func (h *Handler) listCredentials(w http.ResponseWriter, r *http.Request) {
	creds := h.Credentials.List()
	// Mask sensitive fields in response.
	masked := make([]credentials.Credential, len(creds))
	for i, c := range creds {
		masked[i] = c
		if c.Password != "" {
			masked[i].Password = "********"
		}
		if c.Token != "" {
			masked[i].Token = "********"
		}
		if c.HeaderValue != "" {
			masked[i].HeaderValue = "********"
		}
		if c.ParamValue != "" {
			masked[i].ParamValue = "********"
		}
	}
	writeJSON(w, http.StatusOK, masked)
}

func (h *Handler) createCredential(w http.ResponseWriter, r *http.Request) {
	var cred credentials.Credential
	if err := readJSON(r, &cred); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if cred.ID == "" {
		cred.ID = fmt.Sprintf("cred-%d", time.Now().UnixNano())
	}
	h.Credentials.Add(cred)
	h.save()
	writeJSON(w, http.StatusCreated, map[string]string{"id": cred.ID})
}

func (h *Handler) updateCredential(w http.ResponseWriter, r *http.Request) {
	var cred credentials.Credential
	if err := readJSON(r, &cred); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	// Preserve existing secret values when empty (secrets are never exposed via API).
	if existing, ok := h.Credentials.Get(cred.ID); ok {
		switch cred.InjectionType {
		case credentials.InjectHeader:
			if cred.HeaderValue == "" {
				cred.HeaderValue = existing.HeaderValue
			}
		case credentials.InjectBasic:
			if cred.Password == "" {
				cred.Password = existing.Password
			}
		case credentials.InjectBearer:
			if cred.Token == "" {
				cred.Token = existing.Token
			}
		case credentials.InjectQuery:
			if cred.ParamValue == "" {
				cred.ParamValue = existing.ParamValue
			}
		}
	}
	if err := h.Credentials.Update(cred); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func (h *Handler) deleteCredential(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id parameter required", http.StatusBadRequest)
		return
	}
	h.Credentials.Delete(id)
	h.save()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}
