package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/auth"
	"github.com/olljanat-ai/firewall4ai/internal/credentials"
	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
)

func setupHandler(t *testing.T) (*Handler, *http.ServeMux) {
	t.Helper()
	h := &Handler{
		Skills:      auth.NewSkillStore(),
		Approvals:   approval.NewManager(),
		Credentials: credentials.NewManager(),
		Logger:      proxylog.NewLogger(100),
		SaveFunc:    func() error { return nil },
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return h, mux
}

func doRequest(mux *http.ServeMux, method, path string, body any) *httptest.ResponseRecorder {
	var reqBody *bytes.Buffer
	if body != nil {
		data, _ := json.Marshal(body)
		reqBody = bytes.NewBuffer(data)
	} else {
		reqBody = &bytes.Buffer{}
	}
	req := httptest.NewRequest(method, path, reqBody)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func TestHealth(t *testing.T) {
	_, mux := setupHandler(t)
	w := doRequest(mux, "GET", "/api/health", nil)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestSkills_CRUD(t *testing.T) {
	_, mux := setupHandler(t)

	// Create.
	w := doRequest(mux, "POST", "/api/skills", map[string]any{
		"id": "test-skill", "name": "Test Skill", "allowed_hosts": []string{"example.com"},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var skill auth.Skill
	json.NewDecoder(w.Body).Decode(&skill)
	if skill.Token == "" {
		t.Error("created skill should have a token")
	}

	// List.
	w = doRequest(mux, "GET", "/api/skills", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", w.Code)
	}
	var skills []auth.Skill
	json.NewDecoder(w.Body).Decode(&skills)
	if len(skills) != 1 {
		t.Fatalf("expected 1 skill, got %d", len(skills))
	}

	// Update.
	skill.Name = "Updated"
	w = doRequest(mux, "PUT", "/api/skills", skill)
	if w.Code != http.StatusOK {
		t.Fatalf("update: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Duplicate create should fail.
	w = doRequest(mux, "POST", "/api/skills", map[string]any{
		"id": "test-skill", "name": "Duplicate",
	})
	if w.Code != http.StatusConflict {
		t.Errorf("duplicate: expected 409, got %d", w.Code)
	}

	// Delete.
	w = doRequest(mux, "DELETE", "/api/skills?id=test-skill", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d", w.Code)
	}

	// Delete non-existent.
	w = doRequest(mux, "DELETE", "/api/skills?id=nope", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("delete missing: expected 404, got %d", w.Code)
	}
}

func TestApprovals_Workflow(t *testing.T) {
	h, mux := setupHandler(t)

	// Register a pending host.
	h.Approvals.Check("example.com", "skill-1", "", "")

	// List pending.
	w := doRequest(mux, "GET", "/api/approvals/pending", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("pending: expected 200, got %d", w.Code)
	}
	var pending []approval.HostApproval
	json.NewDecoder(w.Body).Decode(&pending)
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}

	// Approve.
	w = doRequest(mux, "POST", "/api/approvals/decide", map[string]any{
		"host": "example.com", "skill_id": "skill-1", "status": "approved", "note": "ok",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("decide: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// List all.
	w = doRequest(mux, "GET", "/api/approvals", nil)
	var all []approval.HostApproval
	json.NewDecoder(w.Body).Decode(&all)
	if len(all) != 1 || all[0].Status != approval.StatusApproved {
		t.Error("expected 1 approved approval")
	}

	// Invalid status.
	w = doRequest(mux, "POST", "/api/approvals/decide", map[string]any{
		"host": "x.com", "skill_id": "s", "status": "invalid",
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid status: expected 400, got %d", w.Code)
	}
}

func TestApprovals_VMSpecific(t *testing.T) {
	h, mux := setupHandler(t)

	// Register a pending host from a specific VM.
	h.Approvals.Check("api.com", "", "10.255.255.10", "")

	// Approve for that VM via API.
	w := doRequest(mux, "POST", "/api/approvals/decide", map[string]any{
		"host": "api.com", "source_ip": "10.255.255.10", "status": "approved", "note": "vm ok",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("decide VM: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify the approval.
	status, exists := h.Approvals.CheckExisting("api.com", "", "10.255.255.10", "")
	if !exists || status != approval.StatusApproved {
		t.Errorf("expected VM-specific approved, got %s (exists=%v)", status, exists)
	}
}

func TestApprovals_Delete(t *testing.T) {
	h, mux := setupHandler(t)

	// Create an approval.
	h.Approvals.Decide("delete-me.com", "", "", "", approval.StatusApproved, "to delete")

	// Delete via API.
	w := doRequest(mux, "DELETE", "/api/approvals", map[string]any{
		"host": "delete-me.com",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify it's gone.
	_, exists := h.Approvals.CheckExisting("delete-me.com", "", "", "")
	if exists {
		t.Error("expected approval to be deleted")
	}
}

func TestApprovals_PathPrefix(t *testing.T) {
	_, mux := setupHandler(t)

	// Create a path-prefix approval via API.
	w := doRequest(mux, "POST", "/api/approvals/decide", map[string]any{
		"host": "github.com", "path_prefix": "/olljanat-ai/", "status": "approved", "note": "repo",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("decide path: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// List all should include path_prefix.
	w = doRequest(mux, "GET", "/api/approvals", nil)
	var all []approval.HostApproval
	json.NewDecoder(w.Body).Decode(&all)
	if len(all) != 1 {
		t.Fatalf("expected 1 approval, got %d", len(all))
	}
	if all[0].PathPrefix != "/olljanat-ai/" {
		t.Errorf("expected path_prefix /olljanat-ai/, got %q", all[0].PathPrefix)
	}

	// Delete with path_prefix.
	w = doRequest(mux, "DELETE", "/api/approvals", map[string]any{
		"host": "github.com", "path_prefix": "/olljanat-ai/",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Should be gone.
	w = doRequest(mux, "GET", "/api/approvals", nil)
	json.NewDecoder(w.Body).Decode(&all)
	if len(all) != 0 {
		t.Errorf("expected 0 approvals after delete, got %d", len(all))
	}
}

func TestCredentials_CRUD(t *testing.T) {
	_, mux := setupHandler(t)

	// Create.
	w := doRequest(mux, "POST", "/api/credentials", map[string]any{
		"name": "Test Cred", "host_pattern": "api.example.com",
		"injection_type": "bearer", "token": "secret123", "active": true,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	credID := result["id"]

	// List should mask secrets.
	w = doRequest(mux, "GET", "/api/credentials", nil)
	var creds []credentials.Credential
	json.NewDecoder(w.Body).Decode(&creds)
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if creds[0].Token != "********" {
		t.Error("token should be masked in list response")
	}

	// Delete.
	w = doRequest(mux, "DELETE", "/api/credentials?id="+credID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d", w.Code)
	}
}

func TestLogs(t *testing.T) {
	h, mux := setupHandler(t)
	h.Logger.Add(proxylog.Entry{Method: "GET", Host: "a.com", Status: "allowed"})
	h.Logger.Add(proxylog.Entry{Method: "POST", Host: "b.com", Status: "denied"})

	// Get logs.
	w := doRequest(mux, "GET", "/api/logs?limit=10", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("logs: expected 200, got %d", w.Code)
	}
	var logs []proxylog.Entry
	json.NewDecoder(w.Body).Decode(&logs)
	if len(logs) != 2 {
		t.Errorf("expected 2 log entries, got %d", len(logs))
	}

	// Get logs since ID 1.
	w = doRequest(mux, "GET", "/api/logs?after=1", nil)
	json.NewDecoder(w.Body).Decode(&logs)
	if len(logs) != 1 {
		t.Errorf("expected 1 log entry after ID 1, got %d", len(logs))
	}

	// Stats.
	w = doRequest(mux, "GET", "/api/logs/stats", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("stats: expected 200, got %d", w.Code)
	}
}

func TestDecideApproval_BadBody(t *testing.T) {
	_, mux := setupHandler(t)
	req := httptest.NewRequest("POST", "/api/approvals/decide", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestDeleteSkill_MissingID(t *testing.T) {
	_, mux := setupHandler(t)
	w := doRequest(mux, "DELETE", "/api/skills", nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestDeleteCredential_MissingID(t *testing.T) {
	_, mux := setupHandler(t)
	w := doRequest(mux, "DELETE", "/api/credentials", nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}
