package credentials

import (
	"net/http"
	"testing"
)

func TestMatchHost(t *testing.T) {
	tests := []struct {
		pattern, host string
		want          bool
	}{
		{"api.example.com", "api.example.com", true},
		{"api.example.com", "other.example.com", false},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "deep.api.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "other.com", false},
	}
	for _, tt := range tests {
		got := matchHost(tt.pattern, tt.host)
		if got != tt.want {
			t.Errorf("matchHost(%q, %q) = %v, want %v", tt.pattern, tt.host, got, tt.want)
		}
	}
}

func TestManager_AddListDelete(t *testing.T) {
	m := NewManager()

	c := Credential{ID: "c1", Name: "Test", Active: true}
	m.Add(c)

	list := m.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(list))
	}

	m.Delete("c1")
	if len(m.List()) != 0 {
		t.Error("expected 0 credentials after delete")
	}
}

func TestManager_Update(t *testing.T) {
	m := NewManager()
	m.Add(Credential{ID: "c1", Name: "Old", Active: true})

	m.Update(Credential{ID: "c1", Name: "New", Active: false})
	list := m.List()
	if len(list) != 1 || list[0].Name != "New" || list[0].Active {
		t.Error("Update should replace the credential")
	}
}

func TestManager_InjectHeader(t *testing.T) {
	m := NewManager()
	m.Add(Credential{
		ID:            "c1",
		HostPattern:   "api.example.com",
		InjectionType: InjectHeader,
		HeaderName:    "X-API-Key",
		HeaderValue:   "secret123",
		Active:        true,
	})

	req, _ := http.NewRequest("GET", "http://api.example.com/data", nil)
	m.InjectForRequest(req, "any-skill")

	if got := req.Header.Get("X-API-Key"); got != "secret123" {
		t.Errorf("expected X-API-Key=secret123, got %q", got)
	}
}

func TestManager_InjectBearer(t *testing.T) {
	m := NewManager()
	m.Add(Credential{
		ID:            "c1",
		HostPattern:   "api.example.com",
		InjectionType: InjectBearer,
		Token:         "mytoken",
		Active:        true,
	})

	req, _ := http.NewRequest("GET", "http://api.example.com/data", nil)
	m.InjectForRequest(req, "any-skill")

	if got := req.Header.Get("Authorization"); got != "Bearer mytoken" {
		t.Errorf("expected Bearer mytoken, got %q", got)
	}
}

func TestManager_InjectBasicAuth(t *testing.T) {
	m := NewManager()
	m.Add(Credential{
		ID:            "c1",
		HostPattern:   "api.example.com",
		InjectionType: InjectBasic,
		Username:      "user",
		Password:      "pass",
		Active:        true,
	})

	req, _ := http.NewRequest("GET", "http://api.example.com/data", nil)
	m.InjectForRequest(req, "any-skill")

	user, pass, ok := req.BasicAuth()
	if !ok || user != "user" || pass != "pass" {
		t.Errorf("expected basic auth user/pass, got %q/%q (ok=%v)", user, pass, ok)
	}
}

func TestManager_InjectQueryParam(t *testing.T) {
	m := NewManager()
	m.Add(Credential{
		ID:            "c1",
		HostPattern:   "api.example.com",
		InjectionType: InjectQuery,
		ParamName:     "api_key",
		ParamValue:    "qp-secret",
		Active:        true,
	})

	req, _ := http.NewRequest("GET", "http://api.example.com/data", nil)
	m.InjectForRequest(req, "any-skill")

	if got := req.URL.Query().Get("api_key"); got != "qp-secret" {
		t.Errorf("expected api_key=qp-secret, got %q", got)
	}
}

func TestManager_InjectSkillFiltering(t *testing.T) {
	m := NewManager()
	m.Add(Credential{
		ID:            "c1",
		HostPattern:   "api.example.com",
		SkillID:       "skill-a",
		InjectionType: InjectBearer,
		Token:         "secret",
		Active:        true,
	})

	// Should not inject for different skill.
	req, _ := http.NewRequest("GET", "http://api.example.com/data", nil)
	m.InjectForRequest(req, "skill-b")
	if req.Header.Get("Authorization") != "" {
		t.Error("should not inject for non-matching skill")
	}

	// Should inject for matching skill.
	req, _ = http.NewRequest("GET", "http://api.example.com/data", nil)
	m.InjectForRequest(req, "skill-a")
	if req.Header.Get("Authorization") != "Bearer secret" {
		t.Error("should inject for matching skill")
	}
}

func TestManager_InactiveCredential(t *testing.T) {
	m := NewManager()
	m.Add(Credential{
		ID:            "c1",
		HostPattern:   "api.example.com",
		InjectionType: InjectBearer,
		Token:         "secret",
		Active:        false,
	})

	req, _ := http.NewRequest("GET", "http://api.example.com/data", nil)
	m.InjectForRequest(req, "any")
	if req.Header.Get("Authorization") != "" {
		t.Error("inactive credential should not be injected")
	}
}

func TestManager_LoadCredentials(t *testing.T) {
	m := NewManager()
	creds := []Credential{
		{ID: "c1", Name: "A", Active: true},
		{ID: "c2", Name: "B", Active: true},
	}
	m.LoadCredentials(creds)

	if len(m.List()) != 2 {
		t.Error("LoadCredentials should restore all credentials")
	}
}
