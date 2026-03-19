package auth

import (
	"testing"
)

func TestGenerateToken(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() error: %v", err)
	}
	if len(token) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("expected token length 64, got %d", len(token))
	}

	// Tokens should be unique.
	token2, _ := GenerateToken()
	if token == token2 {
		t.Error("two generated tokens should not be equal")
	}
}

func TestSkillStore_AddAndAuthenticate(t *testing.T) {
	s := NewSkillStore()

	skill := Skill{ID: "test-skill", Name: "Test", Token: "tok-123", Active: true}
	if err := s.AddSkill(skill); err != nil {
		t.Fatalf("AddSkill() error: %v", err)
	}

	// Duplicate should fail.
	if err := s.AddSkill(skill); err == nil {
		t.Error("expected error adding duplicate skill")
	}

	// Authenticate with valid token.
	got, ok := s.Authenticate("tok-123")
	if !ok {
		t.Fatal("Authenticate() returned false for valid token")
	}
	if got.ID != "test-skill" {
		t.Errorf("expected skill ID %q, got %q", "test-skill", got.ID)
	}

	// Invalid token.
	_, ok = s.Authenticate("bad-token")
	if ok {
		t.Error("Authenticate() should return false for invalid token")
	}
}

func TestSkillStore_InactiveSkill(t *testing.T) {
	s := NewSkillStore()
	skill := Skill{ID: "inactive", Name: "Inactive", Token: "tok-inactive", Active: false}
	s.AddSkill(skill)

	_, ok := s.Authenticate("tok-inactive")
	if ok {
		t.Error("Authenticate() should return false for inactive skill")
	}
}

func TestSkillStore_UpdateSkill(t *testing.T) {
	s := NewSkillStore()
	s.AddSkill(Skill{ID: "s1", Name: "Original", Token: "tok-1", Active: true})

	updated := Skill{ID: "s1", Name: "Updated", Token: "tok-2", Active: true}
	if err := s.UpdateSkill(updated); err != nil {
		t.Fatalf("UpdateSkill() error: %v", err)
	}

	// Old token should not work.
	_, ok := s.Authenticate("tok-1")
	if ok {
		t.Error("old token should not authenticate after update")
	}

	// New token should work.
	got, ok := s.Authenticate("tok-2")
	if !ok {
		t.Fatal("new token should authenticate after update")
	}
	if got.Name != "Updated" {
		t.Errorf("expected name %q, got %q", "Updated", got.Name)
	}

	// Update non-existent.
	if err := s.UpdateSkill(Skill{ID: "nope"}); err == nil {
		t.Error("expected error updating non-existent skill")
	}
}

func TestSkillStore_DeleteSkill(t *testing.T) {
	s := NewSkillStore()
	s.AddSkill(Skill{ID: "s1", Name: "Test", Token: "tok-1", Active: true})

	if err := s.DeleteSkill("s1"); err != nil {
		t.Fatalf("DeleteSkill() error: %v", err)
	}

	_, ok := s.Authenticate("tok-1")
	if ok {
		t.Error("deleted skill should not authenticate")
	}

	if err := s.DeleteSkill("s1"); err == nil {
		t.Error("expected error deleting non-existent skill")
	}
}

func TestSkillStore_IsHostPreApproved(t *testing.T) {
	s := NewSkillStore()
	s.AddSkill(Skill{
		ID: "s1", Token: "tok-1", Active: true,
		AllowedHost: []string{"api.example.com", "*"},
	})

	if !s.IsHostPreApproved("tok-1", "api.example.com") {
		t.Error("expected api.example.com to be pre-approved")
	}
	if !s.IsHostPreApproved("tok-1", "anything.com") {
		t.Error("expected wildcard * to match any host")
	}
	if s.IsHostPreApproved("bad-token", "api.example.com") {
		t.Error("bad token should not have pre-approved hosts")
	}
}

func TestSkillStore_ListAndLoad(t *testing.T) {
	s := NewSkillStore()
	s.AddSkill(Skill{ID: "a", Token: "t-a", Active: true})
	s.AddSkill(Skill{ID: "b", Token: "t-b", Active: true})

	list := s.ListSkills()
	if len(list) != 2 {
		t.Errorf("expected 2 skills, got %d", len(list))
	}

	// Load into new store.
	s2 := NewSkillStore()
	s2.LoadSkills(list)
	if len(s2.ListSkills()) != 2 {
		t.Error("LoadSkills should restore all skills")
	}
	_, ok := s2.Authenticate("t-a")
	if !ok {
		t.Error("loaded skill should authenticate")
	}
}
