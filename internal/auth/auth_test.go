package auth

import (
	"testing"
)

func TestGenerateToken(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() error: %v", err)
	}
	// GUID format: 8-4-4-4-12 = 36 chars
	if len(token) != 36 {
		t.Errorf("expected token length 36 (GUID), got %d", len(token))
	}
	// Check GUID structure: dashes at positions 8, 13, 18, 23
	if token[8] != '-' || token[13] != '-' || token[18] != '-' || token[23] != '-' {
		t.Errorf("token %q does not match GUID format", token)
	}

	// Tokens should be unique.
	token2, _ := GenerateToken()
	if token == token2 {
		t.Error("two generated tokens should not be equal")
	}
}

func TestGenerateGUID(t *testing.T) {
	guid := GenerateGUID()
	if len(guid) != 36 {
		t.Errorf("expected GUID length 36, got %d", len(guid))
	}
	// Version 4: character at position 14 should be '4'
	if guid[14] != '4' {
		t.Errorf("expected version 4 at position 14, got %c", guid[14])
	}
}

func TestSkillStore_AddAndGet(t *testing.T) {
	s := NewSkillStore()

	skill := Skill{ID: "test-skill", Name: "Test", Token: "tok-123", Active: true}
	if err := s.AddSkill(skill); err != nil {
		t.Fatalf("AddSkill() error: %v", err)
	}

	// Duplicate should fail.
	if err := s.AddSkill(skill); err == nil {
		t.Error("expected error adding duplicate skill")
	}

	// Get by ID.
	got, ok := s.GetSkill("test-skill")
	if !ok {
		t.Fatal("GetSkill() returned false for existing skill")
	}
	if got.ID != "test-skill" {
		t.Errorf("expected skill ID %q, got %q", "test-skill", got.ID)
	}

	// Non-existent skill.
	_, ok = s.GetSkill("nonexistent")
	if ok {
		t.Error("GetSkill() should return false for non-existent skill")
	}
}

func TestSkillStore_UpdateSkill(t *testing.T) {
	s := NewSkillStore()
	s.AddSkill(Skill{ID: "s1", Name: "Original", Token: "tok-1", Active: true})

	updated := Skill{ID: "s1", Name: "Updated", Token: "tok-2", Active: true}
	if err := s.UpdateSkill(updated); err != nil {
		t.Fatalf("UpdateSkill() error: %v", err)
	}

	got, ok := s.GetSkill("s1")
	if !ok {
		t.Fatal("GetSkill should find updated skill")
	}
	if got.Name != "Updated" {
		t.Errorf("expected name %q, got %q", "Updated", got.Name)
	}
	if got.Token != "tok-2" {
		t.Errorf("expected token %q, got %q", "tok-2", got.Token)
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

	_, ok := s.GetSkill("s1")
	if ok {
		t.Error("deleted skill should not be found")
	}

	if err := s.DeleteSkill("s1"); err == nil {
		t.Error("expected error deleting non-existent skill")
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
	_, ok := s2.GetSkill("a")
	if !ok {
		t.Error("loaded skill should be found by ID")
	}
}
