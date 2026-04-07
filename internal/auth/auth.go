// Package auth handles AI agent skill management and ID generation.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
)

// Skill represents an AI agent skill.
type Skill struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Token       string `json:"token"`
	Active      bool   `json:"active"`
}

// SkillStore manages skills.
type SkillStore struct {
	mu   sync.RWMutex
	byID map[string]*Skill // keyed by ID
}

// NewSkillStore creates a new empty skill store.
func NewSkillStore() *SkillStore {
	return &SkillStore{
		byID: make(map[string]*Skill),
	}
}

// GenerateGUID creates a cryptographically random UUID v4 string.
func GenerateGUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// GenerateToken creates a cryptographically random token in GUID format.
func GenerateToken() (string, error) {
	return GenerateGUID(), nil
}

// AddSkill registers a new skill.
func (s *SkillStore) AddSkill(skill Skill) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byID[skill.ID]; exists {
		return fmt.Errorf("skill %q already exists", skill.ID)
	}
	s.byID[skill.ID] = &skill
	return nil
}

// GetSkill returns a skill by ID.
func (s *SkillStore) GetSkill(id string) (*Skill, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	skill, ok := s.byID[id]
	if !ok {
		return nil, false
	}
	cp := *skill
	return &cp, true
}

// UpdateSkill updates an existing skill.
func (s *SkillStore) UpdateSkill(skill Skill) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.byID[skill.ID]
	if !ok {
		return fmt.Errorf("skill %q not found", skill.ID)
	}
	*existing = skill
	return nil
}

// DeleteSkill removes a skill.
func (s *SkillStore) DeleteSkill(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[id]; !ok {
		return fmt.Errorf("skill %q not found", id)
	}
	delete(s.byID, id)
	return nil
}

// ListSkills returns all skills.
func (s *SkillStore) ListSkills() []Skill {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Skill, 0, len(s.byID))
	for _, sk := range s.byID {
		result = append(result, *sk)
	}
	return result
}

// LoadSkills bulk-loads skills (used at startup).
func (s *SkillStore) LoadSkills(skills []Skill) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID = make(map[string]*Skill)
	for i := range skills {
		sk := &skills[i]
		s.byID[sk.ID] = sk
	}
}
