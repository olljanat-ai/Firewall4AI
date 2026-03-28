// Package store provides a simple JSON file-backed key-value store.
package store
 
import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)
 
// JSONStore is a thread-safe JSON file-backed store.
type JSONStore[T any] struct {
	mu       sync.RWMutex
	path     string
	data     T
	defaults T
}
 
// New creates a new JSONStore with the given file path and default value.
func New[T any](dir, filename string, defaults T) (*JSONStore[T], error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &JSONStore[T]{
		path:     filepath.Join(dir, filename),
		defaults: defaults,
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}
 
func (s *JSONStore[T]) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.data = s.defaults
			return s.save()
		}
		return err
	}
	return json.Unmarshal(data, &s.data)
}
 
func (s *JSONStore[T]) save() error {
	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o644)
}
 
// Get returns the current data (read-only snapshot).
func (s *JSONStore[T]) Get() T {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data
}
 
// Update applies fn to the data and persists the result.
func (s *JSONStore[T]) Update(fn func(*T)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.data)
	return s.save()
}

// ExportJSON returns the current data serialized as JSON.
func (s *JSONStore[T]) ExportJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.MarshalIndent(s.data, "", "  ")
}

// ImportJSON replaces the data with the given JSON and persists it.
func (s *JSONStore[T]) ImportJSON(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var newData T
	if err := json.Unmarshal(data, &newData); err != nil {
		return err
	}
	s.data = newData
	return s.save()
}
