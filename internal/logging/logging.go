// Package logging provides structured proxy request logging.
package logging
 
import (
	"log"
	"sync"
	"time"
)
 
// FullDetail stores the complete request and response data captured
// when an approval rule has logging mode set to "full".
type FullDetail struct {
	RequestHeaders  map[string][]string `json:"request_headers,omitempty"`
	RequestBody     string              `json:"request_body,omitempty"`
	ResponseHeaders map[string][]string `json:"response_headers,omitempty"`
	ResponseBody    string              `json:"response_body,omitempty"`
	ResponseStatus  int                 `json:"response_status,omitempty"`
}

// Entry represents a single proxy log entry.
type Entry struct {
	ID          int         `json:"id"`
	Timestamp   time.Time   `json:"timestamp"`
	SkillID     string      `json:"skill_id"`
	SourceIP    string      `json:"source_ip,omitempty"`
	Method      string      `json:"method"`
	Host        string      `json:"host"`
	Path        string      `json:"path"`
	Status      string      `json:"status"` // "allowed", "denied", "pending", "error"
	Detail      string      `json:"detail"`
	Duration    int64       `json:"duration_ms"`
	HasFullLog  bool        `json:"has_full_log,omitempty"`
	FullDetail  *FullDetail `json:"-"` // excluded from list responses, served via detail endpoint
}
 
// Logger stores log entries in memory with a configurable max size.
// EntryObserver is called asynchronously for each entry that has full detail data.
// Implementations must be safe for concurrent use.
type EntryObserver func(Entry)

type Logger struct {
	mu       sync.RWMutex
	entries  []Entry
	nextID   int
	maxSize  int
	observer EntryObserver
}
 
// NewLogger creates a new Logger with the given max entries.
func NewLogger(maxSize int) *Logger {
	if maxSize <= 0 {
		maxSize = 10000
	}
	return &Logger{
		entries: make([]Entry, 0, 256),
		nextID:  1,
		maxSize: maxSize,
	}
}

// SetObserver sets a callback that is invoked asynchronously for each entry
// that has full detail data. Used by the observability system.
func (l *Logger) SetObserver(obs EntryObserver) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.observer = obs
}

// Add appends a new log entry and returns it.
func (l *Logger) Add(e Entry) Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.ID = l.nextID
	l.nextID++
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	l.entries = append(l.entries, e)

	// Trim if over max size.
	if len(l.entries) > l.maxSize {
		excess := len(l.entries) - l.maxSize
		l.entries = l.entries[excess:]
	}

	log.Printf("[%s] %s %s%s -> %s (skill=%s)", e.Status, e.Method, e.Host, e.Path, e.Detail, e.SkillID)

	// Notify observer asynchronously for entries with full detail.
	if l.observer != nil && e.FullDetail != nil {
		obs := l.observer
		entry := e // copy for goroutine
		go obs(entry)
	}

	return e
}
 
// Recent returns the last n entries (newest first).
func (l *Logger) Recent(n int) []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	total := len(l.entries)
	if n <= 0 || n > total {
		n = total
	}
	result := make([]Entry, n)
	for i := 0; i < n; i++ {
		result[i] = l.entries[total-1-i]
	}
	return result
}
 
// Since returns all entries after the given ID (for polling).
func (l *Logger) Since(afterID int) []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var result []Entry
	for _, e := range l.entries {
		if e.ID > afterID {
			result = append(result, e)
		}
	}
	return result
}
 
// GetByID returns a single entry by ID including full detail data.
func (l *Logger) GetByID(id int) (Entry, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, e := range l.entries {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}

// Stats returns summary statistics.
func (l *Logger) Stats() map[string]int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	stats := map[string]int{
		"total":   len(l.entries),
		"allowed": 0,
		"denied":  0,
		"pending": 0,
		"error":   0,
	}
	for _, e := range l.entries {
		stats[e.Status]++
	}
	return stats
}
