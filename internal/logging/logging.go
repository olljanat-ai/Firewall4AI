// Package logging provides structured proxy request logging with optional
// file persistence using JSONL format and log rotation.
package logging

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	logFileName    = "requests.jsonl"
	oldLogFileName = "requests.old.jsonl"
	maxLogFileSize = 50 * 1024 * 1024 // 50MB
)

// FullDetail stores the complete request and response data captured
// when an approval rule has logging mode set to "full".
type FullDetail struct {
	RequestHeaders  map[string][]string `json:"request_headers,omitempty"`
	InjectedHeaders map[string][]string `json:"injected_headers,omitempty"`
	RequestBody     string              `json:"request_body,omitempty"`
	ResponseHeaders map[string][]string `json:"response_headers,omitempty"`
	ResponseBody    string              `json:"response_body,omitempty"`
	ResponseStatus  int                 `json:"response_status,omitempty"`
}

// Entry represents a single proxy log entry.
type Entry struct {
	ID         int         `json:"id"`
	Timestamp  time.Time   `json:"timestamp"`
	SkillID    string      `json:"skill_id"`
	Method     string      `json:"method"`
	Host       string      `json:"host"`
	Path       string      `json:"path"`
	Status     string      `json:"status"` // "allowed", "denied", "pending", "error"
	Detail     string      `json:"detail"`
	Duration   int64       `json:"duration_ms"`
	HasFullLog bool        `json:"has_full_log,omitempty"`
	FullDetail *FullDetail `json:"-"` // excluded from list responses, served via detail endpoint
}

// Logger stores log entries in memory with a configurable max size,
// optionally persisting to disk in JSONL format with rotation.
type Logger struct {
	mu      sync.RWMutex
	entries []Entry
	nextID  int
	maxSize int

	// File persistence (optional).
	logDir string
	fileMu sync.Mutex
	file   *os.File
}

// NewLogger creates a new in-memory Logger with the given max entries.
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

// NewPersistentLogger creates a Logger that persists to disk in JSONL format.
// Existing logs are loaded from disk on startup.
func NewPersistentLogger(maxSize int, logDir string) *Logger {
	l := NewLogger(maxSize)
	if logDir == "" {
		return l
	}
	l.logDir = logDir
	os.MkdirAll(logDir, 0o755)
	l.loadFromDisk()
	l.openLogFile()
	return l
}

// Add appends a new log entry and returns it.
func (l *Logger) Add(e Entry) Entry {
	l.mu.Lock()
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
	l.mu.Unlock()

	if l.logDir != "" {
		l.appendToDisk(e)
	}

	log.Printf("[%s] %s %s%s -> %s (skill=%s)", e.Status, e.Method, e.Host, e.Path, e.Detail, e.SkillID)
	return e
}

// Close closes the log file if persistence is enabled.
func (l *Logger) Close() {
	l.fileMu.Lock()
	defer l.fileMu.Unlock()
	if l.file != nil {
		l.file.Close()
		l.file = nil
	}
}

func (l *Logger) loadFromDisk() {
	path := filepath.Join(l.logDir, logFileName)
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue
		}
		entries = append(entries, e)
	}

	if len(entries) == 0 {
		return
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	if len(entries) > l.maxSize {
		entries = entries[len(entries)-l.maxSize:]
	}

	l.mu.Lock()
	l.entries = entries
	l.nextID = entries[len(entries)-1].ID + 1
	l.mu.Unlock()

	log.Printf("Loaded %d log entries from disk", len(entries))
}

func (l *Logger) openLogFile() {
	l.fileMu.Lock()
	defer l.fileMu.Unlock()
	path := filepath.Join(l.logDir, logFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("Warning: failed to open log file: %v", err)
		return
	}
	l.file = f
}

func (l *Logger) appendToDisk(e Entry) {
	l.fileMu.Lock()
	defer l.fileMu.Unlock()
	if l.file == nil {
		return
	}
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	data = append(data, '\n')
	l.file.Write(data)

	if info, err := l.file.Stat(); err == nil && info.Size() > maxLogFileSize {
		l.rotateLocked()
	}
}

func (l *Logger) rotateLocked() {
	if l.file != nil {
		l.file.Close()
		l.file = nil
	}

	path := filepath.Join(l.logDir, logFileName)
	oldPath := filepath.Join(l.logDir, oldLogFileName)
	os.Remove(oldPath)
	os.Rename(path, oldPath)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("Warning: failed to open new log file after rotation: %v", err)
		return
	}
	l.file = f

	// Write current in-memory entries to the new file.
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, e := range l.entries {
		data, _ := json.Marshal(e)
		data = append(data, '\n')
		f.Write(data)
	}
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
