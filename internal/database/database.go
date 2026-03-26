// Package database manages SQL database connections and query execution
// for the agent API. It supports Microsoft SQL Server, PostgreSQL, and MySQL.
package database

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"
)

// DriverType identifies the database driver.
type DriverType string

const (
	DriverMSSQL    DriverType = "mssql"
	DriverPostgres DriverType = "postgres"
	DriverMySQL    DriverType = "mysql"
)

// DatabaseConfig represents a configured database connection.
type DatabaseConfig struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`      // Display name
	APIPath  string     `json:"api_path"`  // URL path segment for agent API (e.g., "mydb")
	Driver   DriverType `json:"driver"`    // mssql, postgres, mysql
	Host     string     `json:"host"`      // Database server host
	Port     int        `json:"port"`      // Database server port
	DBName   string     `json:"db_name"`   // Database name
	Username string     `json:"username"`  // Database username
	Password string     `json:"password"`  // Database password (masked in API responses)
	Active   bool       `json:"active"`    // Enable/disable this connection
}

// DefaultPort returns the default port for a given driver type.
func DefaultPort(driver DriverType) int {
	switch driver {
	case DriverMSSQL:
		return 1433
	case DriverPostgres:
		return 5432
	case DriverMySQL:
		return 3306
	default:
		return 0
	}
}

// DSN builds the data source name for the given config.
func (c *DatabaseConfig) DSN() string {
	port := c.Port
	if port == 0 {
		port = DefaultPort(c.Driver)
	}
	switch c.Driver {
	case DriverMSSQL:
		return fmt.Sprintf("sqlserver://%s:%s@%s:%d?database=%s",
			c.Username, c.Password, c.Host, port, c.DBName)
	case DriverPostgres:
		return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
			c.Username, c.Password, c.Host, port, c.DBName)
	case DriverMySQL:
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
			c.Username, c.Password, c.Host, port, c.DBName)
	default:
		return ""
	}
}

// GoDriverName returns the Go database/sql driver name.
func (c *DatabaseConfig) GoDriverName() string {
	switch c.Driver {
	case DriverMSSQL:
		return "sqlserver"
	case DriverPostgres:
		return "postgres"
	case DriverMySQL:
		return "mysql"
	default:
		return ""
	}
}

// QueryResult holds the result of a SQL query.
type QueryResult struct {
	Columns []string        `json:"columns"`
	Rows    [][]interface{} `json:"rows"`
	Error   string          `json:"error,omitempty"`
}

// Manager manages database connections.
type Manager struct {
	mu      sync.RWMutex
	configs map[string]*DatabaseConfig // keyed by ID
	conns   map[string]*sql.DB         // keyed by ID, lazily created
}

// NewManager creates a new database manager.
func NewManager() *Manager {
	return &Manager{
		configs: make(map[string]*DatabaseConfig),
		conns:   make(map[string]*sql.DB),
	}
}

// Add registers a new database config.
func (m *Manager) Add(c DatabaseConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configs[c.ID] = &c
	// Close any existing connection with this ID.
	if db, ok := m.conns[c.ID]; ok {
		db.Close()
		delete(m.conns, c.ID)
	}
}

// Update replaces a database config.
func (m *Manager) Update(c DatabaseConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configs[c.ID] = &c
	// Close existing connection so it gets recreated with new config.
	if db, ok := m.conns[c.ID]; ok {
		db.Close()
		delete(m.conns, c.ID)
	}
	return nil
}

// Get returns a database config by ID.
func (m *Manager) Get(id string) (*DatabaseConfig, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.configs[id]
	if !ok {
		return nil, false
	}
	cp := *c
	return &cp, true
}

// GetByAPIPath returns a database config by its API path.
func (m *Manager) GetByAPIPath(apiPath string) (*DatabaseConfig, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, c := range m.configs {
		if c.APIPath == apiPath && c.Active {
			cp := *c
			return &cp, true
		}
	}
	return nil, false
}

// Delete removes a database config and closes its connection.
func (m *Manager) Delete(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.configs, id)
	if db, ok := m.conns[id]; ok {
		db.Close()
		delete(m.conns, id)
	}
}

// List returns all database configs.
func (m *Manager) List() []DatabaseConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]DatabaseConfig, 0, len(m.configs))
	for _, c := range m.configs {
		result = append(result, *c)
	}
	return result
}

// LoadConfigs bulk-loads database configs (used at startup).
func (m *Manager) LoadConfigs(configs []DatabaseConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configs = make(map[string]*DatabaseConfig)
	for i := range configs {
		m.configs[configs[i].ID] = &configs[i]
	}
}

// getConn returns a database connection, creating one if needed.
func (m *Manager) getConn(id string) (*sql.DB, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if db, ok := m.conns[id]; ok {
		return db, nil
	}

	cfg, ok := m.configs[id]
	if !ok {
		return nil, fmt.Errorf("database %q not found", id)
	}
	if !cfg.Active {
		return nil, fmt.Errorf("database %q is not active", id)
	}

	driverName := cfg.GoDriverName()
	if driverName == "" {
		return nil, fmt.Errorf("unsupported driver: %s", cfg.Driver)
	}

	db, err := sql.Open(driverName, cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool.
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)

	m.conns[id] = db
	return db, nil
}

// Query executes a SQL query and returns results.
func (m *Manager) Query(id string, query string, args []interface{}) *QueryResult {
	db, err := m.getConn(id)
	if err != nil {
		return &QueryResult{Error: err.Error()}
	}

	query = strings.TrimSpace(query)
	if query == "" {
		return &QueryResult{Error: "empty query"}
	}

	// Determine if this is a SELECT/read query or a write query.
	upper := strings.ToUpper(query)
	if strings.HasPrefix(upper, "SELECT") || strings.HasPrefix(upper, "WITH") || strings.HasPrefix(upper, "SHOW") || strings.HasPrefix(upper, "DESCRIBE") || strings.HasPrefix(upper, "EXPLAIN") {
		return m.queryRows(db, query, args)
	}
	return m.execStatement(db, query, args)
}

// queryRows executes a SELECT query and returns rows.
func (m *Manager) queryRows(db *sql.DB, query string, args []interface{}) *QueryResult {
	rows, err := db.Query(query, args...)
	if err != nil {
		return &QueryResult{Error: err.Error()}
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return &QueryResult{Error: err.Error()}
	}

	result := &QueryResult{
		Columns: cols,
		Rows:    [][]interface{}{},
	}

	for rows.Next() {
		values := make([]interface{}, len(cols))
		scanArgs := make([]interface{}, len(cols))
		for i := range values {
			scanArgs[i] = &values[i]
		}

		if err := rows.Scan(scanArgs...); err != nil {
			return &QueryResult{Error: err.Error()}
		}

		// Convert []byte to string for JSON serialization.
		row := make([]interface{}, len(cols))
		for i, v := range values {
			if b, ok := v.([]byte); ok {
				row[i] = string(b)
			} else {
				row[i] = v
			}
		}
		result.Rows = append(result.Rows, row)
	}

	if err := rows.Err(); err != nil {
		return &QueryResult{Error: err.Error()}
	}

	return result
}

// execStatement executes a non-SELECT statement.
func (m *Manager) execStatement(db *sql.DB, query string, args []interface{}) *QueryResult {
	result, err := db.Exec(query, args...)
	if err != nil {
		return &QueryResult{Error: err.Error()}
	}

	rowsAffected, _ := result.RowsAffected()
	return &QueryResult{
		Columns: []string{"rows_affected"},
		Rows:    [][]interface{}{{rowsAffected}},
	}
}

// Close closes all open database connections.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, db := range m.conns {
		db.Close()
		delete(m.conns, id)
	}
}
