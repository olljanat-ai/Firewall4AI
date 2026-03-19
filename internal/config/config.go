package config
 
import (
	"encoding/json"
	"os"
	"sync"
)
 
// Config holds the main application configuration.
type Config struct {
	ListenAddr    string `json:"listen_addr"`
	AdminAddr     string `json:"admin_addr"`
	DataDir       string `json:"data_dir"`
	TLSCertFile   string `json:"tls_cert_file"`
	TLSKeyFile    string `json:"tls_key_file"`
	MaxLogEntries int    `json:"max_log_entries"`
}
 
var (
	defaultConfig = Config{
		ListenAddr:    ":8080",
		AdminAddr:     ":443",
		DataDir:       "./data",
		MaxLogEntries: 10000,
	}
	current Config
	mu      sync.RWMutex
)
 
// Load reads config from a JSON file or returns defaults.
func Load(path string) (Config, error) {
	mu.Lock()
	defer mu.Unlock()
 
	current = defaultConfig
	if path == "" {
		return current, nil
	}
 
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return current, nil
		}
		return current, err
	}
	if err := json.Unmarshal(data, &current); err != nil {
		return current, err
	}
	return current, nil
}
 
// Get returns the current config.
func Get() Config {
	mu.RLock()
	defer mu.RUnlock()
	return current
}
