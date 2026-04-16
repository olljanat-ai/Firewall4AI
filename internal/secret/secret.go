// Package secret provides authenticated encryption for sensitive fields
// that are persisted to state.json (credentials, database passwords, skill
// tokens, etc.). It uses AES-256-GCM with a master key stored on the
// persistent partition or supplied via the FIREWALL4AI_MASTER_KEY
// environment variable.
//
// Seal returns an "enc:v1:<base64>" envelope that UnmarshalJSON and JSON
// readers can treat as a normal string. Open reverses the transform; if the
// value has no envelope prefix it is returned unchanged so that existing
// plaintext state.json files continue to load during the migration window.
// The first subsequent save re-encrypts them.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// envelopePrefix marks a value as ciphertext. v1 = AES-256-GCM, random
// 12-byte nonce, base64url(no padding) of nonce||ciphertext||tag.
const envelopePrefix = "enc:v1:"

// masterKeyFile is the filename used to persist the auto-generated key.
const masterKeyFile = "master.key"

// envVar is consulted first: if set, it must decode as exactly 32 bytes
// (AES-256) using either hex or base64. This lets operators externalize
// the key to a TPM unseal or KMS-fetched secret without touching disk.
const envVar = "FIREWALL4AI_MASTER_KEY"

var (
	mu    sync.RWMutex
	aead  cipher.AEAD
	ready bool
)

// Init loads or generates the master key and configures the AEAD cipher.
// It is safe to call multiple times; subsequent calls are no-ops. Returns
// an error only when the caller supplied an env var that cannot be parsed
// or when the data directory is not writable. A generated key is written
// to {dataDir}/master.key with mode 0600.
func Init(dataDir string) error {
	mu.Lock()
	defer mu.Unlock()
	if ready {
		return nil
	}

	key, source, err := loadOrCreateKey(dataDir)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gcm: %w", err)
	}
	aead = gcm
	ready = true
	log.Printf("Master encryption key loaded from %s", source)
	return nil
}

// Reset clears the loaded key. Intended for tests.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	aead = nil
	ready = false
}

// IsSealed reports whether s carries the encryption envelope prefix.
func IsSealed(s string) bool {
	return strings.HasPrefix(s, envelopePrefix)
}

// Seal encrypts plaintext and returns an envelope string. Empty strings
// pass through unchanged (callers use "" as a no-value sentinel, and we
// don't want to change that). Values that are already sealed are returned
// unchanged so the operation is idempotent. If the secret package has not
// been initialized, plaintext is returned unchanged with a warning logged
// once — this is the fail-open path for the brief window during startup
// before Init runs; it should not be reached in production flows.
func Seal(plaintext string) string {
	if plaintext == "" {
		return ""
	}
	if IsSealed(plaintext) {
		return plaintext
	}
	mu.RLock()
	defer mu.RUnlock()
	if !ready {
		warnOnce("Seal called before secret.Init; storing plaintext")
		return plaintext
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		log.Printf("secret.Seal: rand read failed: %v", err)
		return plaintext
	}
	ct := aead.Seal(nil, nonce, []byte(plaintext), nil)
	buf := make([]byte, 0, len(nonce)+len(ct))
	buf = append(buf, nonce...)
	buf = append(buf, ct...)
	return envelopePrefix + base64.RawStdEncoding.EncodeToString(buf)
}

// Open reverses Seal. A value without the envelope prefix is returned
// unchanged (backward compatibility with pre-encryption state.json files).
// If the envelope is present but decryption fails — typically because a
// restored backup was encrypted under a different master key — a warning
// is logged and the empty string is returned. We intentionally return ""
// rather than the ciphertext to fail closed.
func Open(s string) string {
	if !IsSealed(s) {
		return s
	}
	mu.RLock()
	defer mu.RUnlock()
	if !ready {
		warnOnce("Open called before secret.Init; cannot decrypt")
		return ""
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(s, envelopePrefix))
	if err != nil {
		log.Printf("secret.Open: base64 decode failed: %v", err)
		return ""
	}
	if len(raw) < aead.NonceSize() {
		log.Printf("secret.Open: ciphertext too short")
		return ""
	}
	nonce := raw[:aead.NonceSize()]
	ct := raw[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		log.Printf("secret.Open: decrypt failed (key mismatch or tampering?): %v", err)
		return ""
	}
	return string(pt)
}

func loadOrCreateKey(dataDir string) (key []byte, source string, err error) {
	if v := strings.TrimSpace(os.Getenv(envVar)); v != "" {
		k, perr := parseKey(v)
		if perr != nil {
			return nil, "", fmt.Errorf("%s: %w", envVar, perr)
		}
		return k, "environment variable " + envVar, nil
	}

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, "", fmt.Errorf("create data dir: %w", err)
	}
	path := filepath.Join(dataDir, masterKeyFile)
	if raw, rerr := os.ReadFile(path); rerr == nil {
		k, perr := parseKey(strings.TrimSpace(string(raw)))
		if perr != nil {
			return nil, "", fmt.Errorf("%s: %w", path, perr)
		}
		return k, path, nil
	} else if !os.IsNotExist(rerr) {
		return nil, "", rerr
	}

	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, "", fmt.Errorf("generate master key: %w", err)
	}
	encoded := base64.RawStdEncoding.EncodeToString(k) + "\n"
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		return nil, "", fmt.Errorf("write master key: %w", err)
	}
	return k, path + " (newly generated)", nil
}

func parseKey(s string) ([]byte, error) {
	if k, err := hex.DecodeString(s); err == nil && len(k) == 32 {
		return k, nil
	}
	if k, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(k) == 32 {
		return k, nil
	}
	if k, err := base64.StdEncoding.DecodeString(s); err == nil && len(k) == 32 {
		return k, nil
	}
	return nil, errors.New("master key must be 32 bytes (hex or base64)")
}

var warnedMu sync.Mutex
var warned = map[string]bool{}

func warnOnce(msg string) {
	warnedMu.Lock()
	defer warnedMu.Unlock()
	if warned[msg] {
		return
	}
	warned[msg] = true
	log.Printf("WARNING: %s", msg)
}
