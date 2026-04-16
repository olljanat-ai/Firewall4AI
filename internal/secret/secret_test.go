package secret

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setup(t *testing.T) string {
	t.Helper()
	Reset()
	os.Unsetenv(envVar)
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return dir
}

func TestSealOpen_Roundtrip(t *testing.T) {
	setup(t)
	for _, pt := range []string{
		"hunter2",
		"",
		"x",
		"Bearer eyJhbGciOiJIUzI1NiJ9.abc.xyz",
		"contains=special&chars;🔒",
	} {
		sealed := Seal(pt)
		if pt == "" {
			if sealed != "" {
				t.Errorf("empty input should seal to empty, got %q", sealed)
			}
			continue
		}
		if !IsSealed(sealed) {
			t.Errorf("expected envelope prefix on %q, got %q", pt, sealed)
		}
		if got := Open(sealed); got != pt {
			t.Errorf("Open(Seal(%q)) = %q", pt, got)
		}
	}
}

func TestSeal_Idempotent(t *testing.T) {
	setup(t)
	first := Seal("p")
	second := Seal(first)
	if first != second {
		t.Errorf("Seal should be idempotent on already-sealed input\n first=%s\nsecond=%s", first, second)
	}
}

func TestOpen_PlaintextPassthrough(t *testing.T) {
	setup(t)
	if got := Open("not-encrypted"); got != "not-encrypted" {
		t.Errorf("plaintext should pass through, got %q", got)
	}
	if got := Open(""); got != "" {
		t.Errorf("empty should pass through, got %q", got)
	}
}

func TestOpen_WrongKeyReturnsEmpty(t *testing.T) {
	dir := setup(t)
	sealed := Seal("p")

	// Rotate the master key: wipe file, re-init.
	Reset()
	if err := os.Remove(filepath.Join(dir, masterKeyFile)); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}

	got := Open(sealed)
	if got != "" {
		t.Errorf("Open with rotated key should fail closed to \"\", got %q", got)
	}
}

func TestInit_UsesEnvVar(t *testing.T) {
	Reset()
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	t.Setenv(envVar, base64.RawStdEncoding.EncodeToString(key))

	if err := Init(dir); err != nil {
		t.Fatalf("Init: %v", err)
	}
	// No master.key file should have been created.
	if _, err := os.Stat(filepath.Join(dir, masterKeyFile)); !os.IsNotExist(err) {
		t.Errorf("master.key should not be created when env var is set (err=%v)", err)
	}

	sealed := Seal("p")
	if got := Open(sealed); got != "p" {
		t.Errorf("roundtrip with env-supplied key failed: got %q", got)
	}
}

func TestInit_RejectsShortKey(t *testing.T) {
	Reset()
	t.Setenv(envVar, base64.RawStdEncoding.EncodeToString([]byte("tooshort")))
	err := Init(t.TempDir())
	if err == nil {
		t.Fatal("expected error for short key")
	}
	if !strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("error should mention 32-byte requirement, got %v", err)
	}
}

func TestInit_PersistsGeneratedKey(t *testing.T) {
	Reset()
	os.Unsetenv(envVar)
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(dir, masterKeyFile))
	if err != nil {
		t.Fatalf("master.key should exist after first Init: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("master.key perms = %o, want 0600", perm)
	}

	sealed := Seal("p")

	// Reinit from disk, ensure we decrypt the same value.
	Reset()
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	if got := Open(sealed); got != "p" {
		t.Errorf("roundtrip across re-Init failed: got %q", got)
	}
}

func TestSeal_FailOpenWhenNotInitialized(t *testing.T) {
	Reset()
	got := Seal("p")
	if got != "p" {
		t.Errorf("Seal before Init should return plaintext unchanged, got %q", got)
	}
}

func TestOpen_FailClosedWhenNotInitialized(t *testing.T) {
	Reset()
	got := Open("enc:v1:garbage")
	if got != "" {
		t.Errorf("Open before Init should return \"\", got %q", got)
	}
}
