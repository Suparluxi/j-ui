package secure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSealerRoundTrip(t *testing.T) {
	sealer, err := NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := sealer.Seal([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := sealer.Open(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "secret" {
		t.Fatalf("plain = %q", plain)
	}
}

func TestLoadExistingKeyRestrictsPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	if err := os.WriteFile(path, make([]byte, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o, want 600", info.Mode().Perm())
	}
}

func TestUUID(t *testing.T) {
	value, err := UUID()
	if err != nil {
		t.Fatal(err)
	}
	if len(value) != 36 || strings.Count(value, "-") != 4 {
		t.Fatalf("invalid UUID %q", value)
	}
}
