package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSaveReplacesPermissiveConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	config := DefaultConfig()
	config.WireGuard.PrivateKey = "test-secret"
	if err := config.SaveToFile(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("permissions=%o", info.Mode().Perm())
	}
	var loaded Config
	if err := LoadFromFile(path, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.WireGuard.PrivateKey != config.WireGuard.PrivateKey {
		t.Fatal("configuration lost")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary file residue: %v %v", entries, err)
	}
}
