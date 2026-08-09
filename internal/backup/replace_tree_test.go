package backup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReplaceTreeRestoresBothTreesWhenFinalRenameFails(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "live-data")
	configDir := filepath.Join(root, "live-config")
	stagedData := filepath.Join(root, "staged-data")
	stagedConfig := filepath.Join(root, "staged-config")
	for path, marker := range map[string]string{
		dataDir: "old-data", configDir: "old-config",
		stagedData: "new-data", stagedConfig: "new-config",
	} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "marker"), []byte(marker), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	renames := 0
	rename := func(oldPath, newPath string) error {
		renames++
		if renames == 4 {
			return errors.New("injected final rename failure")
		}
		return os.Rename(oldPath, newPath)
	}
	err := replaceTreeWithOps(stagedData, dataDir, stagedConfig, configDir, rename, os.RemoveAll)
	if err == nil {
		t.Fatal("replaceTreeWithOps succeeded despite injected failure")
	}
	assertMarker(t, dataDir, "old-data")
	assertMarker(t, configDir, "old-config")
}

func TestReplaceTreeReportsRollbackFailure(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "live-data")
	configDir := filepath.Join(root, "live-config")
	stagedData := filepath.Join(root, "staged-data")
	stagedConfig := filepath.Join(root, "staged-config")
	for _, path := range []string{dataDir, configDir, stagedData, stagedConfig} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	renames := 0
	rename := func(oldPath, newPath string) error {
		renames++
		if renames == 4 {
			return errors.New("injected final rename failure")
		}
		if renames == 5 {
			return errors.New("injected data rollback failure")
		}
		return os.Rename(oldPath, newPath)
	}
	err := replaceTreeWithOps(stagedData, dataDir, stagedConfig, configDir, rename, os.RemoveAll)
	if err == nil || !strings.Contains(err.Error(), "data rollback failure") {
		t.Fatalf("rollback error not reported: %v", err)
	}
}

func assertMarker(t *testing.T, directory, expected string) {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(directory, "marker"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != expected {
		t.Fatalf("%s marker = %q, want %q", directory, content, expected)
	}
}
