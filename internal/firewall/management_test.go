package firewall

import (
	"context"
	"path/filepath"
	"testing"
)

type managementMock struct {
	result Result
	closed int
}

func (m *managementMock) Backend(context.Context) (string, error) { return m.result.Backend, nil }
func (m *managementMock) Ensure(context.Context, string, int) (Result, error) {
	return m.result, nil
}
func (m *managementMock) Close(context.Context, string, int, string) error {
	m.closed++
	return nil
}

func TestManagementFirewallOwnedRuleIsRemoved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "management-firewall.json")
	manager := &managementMock{result: Result{Ownership: Owned, Backend: BackendNFTables}}
	result, err := EnsureManagement(context.Background(), manager, path, 8080)
	if err != nil {
		t.Fatal(err)
	}
	if result.Ownership != Owned {
		t.Fatalf("ownership = %q", result.Ownership)
	}
	if err := CloseManagement(context.Background(), manager, path); err != nil {
		t.Fatal(err)
	}
	if manager.closed != 1 {
		t.Fatalf("close calls = %d", manager.closed)
	}
}

func TestManagementFirewallBorrowedRuleIsPreserved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "management-firewall.json")
	manager := &managementMock{result: Result{Ownership: Borrowed, Backend: BackendUFW}}
	if _, err := EnsureManagement(context.Background(), manager, path, 8080); err != nil {
		t.Fatal(err)
	}
	if err := CloseManagement(context.Background(), manager, path); err != nil {
		t.Fatal(err)
	}
	if manager.closed != 0 {
		t.Fatalf("close calls = %d", manager.closed)
	}
}
