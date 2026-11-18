package password

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func detectServiceAccountPolicyOnDisabledAccount(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewServiceAccountWeakPasswordPolicyOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

func TestServiceAccountPolicyOnDisabledAccount_DisabledUncoveredCounted(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{DN: "CN=svc.old,DC=example,DC=com", SAMAccountName: "svc.old", ServicePrincipalNames: []string{"HOST/old01"}, Disabled: true},
		},
	}
	f := detectServiceAccountPolicyOnDisabledAccount(t, data)
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (the disabled, uncovered service account must be counted by the twin)", f.Count)
	}
	if len(f.AffectedEntities) != 1 {
		t.Fatalf("len(AffectedEntities) = %d, want 1", len(f.AffectedEntities))
	}
}

func TestServiceAccountPolicyOnDisabledAccount_DisabledCoveredNotCounted(t *testing.T) {
	f := detectServiceAccountPolicyOnDisabledAccount(t, &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc.old,DC=example,DC=com", SAMAccountName: "svc.old", ServicePrincipalNames: []string{"HOST/old01"}, Disabled: true},
		},
		FGPPs: []types.FGPP{
			{DN: "CN=strong-pso,DC=example,DC=com", MinPasswordLength: 20, AppliesTo: []string{"CN=svc.old,DC=example,DC=com"}},
		},
	})
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (a 20-char PSO applies directly to the disabled account)", f.Count)
	}
}

func TestServiceAccountPolicyOnDisabledAccount_EnabledNotCounted(t *testing.T) {
	f := detectServiceAccountPolicyOnDisabledAccount(t, &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc.sql,DC=example,DC=com", SAMAccountName: "svc.sql", ServicePrincipalNames: []string{"MSSQLSvc/db01:1433"}},
		},
	})
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (the only service account is active and must be excluded from the disabled-account twin)", f.Count)
	}
}

func TestServiceAccountPolicyOnDisabledAccount_NoServiceAccounts_CountZero(t *testing.T) {
	f := detectServiceAccountPolicyOnDisabledAccount(t, &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=alice,DC=example,DC=com", SAMAccountName: "alice", Disabled: true},
		},
	})
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (no account matches the service-account heuristic)", f.Count)
	}
}

// TestServiceAccountPolicy_ActiveAndDisabledPartition is the partition
// guard: given a mix of active and disabled service accounts, none covered
// by any policy, the active detector's Count plus the disabled twin's Count
// must equal the total number of service accounts - each account is
// claimed by exactly one of the two detectors, never both and never
// neither.
func TestServiceAccountPolicy_ActiveAndDisabledPartition(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc.sql,DC=example,DC=com", SAMAccountName: "svc.sql", ServicePrincipalNames: []string{"MSSQLSvc/db01:1433"}},
			{DN: "CN=svc.web,DC=example,DC=com", SAMAccountName: "svc.web", ServicePrincipalNames: []string{"HTTP/web01:443"}},
			{DN: "CN=svc.old,DC=example,DC=com", SAMAccountName: "svc.old", ServicePrincipalNames: []string{"HOST/old01"}, Disabled: true},
		},
	}

	active := detectServiceAccountPolicy(t, data)
	disabled := detectServiceAccountPolicyOnDisabledAccount(t, data)

	if active.Count != 2 {
		t.Fatalf("active.Count = %d, want 2 (svc.sql and svc.web)", active.Count)
	}
	if disabled.Count != 1 {
		t.Fatalf("disabled.Count = %d, want 1 (svc.old)", disabled.Count)
	}
	if total := active.Count + disabled.Count; total != len(data.Users) {
		t.Fatalf("active.Count + disabled.Count = %d, want %d (every service account claimed exactly once)", total, len(data.Users))
	}
}

