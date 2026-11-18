package password

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestCannotChangeOnDisabledAccount_DisabledWithDenyACECounted is the
// positive case: a disabled account carrying the Deny ACE is counted by the
// twin, at Low.
func TestCannotChangeOnDisabledAccount_DisabledWithDenyACECounted(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users:          []types.User{{SAMAccountName: "blocked-disabled", DN: "CN=blocked-disabled,DC=example,DC=com", Disabled: true}},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=blocked-disabled,DC=example,DC=com", Trustee: sidSelf, AceType: "ACCESS_DENIED_OBJECT", ObjectType: testChangePasswordGUID},
		},
	}

	findings := NewCannotChangeOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityLow {
		t.Fatalf("Severity = %s, want low", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "blocked-disabled" {
		t.Fatalf("AffectedEntities = %+v, want only blocked-disabled", findings[0].AffectedEntities)
	}
}

// TestCannotChangeOnDisabledAccount_ActiveNotCounted mirrors
// TestCannotChange_DisabledAccountExcluded from the sibling file: an active
// account carrying the Deny ACE must not be counted by the twin - it is
// reported by CannotChangeDetector instead, at Medium.
func TestCannotChangeOnDisabledAccount_ActiveNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "blocked-active", DN: "CN=blocked-active,DC=example,DC=com", Disabled: false}},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=blocked-active,DC=example,DC=com", Trustee: sidEveryone, AceType: "ACCESS_DENIED_OBJECT", ObjectType: testChangePasswordGUID},
		},
	}

	findings := NewCannotChangeOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestCannotChangeOnDisabledAccount_DisabledWithoutDenyACENotCounted guards
// the negative case: a disabled account with no Deny ACE on the right must
// not be counted.
func TestCannotChangeOnDisabledAccount_DisabledWithoutDenyACENotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "clean-disabled", DN: "CN=clean-disabled,DC=example,DC=com", Disabled: true}},
	}

	findings := NewCannotChangeOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestCannotChangeOnDisabledAccount_UnknownObjectDNNotCounted mirrors
// TestCannotChange_UnknownObjectDNNotCounted: a Deny ACE whose ObjectDN
// matches no entry in data.Users cannot be attributed to the disabled
// population either - there is no user record to confirm it IS disabled.
func TestCannotChangeOnDisabledAccount_UnknownObjectDNNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "someone-else", DN: "CN=someone-else,DC=example,DC=com", Disabled: true}},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=ghost-object,DC=example,DC=com", Trustee: sidEveryone, AceType: "ACCESS_DENIED_OBJECT", ObjectType: testChangePasswordGUID},
		},
	}

	findings := NewCannotChangeOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: the Deny ACE's ObjectDN matches no known user", findings[0].Count)
	}
}

// TestCannotChangePartition_ActiveAndDisabledCoverTotalWithNoOverlap is the
// partition requirement: on one dataset mixing active and disabled accounts,
// with and without the Deny ACE, CannotChangeDetector's Count plus
// CannotChangeOnDisabledAccountDetector's Count must equal the number of
// distinct blocked DNs that blockedChangePasswordDNs resolves against known
// users - the condition with no Disabled guard at all - with neither
// detector counting the other's account.
func TestCannotChangePartition_ActiveAndDisabledCoverTotalWithNoOverlap(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "blocked-active", DN: "CN=blocked-active,DC=example,DC=com", Disabled: false},
			{SAMAccountName: "blocked-disabled", DN: "CN=blocked-disabled,DC=example,DC=com", Disabled: true},
			{SAMAccountName: "clean-active", DN: "CN=clean-active,DC=example,DC=com", Disabled: false},
			{SAMAccountName: "clean-disabled", DN: "CN=clean-disabled,DC=example,DC=com", Disabled: true},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=blocked-active,DC=example,DC=com", Trustee: sidEveryone, AceType: "ACCESS_DENIED_OBJECT", ObjectType: testChangePasswordGUID},
			{ObjectDN: "CN=blocked-disabled,DC=example,DC=com", Trustee: sidSelf, AceType: "ACCESS_DENIED_OBJECT", ObjectType: testChangePasswordGUID},
		},
	}

	activeFindings := NewCannotChangeDetector().Detect(context.Background(), data)
	disabledFindings := NewCannotChangeOnDisabledAccountDetector().Detect(context.Background(), data)

	totalWithoutGuard := len(blockedChangePasswordDNs(data.ACLEntries))
	if activeFindings[0].Count != 1 {
		t.Fatalf("active Count = %d, want 1", activeFindings[0].Count)
	}
	if disabledFindings[0].Count != 1 {
		t.Fatalf("disabled Count = %d, want 1", disabledFindings[0].Count)
	}
	if activeFindings[0].Count+disabledFindings[0].Count != totalWithoutGuard {
		t.Fatalf("active(%d) + disabled(%d) = %d, want %d (the Disabled guard must partition, not drop or double-count)",
			activeFindings[0].Count, disabledFindings[0].Count,
			activeFindings[0].Count+disabledFindings[0].Count, totalWithoutGuard)
	}
}
