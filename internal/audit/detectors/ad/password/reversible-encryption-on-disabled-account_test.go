package password

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestReversibleEncryptionOnDisabledAccount_OnlyDisabledCounted mirrors
// TestReversibleEncryption_DisabledAccountExcluded from the sibling file:
// the two detectors must partition the same population with no overlap and
// no gap.
// Fixtures use realistic multi-bit UAC values (0x280 active, 0x282
// disabled) rather than the bare 0x80 literal, for the same reason as the
// active detector's test.
func TestReversibleEncryptionOnDisabledAccount_OnlyDisabledCounted(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "active-reversible", UserAccountControl: 0x280, Disabled: false},
			{SAMAccountName: "stale-reversible", UserAccountControl: 0x282, Disabled: true},
		},
	}

	findings := NewReversibleEncryptionOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (only the disabled account)", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityMedium {
		t.Fatalf("Severity = %s, want medium", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "stale-reversible" {
		t.Fatalf("AffectedEntities = %+v, want only stale-reversible", findings[0].AffectedEntities)
	}
}

// TestReversibleEncryptionOnDisabledAccount_EnabledNotFlagged guards the
// negative case: an active account carrying the flag must not be counted
// here.
func TestReversibleEncryptionOnDisabledAccount_EnabledNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "active-reversible", UserAccountControl: 0x280, Disabled: false}},
	}

	findings := NewReversibleEncryptionOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestReversibleEncryptionOnDisabledAccount_FlagNotSetNotFlagged guards a
// disabled account that does not carry the flag.
func TestReversibleEncryptionOnDisabledAccount_FlagNotSetNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "disabled-ordinary", UserAccountControl: 0x202, Disabled: true}},
	}

	findings := NewReversibleEncryptionOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestReversibleEncryptionOnDisabledAccount_Partition verifies active +
// twin = total without the guard, on the same fixture set.
func TestReversibleEncryptionOnDisabledAccount_Partition(t *testing.T) {
	users := []types.User{
		{SAMAccountName: "active-reversible", UserAccountControl: 0x280, Disabled: false},
		{SAMAccountName: "stale-reversible", UserAccountControl: 0x282, Disabled: true},
		{SAMAccountName: "active-ordinary", UserAccountControl: 0x200, Disabled: false},
	}

	activeCount := NewReversibleEncryptionDetector().Detect(context.Background(), &audit.DetectorData{Users: users})[0].Count
	disabledCount := NewReversibleEncryptionOnDisabledAccountDetector().Detect(context.Background(), &audit.DetectorData{Users: users})[0].Count

	if activeCount != 1 || disabledCount != 1 {
		t.Fatalf("active=%d, disabled=%d, want 1 and 1", activeCount, disabledCount)
	}
}
