package password

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestCleartextStorageOnDisabledAccount_OnlyDisabledCounted mirrors
// TestCleartextStorage_DisabledUserPasswordExcluded from the sibling file:
// the two detectors must partition the same population with no overlap and
// no gap.
func TestCleartextStorageOnDisabledAccount_OnlyDisabledCounted(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "active-userpassword", Disabled: false, UserPassword: true, UnixUserPassword: false},
			{SAMAccountName: "disabled-userpassword", Disabled: true, UserPassword: true, UnixUserPassword: false},
		},
	}

	findings := NewCleartextStorageOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (only the disabled account)", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityMedium {
		t.Fatalf("Severity = %s, want medium", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "disabled-userpassword" {
		t.Fatalf("AffectedEntities = %+v, want only disabled-userpassword", findings[0].AffectedEntities)
	}
}

// TestCleartextStorageOnDisabledAccount_EnabledNotFlagged guards the
// negative case: an active account carrying the attribute must not be
// counted here.
func TestCleartextStorageOnDisabledAccount_EnabledNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "active-userpassword", Disabled: false, UserPassword: true}},
	}

	findings := NewCleartextStorageOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestCleartextStorageOnDisabledAccount_NeitherAttributeNotFlagged guards
// a disabled account that carries neither attribute.
func TestCleartextStorageOnDisabledAccount_NeitherAttributeNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "disabled-ordinary", Disabled: true}},
	}

	findings := NewCleartextStorageOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestCleartextStorageOnDisabledAccount_UnixUserPasswordOnlyFires mirrors
// TestCleartextStorage_ActiveUnixUserPasswordOnlyFires from the sibling
// file for the disabled twin: a disabled account carrying only
// unixUserPassword (not userPassword) must still be counted, guarding the
// `u.UnixUserPassword ||` operand of the OR on its own.
func TestCleartextStorageOnDisabledAccount_UnixUserPasswordOnlyFires(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{DN: "CN=disabled-unixuserpassword,CN=Users,DC=corp,DC=local", SAMAccountName: "disabled-unixuserpassword", Disabled: true, UserPassword: false, UnixUserPassword: true},
		},
	}

	findings := NewCleartextStorageOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "disabled-unixuserpassword" {
		t.Fatalf("AffectedEntities = %+v, want only disabled-unixuserpassword", findings[0].AffectedEntities)
	}
}

// TestCleartextStorageOnDisabledAccount_Partition verifies active + twin =
// total without the guard, on the same fixture set.
func TestCleartextStorageOnDisabledAccount_Partition(t *testing.T) {
	users := []types.User{
		{SAMAccountName: "active-userpassword", Disabled: false, UserPassword: true},
		{SAMAccountName: "disabled-userpassword", Disabled: true, UserPassword: true},
		{SAMAccountName: "active-ordinary", Disabled: false},
	}

	activeCount := NewCleartextStorageDetector().Detect(context.Background(), &audit.DetectorData{Users: users})[0].Count
	disabledCount := NewCleartextStorageOnDisabledAccountDetector().Detect(context.Background(), &audit.DetectorData{Users: users})[0].Count

	if activeCount != 1 || disabledCount != 1 {
		t.Fatalf("active=%d, disabled=%d, want 1 and 1", activeCount, disabledCount)
	}
}
