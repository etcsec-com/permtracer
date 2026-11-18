package password

import (
	"context"
	"fmt"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestCommonPatternsOnDisabledAccount_OnlyDisabledCounted mirrors
// TestCommonPatterns_DisabledAccountExcluded from the sibling file: the two
// detectors must partition the same population with no overlap and no gap.
func TestCommonPatternsOnDisabledAccount_OnlyDisabledCounted(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "admin", Disabled: false},
			{SAMAccountName: "administrator", Disabled: true},
		},
	}

	findings := NewCommonPatternsOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (only the disabled account)", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityLow {
		t.Fatalf("Severity = %s, want low", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "administrator" {
		t.Fatalf("AffectedEntities = %+v, want only administrator", findings[0].AffectedEntities)
	}
}

// TestCommonPatternsOnDisabledAccount_EnabledNotFlagged guards the negative
// case: an active account matching a risky pattern must not be counted
// here.
func TestCommonPatternsOnDisabledAccount_EnabledNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "admin", Disabled: false}},
	}

	findings := NewCommonPatternsOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestCommonPatternsOnDisabledAccount_DisabledOrdinaryNameNotFlagged guards
// a disabled account that does not match any risky pattern.
func TestCommonPatternsOnDisabledAccount_DisabledOrdinaryNameNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "jsmith", Disabled: true}},
	}

	findings := NewCommonPatternsOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestCommonPatternsOnDisabledAccount_Partition verifies active + twin =
// total without the guard, on the same fixture set.
func TestCommonPatternsOnDisabledAccount_Partition(t *testing.T) {
	users := []types.User{
		{SAMAccountName: "admin", Disabled: false},
		{SAMAccountName: "administrator", Disabled: true},
		{SAMAccountName: "jsmith", Disabled: false},
	}

	activeCount := NewCommonPatternsDetector().Detect(context.Background(), &audit.DetectorData{Users: users})[0].Count
	disabledCount := NewCommonPatternsOnDisabledAccountDetector().Detect(context.Background(), &audit.DetectorData{Users: users})[0].Count

	if activeCount != 1 || disabledCount != 1 {
		t.Fatalf("active=%d, disabled=%d, want 1 and 1", activeCount, disabledCount)
	}
}

// TestCommonPatternsOnDisabledAccount_TwoPatternsCountedOnce mirrors
// TestCommonPatterns_TwoPatternsCountedOnce: a disabled account matching
// both the "password" substring pattern and the trailing "123$" pattern
// must still be counted once, not once per matching pattern.
func TestCommonPatternsOnDisabledAccount_TwoPatternsCountedOnce(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "password123", Disabled: true}},
	}

	findings := NewCommonPatternsOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (one account matching two patterns must be counted once)", findings[0].Count)
	}
}

// TestCommonPatternsOnDisabledAccount_UnanchoredAdminSubstringNotCounted
// mirrors TestCommonPatterns_UnanchoredAdminSubstringNotCounted: a disabled
// account name that merely contains "admin" as a substring must not be
// flagged by the exact ^admin$ pattern.
func TestCommonPatternsOnDisabledAccount_UnanchoredAdminSubstringNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "labadmin", Disabled: true}},
	}

	findings := NewCommonPatternsOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (labadmin must not match the anchored ^admin$ pattern)", findings[0].Count)
	}
}

// TestCommonPatternsOnDisabledAccount_PasswordSubstringCounted mirrors
// TestCommonPatterns_PasswordSubstringCounted: a disabled account name that
// matches only the "(?i)password" pattern must still be flagged.
func TestCommonPatternsOnDisabledAccount_PasswordSubstringCounted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "xpasswordx", Disabled: true}},
	}

	findings := NewCommonPatternsOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (xpasswordx matches only the password pattern)", findings[0].Count)
	}
}

// TestCommonPatternsOnDisabledAccount_MoreThanTenMatchesAllCounted mirrors
// TestCommonPatterns_MoreThanTenMatchesAllCounted: Count must reflect every
// matching disabled account, not the affectedNames sample capped at 10.
func TestCommonPatternsOnDisabledAccount_MoreThanTenMatchesAllCounted(t *testing.T) {
	var users []types.User
	for i := 1; i <= 11; i++ {
		users = append(users, types.User{
			SAMAccountName: fmt.Sprintf("user%02dpassword", i),
			Disabled:       true,
		})
	}
	data := &audit.DetectorData{Users: users}

	findings := NewCommonPatternsOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 11 {
		t.Fatalf("Count = %d, want 11 (Count must not be capped to the affectedNames sample)", findings[0].Count)
	}
}
