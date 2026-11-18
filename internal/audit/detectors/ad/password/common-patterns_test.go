package password

import (
	"context"
	"fmt"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestCommonPatterns_DisabledAccountExcluded pins the existing guard: a
// disabled account named after a risky pattern must not inflate the active
// population - it is reported separately by
// CommonPatternsOnDisabledAccountDetector instead.
func TestCommonPatterns_DisabledAccountExcluded(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "admin", Disabled: false},
			{SAMAccountName: "administrator", Disabled: true},
		},
	}

	findings := NewCommonPatternsDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled account must be excluded)", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Fatalf("Severity = %s, want high", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "admin" {
		t.Fatalf("AffectedEntities = %+v, want only admin", findings[0].AffectedEntities)
	}
}

// TestCommonPatterns_OrdinaryNameNotFlagged guards the negative case.
func TestCommonPatterns_OrdinaryNameNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "jsmith", Disabled: false}},
	}

	findings := NewCommonPatternsDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestCommonPatterns_TwoPatternsCountedOnce guards the "break" after the
// first pattern match: an account matching both the "password" substring
// pattern and the trailing "123$" pattern must still be counted once, not
// once per matching pattern.
func TestCommonPatterns_TwoPatternsCountedOnce(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "password123", Disabled: false}},
	}

	findings := NewCommonPatternsDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (one account matching two patterns must be counted once)", findings[0].Count)
	}
}

// TestCommonPatterns_UnanchoredAdminSubstringNotCounted guards the anchoring
// of the "admin" pattern: a name that merely contains "admin" as a substring
// must not be flagged by the exact ^admin$ pattern.
func TestCommonPatterns_UnanchoredAdminSubstringNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "labadmin", Disabled: false}},
	}

	findings := NewCommonPatternsDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (labadmin must not match the anchored ^admin$ pattern)", findings[0].Count)
	}
}

// TestCommonPatterns_PasswordSubstringCounted guards the "(?i)password"
// pattern itself: a name that matches only that pattern (no anchored
// pattern, no trailing 123) must still be flagged.
func TestCommonPatterns_PasswordSubstringCounted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "xpasswordx", Disabled: false}},
	}

	findings := NewCommonPatternsDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (xpasswordx matches only the password pattern)", findings[0].Count)
	}
}

// TestCommonPatterns_MoreThanTenMatchesAllCounted guards Count against the
// affectedNames cap: affectedNames is capped at 10 entries for display, but
// Count must reflect every matching account, not the capped sample.
func TestCommonPatterns_MoreThanTenMatchesAllCounted(t *testing.T) {
	var users []types.User
	for i := 1; i <= 11; i++ {
		users = append(users, types.User{
			SAMAccountName: fmt.Sprintf("user%02dpassword", i),
			Disabled:       false,
		})
	}
	data := &audit.DetectorData{Users: users}

	findings := NewCommonPatternsDetector().Detect(context.Background(), data)
	if findings[0].Count != 11 {
		t.Fatalf("Count = %d, want 11 (Count must not be capped to the affectedNames sample)", findings[0].Count)
	}
}
