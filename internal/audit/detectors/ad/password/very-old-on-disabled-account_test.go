package password

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestVeryOldOnDisabledAccount_OnlyDisabledCounted mirrors
// TestVeryOld_DisabledAccountExcluded from the sibling file: the two
// detectors must partition the same population with no overlap and no gap.
func TestVeryOldOnDisabledAccount_OnlyDisabledCounted(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	old := now.AddDate(-2, 0, 0)
	data := &audit.DetectorData{
		IncludeDetails: true,
		Now:            now,
		Users: []types.User{
			{SAMAccountName: "active-old", Disabled: false, PasswordLastSet: old},
			{SAMAccountName: "disabled-old", Disabled: true, PasswordLastSet: old},
		},
	}

	findings := NewVeryOldOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (only the disabled account)", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityLow {
		t.Fatalf("Severity = %s, want low", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "disabled-old" {
		t.Fatalf("AffectedEntities = %+v, want only disabled-old", findings[0].AffectedEntities)
	}
}

// TestVeryOldOnDisabledAccount_EnabledNotFlagged guards the negative case:
// an active account with an old password must not be counted here, even
// though it meets the age condition.
func TestVeryOldOnDisabledAccount_EnabledNotFlagged(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{SAMAccountName: "active-old", Disabled: false, PasswordLastSet: now.AddDate(-2, 0, 0)},
		},
	}

	findings := NewVeryOldOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestVeryOldOnDisabledAccount_DisabledRecentNotFlagged guards a disabled
// account that does not meet the age condition.
func TestVeryOldOnDisabledAccount_DisabledRecentNotFlagged(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{SAMAccountName: "disabled-recent", Disabled: true, PasswordLastSet: now.AddDate(0, -1, 0)},
		},
	}

	findings := NewVeryOldOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestVeryOldOnDisabledAccount_ZeroPasswordLastSetNotFlagged mirrors
// TestVeryOld_ZeroPasswordLastSetNotFlagged from the sibling file: a
// disabled account with a zero PasswordLastSet must not be treated as
// infinitely old.
func TestVeryOldOnDisabledAccount_ZeroPasswordLastSetNotFlagged(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{SAMAccountName: "disabled-unset", Disabled: true},
		},
	}

	findings := NewVeryOldOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestVeryOldOnDisabledAccount_Partition verifies active + twin = total
// without the guard, on the same fixture set.
func TestVeryOldOnDisabledAccount_Partition(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	old := now.AddDate(-2, 0, 0)
	users := []types.User{
		{SAMAccountName: "active-old", Disabled: false, PasswordLastSet: old},
		{SAMAccountName: "disabled-old", Disabled: true, PasswordLastSet: old},
		{SAMAccountName: "active-recent", Disabled: false, PasswordLastSet: now.AddDate(0, -1, 0)},
	}

	activeCount := NewVeryOldDetector().Detect(context.Background(), &audit.DetectorData{Now: now, Users: users})[0].Count
	disabledCount := NewVeryOldOnDisabledAccountDetector().Detect(context.Background(), &audit.DetectorData{Now: now, Users: users})[0].Count

	wantTotal := 0
	for _, u := range users {
		if !u.PasswordLastSet.IsZero() && u.PasswordLastSet.Before(now.AddDate(-1, 0, 0)) {
			wantTotal++
		}
	}
	if activeCount+disabledCount != wantTotal {
		t.Fatalf("active(%d) + disabled(%d) = %d, want %d (no overlap, no gap)", activeCount, disabledCount, activeCount+disabledCount, wantTotal)
	}
}
