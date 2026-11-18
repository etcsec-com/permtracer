package password

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestVeryOld_DisabledAccountExcluded pins the split: a disabled account
// with a password older than 365 days cannot authenticate today, so it
// must not inflate the active population - it is reported separately by
// VeryOldOnDisabledAccountDetector instead.
func TestVeryOld_DisabledAccountExcluded(t *testing.T) {
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

	findings := NewVeryOldDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled account must be excluded)", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityMedium {
		t.Fatalf("Severity = %s, want medium", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "active-old" {
		t.Fatalf("AffectedEntities = %+v, want only active-old", findings[0].AffectedEntities)
	}
}

// TestVeryOld_RecentPasswordNotFlagged guards the negative case.
func TestVeryOld_RecentPasswordNotFlagged(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{SAMAccountName: "active-recent", Disabled: false, PasswordLastSet: now.AddDate(0, -1, 0)},
		},
	}

	findings := NewVeryOldDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestVeryOld_ZeroPasswordLastSetNotFlagged guards the "no password set"
// case: a zero PasswordLastSet must not be treated as infinitely old.
func TestVeryOld_ZeroPasswordLastSetNotFlagged(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{SAMAccountName: "active-unset", Disabled: false},
		},
	}

	findings := NewVeryOldDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}
