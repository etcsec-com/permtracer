package monitoring

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestAdminAuditBypassOnDisabledAccount_SplitByAccountState is the
// table-driven lock for the active/disabled split: an enabled account
// triggers only the active detector, a disabled one triggers only its
// twin, for the identical set of other conditions (adminCount=1, outside
// Protected Users, stale password).
func TestAdminAuditBypassOnDisabledAccount_SplitByAccountState(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name            string
		disabled        bool
		wantActiveCount int
		wantTwinCount   int
	}{
		{name: "enabled admin outside Protected Users with stale password", disabled: false, wantActiveCount: 1, wantTwinCount: 0},
		{name: "disabled admin outside Protected Users with stale password", disabled: true, wantActiveCount: 0, wantTwinCount: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{
				Now: now,
				Users: []types.User{
					{
						SAMAccountName:  "admin-split",
						AdminCount:      true,
						Disabled:        tc.disabled,
						PasswordLastSet: now.AddDate(-1, 0, 0),
					},
				},
			}

			activeFindings := NewAdminAuditBypassDetector().Detect(context.Background(), data)
			if activeFindings[0].Count != tc.wantActiveCount {
				t.Fatalf("active detector Count = %d, want %d", activeFindings[0].Count, tc.wantActiveCount)
			}

			twinFindings := NewAdminAuditBypassOnDisabledAccountDetector().Detect(context.Background(), data)
			if twinFindings[0].Count != tc.wantTwinCount {
				t.Fatalf("twin detector Count = %d, want %d", twinFindings[0].Count, tc.wantTwinCount)
			}
		})
	}
}

// TestAdminAuditBypassOnDisabledAccount_ProtectedByRealSID: a disabled
// admin who IS a member of the real -525 group must not be flagged by the
// twin.
func TestAdminAuditBypassOnDisabledAccount_ProtectedByRealSID(t *testing.T) {
	d := NewAdminAuditBypassOnDisabledAccountDetector()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	puDN := "CN=Protected Users,CN=Users,DC=example,DC=com"
	puSID := "S-1-5-21-1111111111-2222222222-3333333333-525"

	data := &audit.DetectorData{
		Now: now,
		Groups: []types.Group{
			{CN: "Protected Users", SAMAccountName: "Protected Users", DN: puDN, ObjectSID: puSID},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			puSID: {DN: puDN, SID: puSID, EntityType: types.EntityTypeGroup},
		},
		Users: []types.User{
			{
				SAMAccountName:  "admin-protected-disabled",
				AdminCount:      true,
				Disabled:        true,
				PasswordLastSet: now.AddDate(-1, 0, 0),
				MemberOf:        []string{puDN},
			},
		},
	}

	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (disabled admin already in the real Protected Users group must not be flagged)", findings[0].Count)
	}
}

// TestAdminAuditBypassOnDisabledAccount_HomonymProtectedUsersNotTrusted
// mirrors the active detector's homonym test on the disabled side: a group
// literally named "Protected Users" but with an ordinary RID grants no
// protection.
func TestAdminAuditBypassOnDisabledAccount_HomonymProtectedUsersNotTrusted(t *testing.T) {
	d := NewAdminAuditBypassOnDisabledAccountDetector()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	homonymDN := "CN=Protected Users,CN=Marketing,DC=example,DC=com"
	homonymSID := "S-1-5-21-1111111111-2222222222-3333333333-9108"

	data := &audit.DetectorData{
		Now: now,
		Groups: []types.Group{
			{CN: "Protected Users", SAMAccountName: "Protected Users", DN: homonymDN, ObjectSID: homonymSID},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			homonymSID: {DN: homonymDN, SID: homonymSID, EntityType: types.EntityTypeGroup},
		},
		Users: []types.User{
			{
				SAMAccountName:  "admin-homonym-disabled",
				AdminCount:      true,
				Disabled:        true,
				PasswordLastSet: now.AddDate(-1, 0, 0),
				MemberOf:        []string{homonymDN},
			},
		},
	}

	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (homonym \"Protected Users\" group with an ordinary RID must not count as real protection)", findings[0].Count)
	}
}

// TestAdminAuditBypassOnDisabledAccount_NonAdminCountAccountNotFlagged
// mirrors the active detector's AdminCount test on the disabled side: a
// disabled account outside Protected Users with a stale password must only
// be flagged by the twin when AdminCount is actually set.
func TestAdminAuditBypassOnDisabledAccount_NonAdminCountAccountNotFlagged(t *testing.T) {
	d := NewAdminAuditBypassOnDisabledAccountDetector()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		adminCount bool
		wantCount  int
	}{
		{name: "ordinary disabled account (AdminCount=false) outside Protected Users: not flagged", adminCount: false, wantCount: 0},
		{name: "privileged disabled account (AdminCount=true) outside Protected Users: flagged", adminCount: true, wantCount: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{
				Now: now,
				Users: []types.User{
					{
						SAMAccountName:  "ordinary-user-disabled",
						AdminCount:      tc.adminCount,
						Disabled:        true,
						PasswordLastSet: now.AddDate(-1, 0, 0),
					},
				},
			}

			findings := d.Detect(context.Background(), data)
			if findings[0].Count != tc.wantCount {
				t.Fatalf("Count = %d, want %d", findings[0].Count, tc.wantCount)
			}
		})
	}
}

// TestAdminAuditBypassOnDisabledAccount_A8_RecentPasswordNotCounted mirrors
// the active detector's A8 lock on the disabled side: a password set well
// within the last six months must not be counted.
func TestAdminAuditBypassOnDisabledAccount_A8_RecentPasswordNotCounted(t *testing.T) {
	d := NewAdminAuditBypassOnDisabledAccountDetector()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{SAMAccountName: "admin-recent-disabled", AdminCount: true, Disabled: true, PasswordLastSet: now.AddDate(0, -1, 0)},
		},
	}

	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (password set 1 month ago is within the six-month window)", findings[0].Count)
	}
}

// TestAdminAuditBypassOnDisabledAccount_A9_PasswordJustUnderSixMonthsNotCounted
// mirrors the active detector's A9 lock: a password aged about five and a
// half months is younger than the six-month cutoff and must not be counted.
func TestAdminAuditBypassOnDisabledAccount_A9_PasswordJustUnderSixMonthsNotCounted(t *testing.T) {
	d := NewAdminAuditBypassOnDisabledAccountDetector()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{SAMAccountName: "admin-five-half-disabled", AdminCount: true, Disabled: true, PasswordLastSet: now.AddDate(0, -5, -15)},
		},
	}

	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (password aged ~5.5 months is younger than the six-month cutoff)", findings[0].Count)
	}
}

// TestAdminAuditBypassOnDisabledAccount_A10_PasswordJustOverSixMonthsCounted
// mirrors the active detector's A10 lock: a password aged about six and a
// half months is older than the six-month cutoff and must be counted.
func TestAdminAuditBypassOnDisabledAccount_A10_PasswordJustOverSixMonthsCounted(t *testing.T) {
	d := NewAdminAuditBypassOnDisabledAccountDetector()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{SAMAccountName: "admin-six-half-disabled", AdminCount: true, Disabled: true, PasswordLastSet: now.AddDate(0, -6, -15)},
		},
	}

	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (password aged ~6.5 months is older than the six-month cutoff)", findings[0].Count)
	}
}

// TestAdminAuditBypassOnDisabledAccount_A13_DetailsPopulatedOnPositiveFinding
// mirrors the active detector's A13 lock: a positive finding always carries
// the Details block, keyed exactly as the detector builds it.
func TestAdminAuditBypassOnDisabledAccount_A13_DetailsPopulatedOnPositiveFinding(t *testing.T) {
	d := NewAdminAuditBypassOnDisabledAccountDetector()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{SAMAccountName: "admin-positive-disabled", AdminCount: true, Disabled: true, PasswordLastSet: now.AddDate(-1, 0, 0)},
		},
	}

	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (precondition for a positive finding)", findings[0].Count)
	}
	if findings[0].Details == nil {
		t.Fatalf("Details is nil, want a populated Details block for a positive finding")
	}
	if got, ok := findings[0].Details["adminsWithOldPasswords"]; !ok || got != 1 {
		t.Fatalf(`Details["adminsWithOldPasswords"] = %v (ok=%v), want 1`, got, ok)
	}
}

// TestAdminAuditBypassOnDisabledAccount_A15_IncludeDetailsTruePopulatesAffectedEntities
// mirrors the active detector's A15 lock: AffectedEntities is populated for
// a positive finding when the caller requests IncludeDetails.
func TestAdminAuditBypassOnDisabledAccount_A15_IncludeDetailsTruePopulatesAffectedEntities(t *testing.T) {
	d := NewAdminAuditBypassOnDisabledAccountDetector()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	data := &audit.DetectorData{
		Now:            now,
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "admin-included-disabled", AdminCount: true, Disabled: true, PasswordLastSet: now.AddDate(-1, 0, 0)},
		},
	}

	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (precondition for a positive finding)", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) == 0 {
		t.Fatalf("AffectedEntities is empty, want it populated when IncludeDetails=true")
	}
}

// TestAdminAuditBypassOnDisabledAccount_A16_IncludeDetailsFalseAffectedEntitiesNil
// mirrors the active detector's A16 lock: AffectedEntities must stay empty
// for a positive finding when the caller does not request IncludeDetails.
func TestAdminAuditBypassOnDisabledAccount_A16_IncludeDetailsFalseAffectedEntitiesNil(t *testing.T) {
	d := NewAdminAuditBypassOnDisabledAccountDetector()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	data := &audit.DetectorData{
		Now:            now,
		IncludeDetails: false,
		Users: []types.User{
			{SAMAccountName: "admin-excluded-disabled", AdminCount: true, Disabled: true, PasswordLastSet: now.AddDate(-1, 0, 0)},
		},
	}

	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (precondition for a positive finding)", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 0 {
		t.Fatalf("AffectedEntities = %v, want empty when IncludeDetails=false", findings[0].AffectedEntities)
	}
}
