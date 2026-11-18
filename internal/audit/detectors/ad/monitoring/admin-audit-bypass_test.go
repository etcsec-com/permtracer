package monitoring

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestAdminAuditBypass_DescribesCredentialTheftNotAuditBypass locks in the
// fix for the mislabeled claim that Protected Users membership is an audit
// control: it protects against credential theft (NTLM, weak Kerberos, cached
// credentials), it does not enable or disable auditing.
func TestAdminAuditBypass_DescribesCredentialTheftNotAuditBypass(t *testing.T) {
	d := NewAdminAuditBypassDetector()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	t.Run("title and description no longer claim an audit-bypass capability", func(t *testing.T) {
		data := &audit.DetectorData{Now: now}
		findings := d.Detect(context.Background(), data)
		title := strings.ToLower(findings[0].Title)
		desc := strings.ToLower(findings[0].Description)
		if strings.Contains(title, "bypass audit") || strings.Contains(desc, "bypass audit controls") {
			t.Fatalf("finding still claims audit-bypass: title=%q description=%q", findings[0].Title, findings[0].Description)
		}
		if !strings.Contains(desc, "credential") {
			t.Fatalf("expected description to describe credential-theft exposure, got %q", findings[0].Description)
		}
	})

	t.Run("privileged account outside Protected Users with a stale password: flagged", func(t *testing.T) {
		data := &audit.DetectorData{
			Now: now,
			Users: []types.User{
				{SAMAccountName: "admin1", AdminCount: true, PasswordLastSet: now.AddDate(-1, 0, 0)},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("expected count=1, got %d", findings[0].Count)
		}
	})

	t.Run("privileged account in Protected Users: not flagged", func(t *testing.T) {
		data := &audit.DetectorData{
			Now: now,
			Groups: []types.Group{
				{CN: "Protected Users", SAMAccountName: "Protected Users", DN: "CN=Protected Users,CN=Users,DC=example,DC=com", ObjectSID: "S-1-5-21-1111111111-2222222222-3333333333-525"},
			},
			ObjectBySID: map[string]*audit.ObjectMeta{
				"S-1-5-21-1111111111-2222222222-3333333333-525": {DN: "CN=Protected Users,CN=Users,DC=example,DC=com", SID: "S-1-5-21-1111111111-2222222222-3333333333-525", EntityType: types.EntityTypeGroup},
			},
			Users: []types.User{
				{
					SAMAccountName:  "admin2",
					AdminCount:      true,
					PasswordLastSet: now.AddDate(-1, 0, 0),
					MemberOf:        []string{"CN=Protected Users,CN=Users,DC=example,DC=com"},
				},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("expected count=0 (protected), got %d", findings[0].Count)
		}
	})
}

// TestAdminAuditBypass_HomonymProtectedUsersNotTrusted: a group whose CN is
// literally "Protected Users" but whose SID does NOT end in -525 grants no
// real protection - membership in it must not silence the finding for an
// otherwise-eligible admin account.
func TestAdminAuditBypass_HomonymProtectedUsersNotTrusted(t *testing.T) {
	d := NewAdminAuditBypassDetector()
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
				SAMAccountName:  "admin-homonym",
				AdminCount:      true,
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

// TestAdminAuditBypass_LocalizedProtectedUsersRecognized: the REAL -525
// group, renamed to a localized display name, must still be recognized by
// SID suffix - a group whose CN no longer contains "protected users"
// anywhere.
func TestAdminAuditBypass_LocalizedProtectedUsersRecognized(t *testing.T) {
	d := NewAdminAuditBypassDetector()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	localizedDN := "CN=Utilisateurs protégés,CN=Users,DC=example,DC=com"
	localizedSID := "S-1-5-21-1111111111-2222222222-3333333333-525"

	data := &audit.DetectorData{
		Now: now,
		Groups: []types.Group{
			{CN: "Utilisateurs protégés", SAMAccountName: "Utilisateurs protégés", DN: localizedDN, ObjectSID: localizedSID},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			localizedSID: {DN: localizedDN, SID: localizedSID, EntityType: types.EntityTypeGroup},
		},
		Users: []types.User{
			{
				SAMAccountName:  "admin-localized",
				AdminCount:      true,
				PasswordLastSet: now.AddDate(-1, 0, 0),
				MemberOf:        []string{localizedDN},
			},
		},
	}

	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (the real -525 group under a localized CN must still protect its member)", findings[0].Count)
	}
}

// TestAdminAuditBypass_NonAdminCountAccountNotFlagged: an enabled account
// outside Protected Users with a stale password must only be flagged when
// AdminCount is actually set - adminCount=1 is what makes the account
// privileged, not mere exposure to the other conditions.
func TestAdminAuditBypass_NonAdminCountAccountNotFlagged(t *testing.T) {
	d := NewAdminAuditBypassDetector()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		adminCount bool
		wantCount  int
	}{
		{name: "ordinary account (AdminCount=false) outside Protected Users: not flagged", adminCount: false, wantCount: 0},
		{name: "privileged account (AdminCount=true) outside Protected Users: flagged", adminCount: true, wantCount: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{
				Now: now,
				Users: []types.User{
					{
						SAMAccountName:  "ordinary-user",
						AdminCount:      tc.adminCount,
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

// TestAdminAuditBypass_A8_RecentPasswordNotCounted locks in that an admin
// account outside Protected Users whose password was set well within the
// last six months is not counted as a credential-theft exposure.
func TestAdminAuditBypass_A8_RecentPasswordNotCounted(t *testing.T) {
	d := NewAdminAuditBypassDetector()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{SAMAccountName: "admin-recent", AdminCount: true, PasswordLastSet: now.AddDate(0, -1, 0)},
		},
	}

	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (password set 1 month ago is within the six-month window)", findings[0].Count)
	}
}

// TestAdminAuditBypass_A9_PasswordJustUnderSixMonthsNotCounted locks the
// six-month threshold itself: a password aged about five and a half months
// is younger than the six-month cutoff and must not be counted.
func TestAdminAuditBypass_A9_PasswordJustUnderSixMonthsNotCounted(t *testing.T) {
	d := NewAdminAuditBypassDetector()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{SAMAccountName: "admin-five-half", AdminCount: true, PasswordLastSet: now.AddDate(0, -5, -15)},
		},
	}

	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (password aged ~5.5 months is younger than the six-month cutoff)", findings[0].Count)
	}
}

// TestAdminAuditBypass_A10_PasswordJustOverSixMonthsCounted locks the other
// side of the same threshold: a password aged about six and a half months
// is older than the six-month cutoff and must be counted.
func TestAdminAuditBypass_A10_PasswordJustOverSixMonthsCounted(t *testing.T) {
	d := NewAdminAuditBypassDetector()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{SAMAccountName: "admin-six-half", AdminCount: true, PasswordLastSet: now.AddDate(0, -6, -15)},
		},
	}

	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (password aged ~6.5 months is older than the six-month cutoff)", findings[0].Count)
	}
}

// TestAdminAuditBypass_A13_DetailsPopulatedOnPositiveFinding locks that a
// positive finding (Count > 0) always carries the Details block, keyed
// exactly as the detector builds it.
func TestAdminAuditBypass_A13_DetailsPopulatedOnPositiveFinding(t *testing.T) {
	d := NewAdminAuditBypassDetector()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{SAMAccountName: "admin-positive", AdminCount: true, PasswordLastSet: now.AddDate(-1, 0, 0)},
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

// TestAdminAuditBypass_A15_IncludeDetailsTruePopulatesAffectedEntities locks
// that AffectedEntities is populated for a positive finding when the caller
// requests IncludeDetails.
func TestAdminAuditBypass_A15_IncludeDetailsTruePopulatesAffectedEntities(t *testing.T) {
	d := NewAdminAuditBypassDetector()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	data := &audit.DetectorData{
		Now:            now,
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "admin-included", AdminCount: true, PasswordLastSet: now.AddDate(-1, 0, 0)},
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

// TestAdminAuditBypass_A16_IncludeDetailsFalseAffectedEntitiesNil locks the
// opposite side: AffectedEntities must stay empty for a positive finding
// when the caller does not request IncludeDetails.
func TestAdminAuditBypass_A16_IncludeDetailsFalseAffectedEntitiesNil(t *testing.T) {
	d := NewAdminAuditBypassDetector()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	data := &audit.DetectorData{
		Now:            now,
		IncludeDetails: false,
		Users: []types.User{
			{SAMAccountName: "admin-excluded", AdminCount: true, PasswordLastSet: now.AddDate(-1, 0, 0)},
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
