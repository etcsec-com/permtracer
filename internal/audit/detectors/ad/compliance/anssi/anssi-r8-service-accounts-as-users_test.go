package anssi

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestR8ServiceAccountsAsUsers_EnabledServiceAccountWithMail_Counted pins
// branch 1 of the detection matrix: an enabled account recognized as a
// service account by looksLikeServiceAccount (prefix "svc") carrying a
// nominative attribute (Mail) is counted.
func TestR8ServiceAccountsAsUsers_EnabledServiceAccountWithMail_Counted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc_backup,OU=Service Accounts,DC=example,DC=com", SAMAccountName: "svc_backup", Mail: "svc_backup@example.com"},
		},
	}
	findings := NewR8ServiceAccountsAsUsersDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1", findings[0].Count)
	}
}

// TestR8ServiceAccountsAsUsers_DisabledServiceAccountWithMail_NotCounted pins
// branch 4: the Disabled guard excludes a disabled account that would
// otherwise match (same account as the branch above, just disabled). This
// detector has no _ON_DISABLED_ACCOUNT twin, so a disabled match must not be
// counted anywhere.
func TestR8ServiceAccountsAsUsers_DisabledServiceAccountWithMail_NotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc_backup,OU=Service Accounts,DC=example,DC=com", SAMAccountName: "svc_backup", Mail: "svc_backup@example.com", Disabled: true},
		},
	}
	findings := NewR8ServiceAccountsAsUsersDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Errorf("Count = %d, want 0 (disabled account must be excluded)", findings[0].Count)
	}
}

// TestR8ServiceAccountsAsUsers_ServiceAccountWithoutNominativeAttrs_NotCounted
// pins branch 3/5 (the AND side): an enabled account that looks like a
// service account but carries none of Mail/Title/Department is not counted.
func TestR8ServiceAccountsAsUsers_ServiceAccountWithoutNominativeAttrs_NotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc_backup,OU=Service Accounts,DC=example,DC=com", SAMAccountName: "svc_backup"},
		},
	}
	findings := NewR8ServiceAccountsAsUsersDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Errorf("Count = %d, want 0 (no nominative attribute present)", findings[0].Count)
	}
}

// TestR8ServiceAccountsAsUsers_OrdinaryUserWithMail_NotCounted pins the
// negative control for looksLikeServiceAccount: an enabled, ordinary
// nominative account with a mailbox and none of the recognized prefixes/SPN
// pattern is not counted, even though it satisfies the nominative-attribute
// side of the AND.
func TestR8ServiceAccountsAsUsers_OrdinaryUserWithMail_NotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=jdoe,OU=Users,DC=example,DC=com", SAMAccountName: "jdoe", Mail: "jdoe@example.com"},
		},
	}
	findings := NewR8ServiceAccountsAsUsersDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Errorf("Count = %d, want 0 (ordinary account, not a service account)", findings[0].Count)
	}
}

// TestR8ServiceAccountsAsUsers_SPNAndPasswordNeverExpiresWithTitle_Counted
// pins branch 3: an account with no recognized prefix, but with
// PasswordNeverExpires=true and at least one SPN, carrying a nominative
// attribute (Title), is counted via the second half of looksLikeServiceAccount.
func TestR8ServiceAccountsAsUsers_SPNAndPasswordNeverExpiresWithTitle_Counted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{
				DN:                    "CN=batchrunner,OU=Users,DC=example,DC=com",
				SAMAccountName:        "batchrunner",
				PasswordNeverExpires:  true,
				ServicePrincipalNames: []string{"HTTP/batchrunner.example.com"},
				Title:                 "Batch",
			},
		},
	}
	findings := NewR8ServiceAccountsAsUsersDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1", findings[0].Count)
	}
}

// TestR8ServiceAccountsAsUsers_SPNWithoutPasswordNeverExpires_NotCounted pins
// the neighboring state that must NOT trigger branch 3: the same SPN-bearing
// account, but with PasswordNeverExpires=false, does not match
// looksLikeServiceAccount's second condition and is not counted.
func TestR8ServiceAccountsAsUsers_SPNWithoutPasswordNeverExpires_NotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{
				DN:                    "CN=batchrunner,OU=Users,DC=example,DC=com",
				SAMAccountName:        "batchrunner",
				PasswordNeverExpires:  false,
				ServicePrincipalNames: []string{"HTTP/batchrunner.example.com"},
				Title:                 "Batch",
			},
		},
	}
	findings := NewR8ServiceAccountsAsUsersDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Errorf("Count = %d, want 0 (PasswordNeverExpires=false, not a service account pattern)", findings[0].Count)
	}
}

// TestR8ServiceAccountsAsUsers_RecognizedPrefixes_Counted pins every
// recognized sAMAccountName prefix in looksLikeServiceAccount
// (r6_to_r15_lifecycle.go), one subtest per prefix, including the
// short "s-" prefix that the ANALYSE.md documents as the heuristic's
// central false-positive risk (a nominative "initial-dash-name" account like
// "s-dupont" is classified as a service account purely by this prefix).
func TestR8ServiceAccountsAsUsers_RecognizedPrefixes_Counted(t *testing.T) {
	prefixes := []struct {
		name string
		sam  string
	}{
		{"srv", "srv-print01"},
		{"service", "service_mail"},
		{"sa_", "sa_sqlbackup"},
		{"s-", "s-dupont"},
		{"app-", "app-webfront"},
	}
	for _, tc := range prefixes {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{
				Users: []types.User{
					{DN: "CN=" + tc.sam + ",OU=Users,DC=example,DC=com", SAMAccountName: tc.sam, Department: "Test"},
				},
			}
			findings := NewR8ServiceAccountsAsUsersDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(findings))
			}
			if findings[0].Count != 1 {
				t.Errorf("Count = %d, want 1 for prefix %q (sam=%q)", findings[0].Count, tc.name, tc.sam)
			}
		})
	}
}

// TestR8ServiceAccountsAsUsers_NominativeAttributesAreDisjointOR pins branch
// 5: Mail, Title and Department are an OR - any single one of the three is
// sufficient to count a recognized service account, one subtest per
// attribute.
func TestR8ServiceAccountsAsUsers_NominativeAttributesAreDisjointOR(t *testing.T) {
	cases := []struct {
		name string
		user types.User
	}{
		{"mail only", types.User{DN: "CN=svc_mailonly,DC=example,DC=com", SAMAccountName: "svc_mailonly", Mail: "svc_mailonly@example.com"}},
		{"title only", types.User{DN: "CN=svc_titleonly,DC=example,DC=com", SAMAccountName: "svc_titleonly", Title: "Operator"}},
		{"department only", types.User{DN: "CN=svc_deptonly,DC=example,DC=com", SAMAccountName: "svc_deptonly", Department: "IT"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{Users: []types.User{tc.user}}
			findings := NewR8ServiceAccountsAsUsersDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(findings))
			}
			if findings[0].Count != 1 {
				t.Errorf("Count = %d, want 1 for %s", findings[0].Count, tc.name)
			}
		})
	}
}

// TestR8ServiceAccountsAsUsers_MixedPopulation_CountMatchesOnlyMatches pins
// an end-to-end mix: among several users, only those that satisfy the full
// AND (service-looking AND nominative attribute AND enabled) are counted.
func TestR8ServiceAccountsAsUsers_MixedPopulation_CountMatchesOnlyMatches(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{DN: "CN=svc_backup,DC=example,DC=com", SAMAccountName: "svc_backup", Mail: "svc_backup@example.com"},            // matches
			{DN: "CN=svc_disabled,DC=example,DC=com", SAMAccountName: "svc_disabled", Mail: "x@example.com", Disabled: true}, // disabled, excluded
			{DN: "CN=svc_bare,DC=example,DC=com", SAMAccountName: "svc_bare"},                                                // no nominative attr, excluded
			{DN: "CN=jdoe,DC=example,DC=com", SAMAccountName: "jdoe", Mail: "jdoe@example.com"},                              // ordinary user, excluded
		},
	}
	findings := NewR8ServiceAccountsAsUsersDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].DN != "CN=svc_backup,DC=example,DC=com" {
		t.Errorf("expected the single affected entity to be svc_backup, got %+v", findings[0].AffectedEntities)
	}
}
