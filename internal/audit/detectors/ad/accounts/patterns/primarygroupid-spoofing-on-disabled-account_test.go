package patterns

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestPrimaryGroupIdSpoofingOnDisabledAccount mirrors
// TestPrimaryGroupIdSpoofing's cases on disabled accounts: the same
// exclusions (standard/unset primaryGroupID, Guest, gMSA) apply, and the
// partition with the active detector is strict by account state.
func TestPrimaryGroupIdSpoofingOnDisabledAccount(t *testing.T) {
	cases := []struct {
		name      string
		user      types.User
		wantCount int
	}{
		{
			name: "disabled built-in Guest (RID 501) with primaryGroupID 514 (Domain Guests) does not fire",
			user: types.User{
				SAMAccountName: "Guest",
				ObjectSID:      "S-1-5-21-1004336348-1177238915-682003330-501",
				PrimaryGroupID: 514,
				Disabled:       true,
			},
			wantCount: 0,
		},
		{
			name: "disabled gMSA with primaryGroupID 515 (Domain Computers) does not fire",
			user: types.User{
				SAMAccountName: "svc-backup$",
				ObjectSID:      "S-1-5-21-1004336348-1177238915-682003330-1112",
				PrimaryGroupID: 515,
				IsGMSA:         true,
				Disabled:       true,
			},
			wantCount: 0,
		},
		{
			name: "disabled non-gMSA user with primaryGroupID 515 (Domain Computers) still fires - gMSA exception requires IsGMSA",
			user: types.User{
				SAMAccountName: "app-service-01",
				ObjectSID:      "S-1-5-21-1004336348-1177238915-682003330-1113",
				PrimaryGroupID: 515,
				IsGMSA:         false,
				Disabled:       true,
			},
			wantCount: 1,
		},
		{
			name: "disabled ordinary user with primaryGroupID 513 (standard) does not fire",
			user: types.User{
				SAMAccountName: "jdupont",
				ObjectSID:      "S-1-5-21-1004336348-1177238915-682003330-1105",
				PrimaryGroupID: 513,
				Disabled:       true,
			},
			wantCount: 0,
		},
		{
			name: "disabled account with primaryGroupID 0 (unset/unreadable) does not fire",
			user: types.User{
				SAMAccountName: "unreadable",
				PrimaryGroupID: 0,
				Disabled:       true,
			},
			wantCount: 0,
		},
		{
			name: "disabled non-Guest account with primaryGroupID 514 (Domain Guests) still fires - RID doesn't match Guest",
			user: types.User{
				SAMAccountName: "notguest",
				ObjectSID:      "S-1-5-21-1004336348-1177238915-682003330-9999",
				PrimaryGroupID: 514,
				Disabled:       true,
			},
			wantCount: 1,
		},
		{
			name: "disabled account with non-standard primaryGroupID - classic hide-membership spoofing - fires",
			user: types.User{
				SAMAccountName: "attacker",
				ObjectSID:      "S-1-5-21-1004336348-1177238915-682003330-1150",
				PrimaryGroupID: 512,
				Disabled:       true,
				MemberOf:       []string{"CN=Marketing,CN=Users,DC=corp,DC=local"},
			},
			wantCount: 1,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := &audit.DetectorData{
				Users:          []types.User{c.user},
				IncludeDetails: true,
			}
			findings := NewPrimaryGroupIdSpoofingOnDisabledAccountDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding wrapper, got %d", len(findings))
			}
			if findings[0].Count != c.wantCount {
				t.Fatalf("Count = %d, want %d", findings[0].Count, c.wantCount)
			}
		})
	}
}

// TestPrimaryGroupIdSpoofingOnDisabledAccount_ActiveNotFlagged is the
// partition guard: the same non-standard primaryGroupID must be split
// strictly between the two detectors by account state - an active account
// belongs to PrimaryGroupIdSpoofingDetector only, never to this twin.
func TestPrimaryGroupIdSpoofingOnDisabledAccount_ActiveNotFlagged(t *testing.T) {
	u := types.User{
		SAMAccountName: "attacker",
		ObjectSID:      "S-1-5-21-1004336348-1177238915-682003330-1150",
		PrimaryGroupID: 512,
		Disabled:       false,
		MemberOf:       []string{"CN=Marketing,CN=Users,DC=corp,DC=local"},
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	twin := NewPrimaryGroupIdSpoofingOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if twin.Count != 0 {
		t.Fatalf("twin Count = %d, want 0 (active account must not be counted by the disabled-account twin)", twin.Count)
	}

	active := NewPrimaryGroupIdSpoofingDetector().Detect(context.Background(), data)[0]
	if active.Count != 1 {
		t.Fatalf("active Count = %d, want 1 (active account belongs to PrimaryGroupIdSpoofingDetector)", active.Count)
	}
}
