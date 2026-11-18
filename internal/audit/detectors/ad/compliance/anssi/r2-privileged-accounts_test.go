package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// r2TestDomainSID is the forest's well-known domain SID prefix; appending a
// RID suffix (e.g. "-512") gives a specific group's SID, as a real forest's
// SID-RID structure works.
const r2TestDomainSID = "S-1-5-21-1111111111-2222222222-3333333333"

// r2DomainAdminsDN is the Domain Admins group's DN shared by the test cases
// below; r2ObjectBySID binds it to the real -512 RID so
// privgroups.DNsBySIDSuffix resolves it the same way engine.collectData
// would from a real collection.
const r2DomainAdminsDN = "CN=Domain Admins,CN=Users,DC=test,DC=local"

func r2ObjectBySID(groupDN string) map[string]*audit.ObjectMeta {
	return map[string]*audit.ObjectMeta{
		r2TestDomainSID + "-512": {DN: groupDN, SID: r2TestDomainSID + "-512", EntityType: types.EntityTypeGroup},
	}
}

func daMember(sam string) types.User {
	return types.User{
		SAMAccountName: sam,
		MemberOf:       []string{r2DomainAdminsDN},
	}
}

func TestR2PrivilegedAccounts_Detect(t *testing.T) {
	cases := []struct {
		name      string
		data      *audit.DetectorData
		wantCount int
	}{
		{
			name: "4 Domain Admins, no SPN -> clean ( live lab baseline)",
			data: &audit.DetectorData{
				Users: []types.User{
					daMember("Administrator"), daMember("admin"), daMember("administrator2"), daMember("backup_admin"),
				},
				ObjectBySID: r2ObjectBySID(r2DomainAdminsDN),
			},
			wantCount: 0,
		},
		{
			name: "11 Domain Admins -> flagged (>10 threshold)",
			data: &audit.DetectorData{
				Users: func() []types.User {
					var u []types.User
					for i := 0; i < 11; i++ {
						u = append(u, daMember("da_user"))
					}
					return u
				}(),
				ObjectBySID: r2ObjectBySID(r2DomainAdminsDN),
			},
			wantCount: 1,
		},
		{
			name: "SPN-bearing account in Domain Admins -> flagged ( live-verified on DC01)",
			data: &audit.DetectorData{
				Users: []types.User{
					{
						SAMAccountName:        "backup_admin",
						MemberOf:              []string{r2DomainAdminsDN},
						ServicePrincipalNames: []string{"t131/kerbtest-r2.test.local"},
					},
				},
				ObjectBySID: r2ObjectBySID(r2DomainAdminsDN),
			},
			wantCount: 1,
		},
		{
			name: "SPN on a non-DA account -> not flagged",
			data: &audit.DetectorData{
				Users: []types.User{
					{SAMAccountName: "svc_regular", ServicePrincipalNames: []string{"http/web01"}},
				},
				ObjectBySID: r2ObjectBySID(r2DomainAdminsDN),
			},
			wantCount: 0,
		},
		{
			name: "SPN-bearing account disabled, in Domain Admins -> not flagged (Enabled guard)",
			data: &audit.DetectorData{
				Users: []types.User{
					{
						SAMAccountName:        "disabled_da_svc",
						Disabled:              true,
						MemberOf:              []string{r2DomainAdminsDN},
						ServicePrincipalNames: []string{"t131/kerbtest-r2-disabled.test.local"},
					},
				},
				ObjectBySID: r2ObjectBySID(r2DomainAdminsDN),
			},
			wantCount: 0,
		},
		{
			name: "homonym Domain Admins CN with an ordinary SID -> not counted",
			data: &audit.DetectorData{
				Users: []types.User{
					{
						SAMAccountName: "da_user",
						MemberOf:       []string{"CN=Domain Admins,OU=Decommissioned,DC=test,DC=local"},
					},
				},
				ObjectBySID: map[string]*audit.ObjectMeta{
					r2TestDomainSID + "-3001": {DN: "CN=Domain Admins,OU=Decommissioned,DC=test,DC=local", SID: r2TestDomainSID + "-3001", EntityType: types.EntityTypeGroup},
				},
			},
			wantCount: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := NewR2PrivilegedAccountsDetector()
			findings := d.Detect(context.Background(), tc.data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding struct, got %d", len(findings))
			}
			if findings[0].Count != tc.wantCount {
				t.Errorf("Count = %d, want %d (details=%+v)", findings[0].Count, tc.wantCount, findings[0].Details)
			}
		})
	}
}

// TestR2PrivilegedAccounts_LocalizedDomainAdminsSPNFlagged proves the SID
// fix with a positive assertion: an SPN-bearing account in a
// localized-CN Domain Admins group (real -512 RID) must still be flagged,
// even though main's strings.Contains(memberOf, "domain admins") can never
// match a non-English CN.
func TestR2PrivilegedAccounts_LocalizedDomainAdminsSPNFlagged(t *testing.T) {
	groupDN := "CN=Admins du domaine,CN=Users,DC=corp,DC=local"
	data := &audit.DetectorData{
		Users: []types.User{
			{
				SAMAccountName:        "svc_localise",
				MemberOf:              []string{groupDN},
				ServicePrincipalNames: []string{"t131/kerbtest-r2-fr.corp.local"},
			},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			r2TestDomainSID + "-512": {DN: groupDN, SID: r2TestDomainSID + "-512", EntityType: types.EntityTypeGroup},
		},
	}

	findings := NewR2PrivilegedAccountsDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected the SPN-bearing account in the localized Domain Admins group to be flagged, got %+v", findings)
	}
}

// TestR2PrivilegedAccounts_HomonymSPNNotFlagged proves the homonym fix: an
// SPN-bearing account whose memberOf contains the exact English text
// "CN=Domain Admins" but under a group with a different, non-512 RID is not
// the real Domain Admins group and must not be flagged. Main's
// strings.Contains(memberOf, "domain admins") false-positives on it.
func TestR2PrivilegedAccounts_HomonymSPNNotFlagged(t *testing.T) {
	groupDN := "CN=Domain Admins,OU=Decommissioned,DC=test,DC=local"
	data := &audit.DetectorData{
		Users: []types.User{
			{
				SAMAccountName:        "svc_homonym",
				MemberOf:              []string{groupDN},
				ServicePrincipalNames: []string{"t131/kerbtest-r2-homonym.test.local"},
			},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			r2TestDomainSID + "-3001": {DN: groupDN, SID: r2TestDomainSID + "-3001", EntityType: types.EntityTypeGroup},
		},
	}

	findings := NewR2PrivilegedAccountsDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected the SPN-bearing account in the homonym group (non-512 RID) to NOT be flagged, got %+v", findings)
	}
}

// TestR2PrivilegedAccounts_ThresholdBoundary pins the exact threshold
// boundary: exactly daCountBenchmark (10) enabled Domain Admins must stay
// clean, and one more (11) must flip the finding. This kills the `daCount >
// daCountBenchmark` -> `daCount >= daCountBenchmark` mutation, which no
// other case in this file exercises (the existing 11-member case alone
// can't distinguish > from >=).
func TestR2PrivilegedAccounts_ThresholdBoundary(t *testing.T) {
	cases := []struct {
		name      string
		count     int
		wantCount int
	}{
		{name: "exactly 10 enabled Domain Admins -> clean", count: 10, wantCount: 0},
		{name: "11 enabled Domain Admins -> flagged", count: 11, wantCount: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var users []types.User
			for i := 0; i < tc.count; i++ {
				users = append(users, daMember("da_user"))
			}
			data := &audit.DetectorData{
				Users:       users,
				ObjectBySID: r2ObjectBySID(r2DomainAdminsDN),
			}
			findings := NewR2PrivilegedAccountsDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding struct, got %d", len(findings))
			}
			if findings[0].Count != tc.wantCount {
				t.Errorf("Count = %d, want %d (details=%+v)", findings[0].Count, tc.wantCount, findings[0].Details)
			}
		})
	}
}

// TestR2PrivilegedAccounts_DisabledMembersNotCounted proves the Enabled
// guard on the daCount loop (r2-privileged-accounts.go, "Count domain
// admins"): a disabled Domain Admins member must not count toward the
// headcount threshold. 10 enabled + 1 disabled stays clean; 11 enabled
// flips the finding.
func TestR2PrivilegedAccounts_DisabledMembersNotCounted(t *testing.T) {
	cases := []struct {
		name      string
		enabled   int
		disabled  int
		wantCount int
	}{
		{name: "10 enabled + 1 disabled -> clean", enabled: 10, disabled: 1, wantCount: 0},
		{name: "11 enabled -> flagged", enabled: 11, disabled: 0, wantCount: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var users []types.User
			for i := 0; i < tc.enabled; i++ {
				users = append(users, daMember("da_user"))
			}
			for i := 0; i < tc.disabled; i++ {
				users = append(users, types.User{
					SAMAccountName: "disabled_da_user",
					Disabled:       true,
					MemberOf:       []string{r2DomainAdminsDN},
				})
			}
			data := &audit.DetectorData{
				Users:       users,
				ObjectBySID: r2ObjectBySID(r2DomainAdminsDN),
			}
			findings := NewR2PrivilegedAccountsDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding struct, got %d", len(findings))
			}
			if findings[0].Count != tc.wantCount {
				t.Errorf("Count = %d, want %d (details=%+v)", findings[0].Count, tc.wantCount, findings[0].Details)
			}
		})
	}
}

// the ">10 Domain Admins" threshold was previously presented as an
// ANSSI PA-099 requirement. It's INTROUVABLE in the published PA-099 text
// (verified against the full v1.0 PDF, 02/10/2023): no recommendation
// specifies a numeric ceiling on Domain Admins membership. The finding must
// no longer claim ANSSI mandates this specific number.
func TestR2PrivilegedAccounts_DoesNotClaimANSSIMandatesTheHeadcount(t *testing.T) {
	data := &audit.DetectorData{
		Users: func() []types.User {
			var u []types.User
			for i := 0; i < 11; i++ {
				u = append(u, daMember("da_user"))
			}
			return u
		}(),
		ObjectBySID: r2ObjectBySID(r2DomainAdminsDN),
	}
	d := NewR2PrivilegedAccountsDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count == 0 {
		t.Fatalf("expected a flagged finding, got %+v", findings)
	}
	desc := findings[0].Description
	if strings.Contains(desc, "ANSSI R2 recommendations") || strings.Contains(strings.ToLower(desc), "anssi recommends") {
		t.Errorf("description still attributes the headcount threshold to ANSSI: %q", desc)
	}
	if !strings.Contains(desc, "product benchmark") {
		t.Errorf("description should honestly present the headcount as a product benchmark, got %q", desc)
	}
}

// TestR2PrivilegedAccounts_NonMembersNotCounted proves the membership guard
// on the daCount loop (r2-privileged-accounts.go, "Count domain admins"):
// an enabled user who is NOT a Domain Admins member must not count toward
// the headcount threshold. 6 enabled Domain Admins plus 6 enabled
// non-members stays clean; 11 enabled Domain Admins alone flips the
// finding.
func TestR2PrivilegedAccounts_NonMembersNotCounted(t *testing.T) {
	cases := []struct {
		name       string
		members    int
		nonMembers int
		wantCount  int
	}{
		{name: "6 enabled DA + 6 enabled non-members -> clean", members: 6, nonMembers: 6, wantCount: 0},
		{name: "11 enabled DA -> flagged", members: 11, nonMembers: 0, wantCount: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var users []types.User
			for i := 0; i < tc.members; i++ {
				users = append(users, daMember("da_user"))
			}
			for i := 0; i < tc.nonMembers; i++ {
				users = append(users, types.User{
					SAMAccountName: "regular_user",
					MemberOf:       []string{"CN=Regular Users,CN=Users,DC=test,DC=local"},
				})
			}
			data := &audit.DetectorData{
				Users:       users,
				ObjectBySID: r2ObjectBySID(r2DomainAdminsDN),
			}
			findings := NewR2PrivilegedAccountsDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding struct, got %d", len(findings))
			}
			if findings[0].Count != tc.wantCount {
				t.Errorf("Count = %d, want %d (details=%+v)", findings[0].Count, tc.wantCount, findings[0].Details)
			}
		})
	}
}
