package nesting

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

const nestingTestDomainSID = "S-1-5-21-1111111111-2222222222-3333333333"

// TestDangerousGroupNesting_FiresOnRealPipelineData covers a bug where the
// detector read group.DistinguishedName, an "alias for DN" field that
// parseGroup (internal/providers/ldap/parser.go) never assigns - only DN is
// populated. On real pipeline data DistinguishedName is always "", so
// isProtected was always false and the detector could never fire, no
// matter how a real domain nested Domain Admins.
func TestDangerousGroupNesting_FiresOnRealPipelineData(t *testing.T) {
	groupSID := nestingTestDomainSID + "-512"
	groupDN := "CN=Domain Admins,CN=Users,DC=contoso,DC=com"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{
				// Only DN set, matching what parseGroup actually produces -
				// DistinguishedName is deliberately left empty.
				DN:       groupDN,
				MemberOf: []string{"CN=HelpDesk,OU=Groups,DC=contoso,DC=com"}, // non-protected parent
			},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	findings := NewDangerousNestingDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 (Domain Admins nested in a non-protected group), got %d", findings[0].Count)
	}
}

// TestDangerousGroupNesting_LocalizedProtectedGroupCounted proves the SID
// fix: a localized forest's Domain Admins (French CN, real RID -512) is
// still recognized as protected. Main's strings.Contains(group.DN,
// "CN=Domain Admins") never matches a non-English CN, so this nesting would
// be invisible on main.
func TestDangerousGroupNesting_LocalizedProtectedGroupCounted(t *testing.T) {
	groupSID := nestingTestDomainSID + "-512"
	groupDN := "CN=Admins du domaine,CN=Users,DC=corp,DC=local"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{
				DN:       groupDN,
				MemberOf: []string{"CN=HelpDesk,OU=Groups,DC=corp,DC=local"}, // non-protected parent
			},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewDangerousNestingDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (localized Domain Admins CN, real RID -512 - main's English substring match is blind here)", f.Count)
	}
}

// TestDangerousGroupNesting_EnglishHomonymDifferentSIDNotCounted proves the
// homonym fix: a group whose CN contains the exact English text "CN=Domain
// Admins" but carries a different, non-512 RID is not the real Domain
// Admins group. Main's strings.Contains(group.DN, "CN=Domain Admins")
// false-positives on it and flags it as a dangerous nesting.
func TestDangerousGroupNesting_EnglishHomonymDifferentSIDNotCounted(t *testing.T) {
	homonymSID := nestingTestDomainSID + "-3001"
	homonymDN := "CN=Domain Admins,OU=Decommissioned,DC=corp,DC=local"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{
				DN:       homonymDN,
				MemberOf: []string{"CN=HelpDesk,OU=Groups,DC=corp,DC=local"}, // non-protected parent
			},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			homonymSID: {DN: homonymDN, SID: homonymSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewDangerousNestingDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (homonym group's SID does not end in -512 - not the real Domain Admins, main's substring match false-positives here)", f.Count)
	}
}

// TestDangerousGroupNesting_ProtectedParentOnlyNotCounted proves that a
// protected group whose ONLY parent is itself one of the eight protected
// groups is not an escalation path: being nested only inside other
// already-privileged groups adds no new reachability. A mutant that treats
// every parent as "unexpected" (ignoring protectedDNs entirely) would count
// this case, since it only checks that a parent exists.
func TestDangerousGroupNesting_ProtectedParentOnlyNotCounted(t *testing.T) {
	protectedParentSID := nestingTestDomainSID + "-544"
	protectedParentDN := "CN=Administrators,OU=X,DC=corp,DC=local"
	groupSID := nestingTestDomainSID + "-512"
	groupDN := "CN=Domain Admins,OU=X,DC=corp,DC=local"

	t.Run("all_parents_protected_not_counted", func(t *testing.T) {
		data := &audit.DetectorData{
			Groups: []types.Group{
				{
					DN:       groupDN,
					MemberOf: []string{protectedParentDN},
				},
			},
			ObjectBySID: map[string]*audit.ObjectMeta{
				groupSID:           {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
				protectedParentSID: {DN: protectedParentDN, SID: protectedParentSID, EntityType: types.EntityTypeGroup},
			},
		}
		f := NewDangerousNestingDetector().Detect(context.Background(), data)[0]
		if f.Count != 0 {
			t.Fatalf("Count = %d, want 0 (sole parent is itself protected RID -544 - not an escalation path)", f.Count)
		}
	})

	t.Run("ordinary_parent_added_counted", func(t *testing.T) {
		data := &audit.DetectorData{
			Groups: []types.Group{
				{
					DN:       groupDN,
					MemberOf: []string{protectedParentDN, "CN=HelpDesk,OU=Groups,DC=corp,DC=local"},
				},
			},
			ObjectBySID: map[string]*audit.ObjectMeta{
				groupSID:           {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
				protectedParentSID: {DN: protectedParentDN, SID: protectedParentSID, EntityType: types.EntityTypeGroup},
			},
		}
		f := NewDangerousNestingDetector().Detect(context.Background(), data)[0]
		if f.Count != 1 {
			t.Fatalf("Count = %d, want 1 (an ordinary, non-protected parent is now also present)", f.Count)
		}
	})
}
