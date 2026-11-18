package privileged

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

const protectedUsersTestDomainSID = "S-1-5-21-4444444444-5555555555-6666666666"

// TestProtectedUsersEmpty_LocalizedNameWithRealSIDTreatedAsTarget proves the
// SID fix: a localized forest's Protected Users group (French name, real
// RID -525) is still recognized as the target group, even though its
// SAMAccountName is not the English "protected users" string main's
// strings.EqualFold match requires. Main can never find this group by name,
// so protectedUsersGroup stays nil and main's isEmpty defaults to true
// (wrongly reporting it empty even though it has a member here).
func TestProtectedUsersEmpty_LocalizedNameWithRealSIDTreatedAsTarget(t *testing.T) {
	groupSID := protectedUsersTestDomainSID + "-525"
	groupDN := "CN=Utilisateurs protégés,CN=Users,DC=corp,DC=local"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{
				DN:             groupDN,
				SAMAccountName: "Utilisateurs protégés",
				Member:         []string{"CN=Alice,CN=Users,DC=corp,DC=local"},
			},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewProtectedUsersEmptyDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (localized Protected Users CN, real RID -525, HAS a member - main's English name match never finds this group and defaults to \"not found\" => wrongly empty)", f.Count)
	}
}

// TestProtectedUsersEmpty_EnglishHomonymDifferentSIDNotTreatedAsTarget proves
// the homonym fix: a group named exactly "Protected Users" in English but
// carrying a different, non-525 RID is not the real Protected Users group.
// The real group here (localized name, RID -525) has a member, so the
// correct Count is 0. Main's strings.EqualFold(name, "protected users")
// matches the homonym by name alone - it comes first in data.Groups - and
// reports IT (empty) as the finding, Count=1, ignoring the real non-empty
// group entirely.
func TestProtectedUsersEmpty_EnglishHomonymDifferentSIDNotTreatedAsTarget(t *testing.T) {
	realSID := protectedUsersTestDomainSID + "-525"
	realDN := "CN=Utilisateurs protégés,CN=Users,DC=corp,DC=local"
	homonymSID := protectedUsersTestDomainSID + "-3002"
	homonymDN := "CN=Protected Users,OU=Legacy,DC=corp,DC=local"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{
				DN:             homonymDN,
				SAMAccountName: "Protected Users",
				Member:         nil,
			},
			{
				DN:             realDN,
				SAMAccountName: "Utilisateurs protégés",
				Member:         []string{"CN=Alice,CN=Users,DC=corp,DC=local"},
			},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			realSID:    {DN: realDN, SID: realSID, EntityType: types.EntityTypeGroup},
			homonymSID: {DN: homonymDN, SID: homonymSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewProtectedUsersEmptyDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (the real Protected Users group, RID -525, has a member; an English-named homonym under a different SID must not be mistaken for it)", f.Count)
	}
}

// TestProtectedUsersEmpty_NoGroupCollectedCountsAsEmpty is the baseline:
// when no group resolves to RID -525 at all (not collected), the finding
// must still fire as empty - unchanged fail-open-to-reporting behavior from
// before the SID fix.
func TestProtectedUsersEmpty_NoGroupCollectedCountsAsEmpty(t *testing.T) {
	data := &audit.DetectorData{}

	f := NewProtectedUsersEmptyDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (no Protected Users group collected at all)", f.Count)
	}
}

// TestProtectedUsersEmpty_TypeAndSeverity locks the finding's identifying
// fields.
func TestProtectedUsersEmpty_TypeAndSeverity(t *testing.T) {
	data := &audit.DetectorData{}
	f := NewProtectedUsersEmptyDetector().Detect(context.Background(), data)[0]
	if f.Type != "GROUP_PROTECTED_USERS_EMPTY" {
		t.Fatalf("Type = %q, want %q", f.Type, "GROUP_PROTECTED_USERS_EMPTY")
	}
	if f.Severity != types.SeverityMedium {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityMedium)
	}
}

// TestProtectedUsersEmpty_FoundButNoMembersCountsAsEmpty proves the group IS
// found by SID (protectedUsersGroup is non-nil) but has zero members, so the
// finding must still count it as empty. A mutant that drops the
// len(protectedUsersGroup.Member) == 0 clause from isEmpty would read
// isEmpty as false here (group found => not nil => not empty) and miss this
// case entirely.
func TestProtectedUsersEmpty_FoundButNoMembersCountsAsEmpty(t *testing.T) {
	groupSID := protectedUsersTestDomainSID + "-525"
	groupDN := "CN=Protected Users,CN=Users,DC=corp,DC=local"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{
				DN:     groupDN,
				Member: nil,
			},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewProtectedUsersEmptyDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (Protected Users group found by SID but has zero members)", f.Count)
	}
}

// TestProtectedUsersEmpty_MixedCaseDNFound proves the case-insensitive
// lookup: the group's own DN is stored in mixed case, and so is the DN the
// SID index was built from (DNsBySIDSuffix lowercases it before keying the
// map). Only a case-insensitive comparison on the group's DN finds it. A
// mutant that drops strings.ToLower on data.Groups[i].DN compares the raw
// mixed-case DN against the lowercased map key and never finds a match,
// leaving protectedUsersGroup nil.
func TestProtectedUsersEmpty_MixedCaseDNFound(t *testing.T) {
	groupSID := protectedUsersTestDomainSID + "-525"
	groupDN := "CN=Protected Users,CN=Users,DC=Corp,DC=Local"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{
				DN:     groupDN,
				Member: []string{"CN=Alice,CN=Users,DC=Corp,DC=Local"},
			},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewProtectedUsersEmptyDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (mixed-case DN group found via case-insensitive lookup, has a member)", f.Count)
	}
}
