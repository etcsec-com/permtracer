package privileged

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestNotInProtectedUsersOnDisabledAccount_DisabledMembershipFlagged is the
// baseline positive: a disabled direct member of a real privileged group
// (Backup Operators, S-1-5-32-551), not itself in Protected Users, must be
// flagged.
func TestNotInProtectedUsersOnDisabledAccount_DisabledMembershipFlagged(t *testing.T) {
	boDN := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	boSID := "S-1-5-32-551"
	u := types.User{SAMAccountName: "bo-member", MemberOf: []string{boDN}, Disabled: true}
	data := &audit.DetectorData{
		Groups:      []types.Group{protectedUsersGroupFixture()},
		Users:       []types.User{u},
		ObjectBySID: withProtectedUsersSID(map[string]*audit.ObjectMeta{boSID: {DN: boDN, SID: boSID, EntityType: types.EntityTypeGroup}}),
	}

	f := NewNotInProtectedUsersOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled Backup Operators member not in Protected Users)", f.Count)
	}
	if f.Type != "NOT_IN_PROTECTED_USERS_ON_DISABLED_ACCOUNT" {
		t.Fatalf("Type = %q, want NOT_IN_PROTECTED_USERS_ON_DISABLED_ACCOUNT", f.Type)
	}
}

// TestNotInProtectedUsersOnDisabledAccount_ActiveMembershipNotFlagged is
// the partition guard from this detector's side: an enabled member of the
// same group must not be counted here - it belongs to
// NotInProtectedUsersDetector instead.
func TestNotInProtectedUsersOnDisabledAccount_ActiveMembershipNotFlagged(t *testing.T) {
	boDN := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	boSID := "S-1-5-32-551"
	u := types.User{SAMAccountName: "bo-member", MemberOf: []string{boDN}, Disabled: false}
	data := &audit.DetectorData{
		Groups:      []types.Group{protectedUsersGroupFixture()},
		Users:       []types.User{u},
		ObjectBySID: withProtectedUsersSID(map[string]*audit.ObjectMeta{boSID: {DN: boDN, SID: boSID, EntityType: types.EntityTypeGroup}}),
	}

	f := NewNotInProtectedUsersOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (active member must not be counted here)", f.Count)
	}
}

// TestNotInProtectedUsersOnDisabledAccount_DisabledInProtectedUsersNotFlagged:
// a disabled privileged member already in Protected Users must not be
// flagged.
func TestNotInProtectedUsersOnDisabledAccount_DisabledInProtectedUsersNotFlagged(t *testing.T) {
	boDN := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	boSID := "S-1-5-32-551"
	u := types.User{SAMAccountName: "bo-member", MemberOf: []string{boDN, protectedUsersDN}, Disabled: true}
	data := &audit.DetectorData{
		Groups:      []types.Group{protectedUsersGroupFixture()},
		Users:       []types.User{u},
		ObjectBySID: withProtectedUsersSID(map[string]*audit.ObjectMeta{boSID: {DN: boDN, SID: boSID, EntityType: types.EntityTypeGroup}}),
	}

	f := NewNotInProtectedUsersOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (already in Protected Users must not be flagged)", f.Count)
	}
}

// TestNotInProtectedUsersOnDisabledAccount_DisabledSpnExcluded mirrors the
// active detector's SPN exclusion: a disabled privileged account with an
// SPN is incompatible with Protected Users and must not be flagged.
func TestNotInProtectedUsersOnDisabledAccount_DisabledSpnExcluded(t *testing.T) {
	boDN := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	boSID := "S-1-5-32-551"
	u := types.User{SAMAccountName: "bo-member", MemberOf: []string{boDN}, Disabled: true, ServicePrincipalNames: []string{"HTTP/bo-member.example.com"}}
	data := &audit.DetectorData{
		Groups:      []types.Group{protectedUsersGroupFixture()},
		Users:       []types.User{u},
		ObjectBySID: withProtectedUsersSID(map[string]*audit.ObjectMeta{boSID: {DN: boDN, SID: boSID, EntityType: types.EntityTypeGroup}}),
	}

	f := NewNotInProtectedUsersOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (SPN-bearing account must stay excluded, disabled or not)", f.Count)
	}
}

// TestNotInProtectedUsersOnDisabledAccount_DisabledRenamedAdministratorExcluded
// mirrors the active detector's RID-500 exclusion on the disabled side.
func TestNotInProtectedUsersOnDisabledAccount_DisabledRenamedAdministratorExcluded(t *testing.T) {
	u := types.User{SAMAccountName: "svc-legacy-root", AdminCount: true, Disabled: true, ObjectSID: "S-1-5-21-1111111111-2222222222-3333333333-500"}
	data := &audit.DetectorData{
		Groups:      []types.Group{protectedUsersGroupFixture()},
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{protectedUsersSID: {DN: protectedUsersDN, SID: protectedUsersSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewNotInProtectedUsersOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (RID -500 must stay excluded regardless of state)", f.Count)
	}
}

// TestNotInProtectedUsersOnDisabledAccount_SeverityIsMedium locks this
// detector's severity at Medium, distinct from the High of the
// active-account detector.
func TestNotInProtectedUsersOnDisabledAccount_SeverityIsMedium(t *testing.T) {
	boDN := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	boSID := "S-1-5-32-551"
	u := types.User{SAMAccountName: "bo-member", MemberOf: []string{boDN}, Disabled: true}
	data := &audit.DetectorData{
		Groups:      []types.Group{protectedUsersGroupFixture()},
		Users:       []types.User{u},
		ObjectBySID: withProtectedUsersSID(map[string]*audit.ObjectMeta{boSID: {DN: boDN, SID: boSID, EntityType: types.EntityTypeGroup}}),
	}

	f := NewNotInProtectedUsersOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Severity != types.SeverityMedium {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityMedium)
	}
}

// TestNotInProtectedUsersOnDisabledAccount_NoProtectedUsersGroupStaysSilent
// mirrors the active detector's declared limitation on the disabled side.
func TestNotInProtectedUsersOnDisabledAccount_NoProtectedUsersGroupStaysSilent(t *testing.T) {
	boDN := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	boSID := "S-1-5-32-551"
	u := types.User{SAMAccountName: "would-be-flagged", MemberOf: []string{boDN}, Disabled: true}
	data := &audit.DetectorData{
		Groups:      []types.Group{},
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{boSID: {DN: boDN, SID: boSID, EntityType: types.EntityTypeGroup}},
	}

	findings := NewNotInProtectedUsersOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0 (no -525 group in the index must produce no finding)", len(findings))
	}
}

// TestNotInProtectedUsersOnDisabledAccount_AdminCountAloneFlagged isolates
// criterion 1 (AdminCount=true) from criterion 2 on the disabled side: the
// user carries no group membership at all, so only AdminCount can make it
// privileged. Must be flagged.
func TestNotInProtectedUsersOnDisabledAccount_AdminCountAloneFlagged(t *testing.T) {
	u := types.User{SAMAccountName: "disabled-admincount-only", AdminCount: true, Disabled: true}
	data := &audit.DetectorData{
		Groups:      []types.Group{protectedUsersGroupFixture()},
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{protectedUsersSID: {DN: protectedUsersDN, SID: protectedUsersSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewNotInProtectedUsersOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled AdminCount=true account, no group membership, not in Protected Users, must be flagged)", f.Count)
	}
}

// TestNotInProtectedUsersOnDisabledAccount_AccountOperatorsMembershipFlagged
// isolates the -548 (Account Operators) entry of privilegedGroupSIDSuffixes
// on the disabled side: a disabled direct member, not itself AdminCount,
// not in Protected Users, must be flagged.
func TestNotInProtectedUsersOnDisabledAccount_AccountOperatorsMembershipFlagged(t *testing.T) {
	aoDN := "CN=Account Operators,CN=Builtin,DC=example,DC=com"
	aoSID := "S-1-5-32-548"
	u := types.User{SAMAccountName: "ao-member", MemberOf: []string{aoDN}, Disabled: true}
	data := &audit.DetectorData{
		Groups:      []types.Group{protectedUsersGroupFixture()},
		Users:       []types.User{u},
		ObjectBySID: withProtectedUsersSID(map[string]*audit.ObjectMeta{aoSID: {DN: aoDN, SID: aoSID, EntityType: types.EntityTypeGroup}}),
	}

	f := NewNotInProtectedUsersOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled Account Operators (-548) member not in Protected Users)", f.Count)
	}
}

// TestNotInProtectedUsersOnDisabledAccount_DomainAdminsMembershipFlagged
// isolates the -512 (Domain Admins) entry of privilegedGroupSIDSuffixes on
// the disabled side: a disabled direct member, not itself AdminCount, not
// in Protected Users, must be flagged.
func TestNotInProtectedUsersOnDisabledAccount_DomainAdminsMembershipFlagged(t *testing.T) {
	daDN := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	daSID := "S-1-5-21-1111111111-2222222222-3333333333-512"
	u := types.User{SAMAccountName: "da-member", MemberOf: []string{daDN}, Disabled: true}
	data := &audit.DetectorData{
		Groups:      []types.Group{protectedUsersGroupFixture()},
		Users:       []types.User{u},
		ObjectBySID: withProtectedUsersSID(map[string]*audit.ObjectMeta{daSID: {DN: daDN, SID: daSID, EntityType: types.EntityTypeGroup}}),
	}

	f := NewNotInProtectedUsersOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled Domain Admins (-512) member not in Protected Users)", f.Count)
	}
}

// TestNotInProtectedUsersOnDisabledAccount_MemberListAloneProtectsAcrossCase
// mirrors the active detector's isolation of method 2 (the real -525
// group's own Member list) from method 1, on the disabled side: the
// privileged user's own MemberOf never references the Protected Users
// group at all (empty), so only the group's Member list can protect it.
func TestNotInProtectedUsersOnDisabledAccount_MemberListAloneProtectsAcrossCase(t *testing.T) {
	groupSID := "S-1-5-21-4444444444-5555555555-6666666666-525"
	resolvedDN := "cn=protected users,cn=users,dc=example,dc=com"
	collectedDN := "CN=PROTECTED USERS,CN=USERS,DC=EXAMPLE,DC=COM"
	memberEntryDN := "CN=CASE-MEMBER,CN=USERS,DC=EXAMPLE,DC=COM"
	userDN := "CN=Case-Member,CN=Users,DC=Example,DC=Com"

	u := types.User{SAMAccountName: "case-member", DN: userDN, AdminCount: true, Disabled: true}
	data := &audit.DetectorData{
		Groups: []types.Group{{CN: "Protected Users", SAMAccountName: "Protected Users", DN: collectedDN, ObjectSID: groupSID, Member: []string{memberEntryDN}}},
		Users:  []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: resolvedDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewNotInProtectedUsersOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (method 2 alone, across a DN case mismatch on both the group and its member entry, must still protect a disabled account)", f.Count)
	}
}

// TestNotInProtectedUsersOnDisabledAccount_RenamedKrbtgtStillExcludedByRID
// mirrors the active detector's RID-502 exclusion on the disabled side: no
// SPN is set, so this isolates the -502 exclusion from the SPN exclusion.
func TestNotInProtectedUsersOnDisabledAccount_RenamedKrbtgtStillExcludedByRID(t *testing.T) {
	u := types.User{SAMAccountName: "svc-legacy-kdc", AdminCount: true, Disabled: true, ObjectSID: "S-1-5-21-1111111111-2222222222-3333333333-502"}
	data := &audit.DetectorData{
		Groups:      []types.Group{protectedUsersGroupFixture()},
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{protectedUsersSID: {DN: protectedUsersDN, SID: protectedUsersSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewNotInProtectedUsersOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (RID -502 must stay excluded regardless of state)", f.Count)
	}
}
