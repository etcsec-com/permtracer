package membership

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestGpoModifyRightsOnDisabledAccount_DisabledMemberFires is the mirror
// positive of TestGpoModifyRights_DisabledMemberNotCounted: a disabled
// direct member of the real GPCO group must be counted here.
func TestGpoModifyRightsOnDisabledAccount_DisabledMemberFires(t *testing.T) {
	groupSID := gpoTestDomainSID + "-520"
	groupDN := "CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=local"
	u := types.User{
		DN:             "CN=disabled-member,CN=Users,DC=corp,DC=local",
		SAMAccountName: "disabled-member",
		Disabled:       true,
		MemberOf:       []string{groupDN},
	}
	data := &audit.DetectorData{
		Users: []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
		IncludeDetails: true,
	}

	f := NewGpoModifyRightsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled member of the real GPCO group must fire here)", f.Count)
	}
	if len(f.AffectedEntities) != 1 || f.AffectedEntities[0].DN != u.DN {
		t.Fatalf("AffectedEntities = %v, want only %q", f.AffectedEntities, u.DN)
	}
}

// TestGpoModifyRightsOnDisabledAccount_ActiveMemberDoesNotFire is the
// mirror negative: an active (non-disabled) member of the real GPCO group
// must not be counted here - it is covered instead by
// GpoModifyRightsDetector (gpo-modify-rights.go).
func TestGpoModifyRightsOnDisabledAccount_ActiveMemberDoesNotFire(t *testing.T) {
	groupSID := gpoTestDomainSID + "-520"
	groupDN := "CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=local"
	u := types.User{
		SAMAccountName: "active-member",
		Disabled:       false,
		MemberOf:       []string{groupDN},
	}
	data := &audit.DetectorData{
		Users: []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewGpoModifyRightsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (active member must not fire here, covered by the active detector instead)", f.Count)
	}
}

// TestGpoModifyRightsOnDisabledAccount_DisabledNonMemberDoesNotFire proves
// the group-membership condition still applies: a disabled user who is NOT
// a member of GPCO must not be counted.
func TestGpoModifyRightsOnDisabledAccount_DisabledNonMemberDoesNotFire(t *testing.T) {
	groupSID := gpoTestDomainSID + "-520"
	groupDN := "CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=local"
	u := types.User{
		SAMAccountName: "disabled-non-member",
		Disabled:       true,
		MemberOf:       []string{"CN=Marketing,CN=Users,DC=corp,DC=local"},
	}
	data := &audit.DetectorData{
		Users: []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewGpoModifyRightsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (disabled but not a GPCO member)", f.Count)
	}
}

// TestGpoModifyRightsOnDisabledAccount_IncludeDetailsFalseOmitsAffectedEntities
// proves the IncludeDetails gate's false side, left untested until now: with
// one disabled GPCO member and IncludeDetails=false, AffectedEntities must
// stay nil.
func TestGpoModifyRightsOnDisabledAccount_IncludeDetailsFalseOmitsAffectedEntities(t *testing.T) {
	groupSID := gpoTestDomainSID + "-520"
	groupDN := "CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=local"
	u := types.User{
		DN:             "CN=disabled-member,CN=Users,DC=corp,DC=local",
		SAMAccountName: "disabled-member",
		Disabled:       true,
		MemberOf:       []string{groupDN},
	}
	data := &audit.DetectorData{
		IncludeDetails: false,
		Users:          []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewGpoModifyRightsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.AffectedEntities != nil {
		t.Fatalf("AffectedEntities = %v, want nil (IncludeDetails=false)", f.AffectedEntities)
	}
}

// TestGpoModifyRightsOnDisabledAccount_TypeAndSeverity locks the finding's
// identifying fields, in particular the Medium severity mandated by the
// split severity grid (D1) for a domain-level privilege.
func TestGpoModifyRightsOnDisabledAccount_TypeAndSeverity(t *testing.T) {
	data := &audit.DetectorData{}
	f := NewGpoModifyRightsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Type != "GPO_MODIFY_RIGHTS_ON_DISABLED_ACCOUNT" {
		t.Fatalf("Type = %q, want %q", f.Type, "GPO_MODIFY_RIGHTS_ON_DISABLED_ACCOUNT")
	}
	if f.Severity != types.SeverityMedium {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityMedium)
	}
}

// TestGpoModifyRightsOnDisabledAccount_PrimaryGroupDisabledCounted proves
// the twin's primary-group path: a DISABLED user whose primary group is
// GPCO (PrimaryGroupID 520, resolved via DomainSID+"-520" in ObjectBySID),
// with no memberOf entry at all, must be counted here and not by the
// active detector - mirroring TestGpoModifyRights_PrimaryGroupCounted's
// primary-group construction on the disabled side.
func TestGpoModifyRightsOnDisabledAccount_PrimaryGroupDisabledCounted(t *testing.T) {
	groupSID := gpoTestDomainSID + "-520"
	groupDN := "CN=Group Policy Creator Owners,CN=Users,DC=example,DC=com"
	u := types.User{
		SAMAccountName: "disabled-primary-group-member",
		Disabled:       true,
		PrimaryGroupID: 520,
		MemberOf:       nil,
	}
	data := &audit.DetectorData{
		Users:      []types.User{u},
		DomainInfo: &types.DomainInfo{DomainSID: gpoTestDomainSID},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	disabled := NewGpoModifyRightsOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if disabled.Count != 1 {
		t.Fatalf("disabled Count = %d, want 1 (GPCO as PRIMARY group, disabled account, no memberOf entry at all)", disabled.Count)
	}

	active := NewGpoModifyRightsDetector().Detect(context.Background(), data)[0]
	if active.Count != 0 {
		t.Fatalf("active Count = %d, want 0 (user is disabled, must not be counted by the active detector)", active.Count)
	}
}

// TestGpoModifyRightsPartition_ExhaustiveAndDisjoint proves the acceptance
// criterion that both halves of the split share exactly the same GPCO
// membership condition and partition the same population without overlap:
// for a fixed set of direct GPCO members, every user lands in exactly one
// of the two detectors, split only on Disabled, and the two
// AffectedEntities sets are disjoint.
func TestGpoModifyRightsPartition_ExhaustiveAndDisjoint(t *testing.T) {
	groupSID := gpoTestDomainSID + "-520"
	groupDN := "CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=local"
	dn1 := "CN=alice,CN=Users,DC=corp,DC=local"
	dn2 := "CN=bob,CN=Users,DC=corp,DC=local"
	dn3 := "CN=carol,CN=Users,DC=corp,DC=local"
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{DN: dn1, SAMAccountName: "enabled-1", MemberOf: []string{groupDN}, Disabled: false},
			{DN: dn2, SAMAccountName: "enabled-2", MemberOf: []string{groupDN}, Disabled: false},
			{DN: dn3, SAMAccountName: "disabled-1", MemberOf: []string{groupDN}, Disabled: true},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	active := NewGpoModifyRightsDetector().Detect(context.Background(), data)
	disabled := NewGpoModifyRightsOnDisabledAccountDetector().Detect(context.Background(), data)

	if len(active) != 1 || active[0].Count != 2 {
		t.Fatalf("active findings = %+v, want 1 finding with count 2", active)
	}
	if len(disabled) != 1 || disabled[0].Count != 1 {
		t.Fatalf("disabled findings = %+v, want 1 finding with count 1", disabled)
	}
	if active[0].Count+disabled[0].Count != len(data.Users) {
		t.Fatalf("partition not exhaustive: active=%d + disabled=%d != total=%d", active[0].Count, disabled[0].Count, len(data.Users))
	}

	seen := map[string]bool{}
	for _, e := range active[0].AffectedEntities {
		seen[e.SAMAccountName] = true
	}
	for _, e := range disabled[0].AffectedEntities {
		if seen[e.SAMAccountName] {
			t.Fatalf("%s appears in both the active and disabled-account finding: partition is not disjoint", e.SAMAccountName)
		}
	}
}
