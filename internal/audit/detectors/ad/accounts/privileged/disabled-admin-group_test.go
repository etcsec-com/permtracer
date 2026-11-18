package privileged

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestDisabledAdminGroup_RenamedDomainAdminsStillFlagged: the real -512
// group, renamed to a localized display name, must still be recognized by
// RID suffix and count its disabled member.
func TestDisabledAdminGroup_RenamedDomainAdminsStillFlagged(t *testing.T) {
	dn := "CN=Admins du domaine,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-512"
	u := types.User{SAMAccountName: "renamed-member", MemberOf: []string{dn}, Disabled: true}
	data := &audit.DetectorData{
		Groups: []types.Group{{CN: "Admins du domaine", SAMAccountName: "Admins du domaine", DN: dn, ObjectSID: sid}},
		Users:  []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewDisabledAdminGroupDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (renamed -512 group member, disabled, must be flagged)", f.Count)
	}
}

// TestDisabledAdminGroup_OrdinaryGroupNamedDomainAdminsDecoyNotFlagged: a
// group literally named "Domain Admins Decoy" with an ordinary RID grants
// no real privilege, so its disabled member must not be flagged.
func TestDisabledAdminGroup_OrdinaryGroupNamedDomainAdminsDecoyNotFlagged(t *testing.T) {
	dn := "CN=Domain Admins Decoy,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-9201"
	u := types.User{SAMAccountName: "decoy-member", MemberOf: []string{dn}, Disabled: true}
	data := &audit.DetectorData{
		Groups: []types.Group{{CN: "Domain Admins Decoy", SAMAccountName: "Domain Admins Decoy", DN: dn, ObjectSID: sid}},
		Users:  []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewDisabledAdminGroupDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (\"Domain Admins Decoy\" with an ordinary RID must not count as an admin group)", f.Count)
	}
}

// TestDisabledAdminGroup_EnterpriseAdminsSuffixFlagged covers the -519
// Enterprise Admins RID in isolation.
func TestDisabledAdminGroup_EnterpriseAdminsSuffixFlagged(t *testing.T) {
	dn := "CN=Enterprise Admins,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-519"
	u := types.User{SAMAccountName: "ea-member", MemberOf: []string{dn}, Disabled: true}
	data := &audit.DetectorData{
		Groups: []types.Group{{CN: "Enterprise Admins", SAMAccountName: "Enterprise Admins", DN: dn, ObjectSID: sid}},
		Users:  []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewDisabledAdminGroupDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (-519 Enterprise Admins member, disabled, must be flagged)", f.Count)
	}
}

// TestDisabledAdminGroup_SchemaAdminsSuffixFlagged covers the -518 Schema
// Admins RID in isolation.
func TestDisabledAdminGroup_SchemaAdminsSuffixFlagged(t *testing.T) {
	dn := "CN=Schema Admins,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-518"
	u := types.User{SAMAccountName: "sa-member", MemberOf: []string{dn}, Disabled: true}
	data := &audit.DetectorData{
		Groups: []types.Group{{CN: "Schema Admins", SAMAccountName: "Schema Admins", DN: dn, ObjectSID: sid}},
		Users:  []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewDisabledAdminGroupDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (-518 Schema Admins member, disabled, must be flagged)", f.Count)
	}
}

// TestDisabledAdminGroup_EmptyMemberOfNotFlagged: a disabled user with no
// MemberOf at all must never be flagged, regardless of group resolution.
func TestDisabledAdminGroup_EmptyMemberOfNotFlagged(t *testing.T) {
	sid := "S-1-5-21-1111111111-2222222222-3333333333-512"
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	u := types.User{SAMAccountName: "no-membership", Disabled: true}
	data := &audit.DetectorData{
		Groups: []types.Group{{CN: "Domain Admins", SAMAccountName: "Domain Admins", DN: dn, ObjectSID: sid}},
		Users:  []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewDisabledAdminGroupDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (empty MemberOf must never be flagged)", f.Count)
	}
}

// TestDisabledAdminGroup_ActiveAdminNotFlagged is the detector's own
// condition: an active (not disabled) admin group member must not be
// flagged, whether by Disabled or by the UAC bit.
func TestDisabledAdminGroup_ActiveAdminNotFlagged(t *testing.T) {
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-512"
	u := types.User{SAMAccountName: "active-admin", MemberOf: []string{dn}}
	data := &audit.DetectorData{
		Groups: []types.Group{{CN: "Domain Admins", SAMAccountName: "Domain Admins", DN: dn, ObjectSID: sid}},
		Users:  []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewDisabledAdminGroupDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (active admin group member must not be flagged)", f.Count)
	}
}

// TestDisabledAdminGroup_UACBitAloneFlagsWithoutDisabledField: the
// UserAccountControl bit 0x2 alone (Disabled field left false) must still
// flag an admin group member, matching the detector's isDisabled OR logic.
func TestDisabledAdminGroup_UACBitAloneFlagsWithoutDisabledField(t *testing.T) {
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-512"
	u := types.User{SAMAccountName: "uac-disabled", MemberOf: []string{dn}, UserAccountControl: 0x2}
	data := &audit.DetectorData{
		Groups: []types.Group{{CN: "Domain Admins", SAMAccountName: "Domain Admins", DN: dn, ObjectSID: sid}},
		Users:  []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewDisabledAdminGroupDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (UAC bit 0x2 alone must flag the admin group member)", f.Count)
	}
}

// TestDisabledAdminGroup_DoubleMembershipCountedOnce: a disabled user
// belonging to two admin groups (-512 and -519) must be counted exactly
// once, not twice.
func TestDisabledAdminGroup_DoubleMembershipCountedOnce(t *testing.T) {
	daDN := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	daSID := "S-1-5-21-1111111111-2222222222-3333333333-512"
	eaDN := "CN=Enterprise Admins,CN=Users,DC=example,DC=com"
	eaSID := "S-1-5-21-1111111111-2222222222-3333333333-519"
	u := types.User{SAMAccountName: "double-member", MemberOf: []string{daDN, eaDN}, Disabled: true}
	data := &audit.DetectorData{
		Groups: []types.Group{
			{CN: "Domain Admins", SAMAccountName: "Domain Admins", DN: daDN, ObjectSID: daSID},
			{CN: "Enterprise Admins", SAMAccountName: "Enterprise Admins", DN: eaDN, ObjectSID: eaSID},
		},
		Users: []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			daSID: {DN: daDN, SID: daSID, EntityType: types.EntityTypeGroup},
			eaSID: {DN: eaDN, SID: eaSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewDisabledAdminGroupDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (double admin-group membership must be counted once)", f.Count)
	}
}

// TestDisabledAdminGroup_IncludeDetailsTrueAttachesAffectedEntities proves
// the IncludeDetails gate's true side: with one affected disabled admin and
// IncludeDetails=true, AffectedEntities must be populated.
func TestDisabledAdminGroup_IncludeDetailsTrueAttachesAffectedEntities(t *testing.T) {
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-512"
	u := types.User{DN: "CN=flagged,CN=Users,DC=example,DC=com", SAMAccountName: "flagged", MemberOf: []string{dn}, Disabled: true}
	data := &audit.DetectorData{
		IncludeDetails: true,
		Groups:         []types.Group{{CN: "Domain Admins", SAMAccountName: "Domain Admins", DN: dn, ObjectSID: sid}},
		Users:          []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewDisabledAdminGroupDetector().Detect(context.Background(), data)[0]
	if len(f.AffectedEntities) != 1 {
		t.Fatalf("AffectedEntities = %v, want 1 entity (IncludeDetails=true with 1 affected)", f.AffectedEntities)
	}
}

// TestDisabledAdminGroup_IncludeDetailsFalseOmitsAffectedEntities proves the
// IncludeDetails gate's false side: with the same affected disabled admin,
// IncludeDetails=false must leave AffectedEntities nil.
func TestDisabledAdminGroup_IncludeDetailsFalseOmitsAffectedEntities(t *testing.T) {
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-512"
	u := types.User{DN: "CN=flagged,CN=Users,DC=example,DC=com", SAMAccountName: "flagged", MemberOf: []string{dn}, Disabled: true}
	data := &audit.DetectorData{
		IncludeDetails: false,
		Groups:         []types.Group{{CN: "Domain Admins", SAMAccountName: "Domain Admins", DN: dn, ObjectSID: sid}},
		Users:          []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewDisabledAdminGroupDetector().Detect(context.Background(), data)[0]
	if f.AffectedEntities != nil {
		t.Fatalf("AffectedEntities = %v, want nil (IncludeDetails=false)", f.AffectedEntities)
	}
}
