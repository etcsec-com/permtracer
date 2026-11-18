package privileged

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestExpiredAdminGroup_RenamedDomainAdminsStillFlagged: the real -512
// group, renamed to a localized display name, must still be recognized by
// RID suffix and count its expired member.
func TestExpiredAdminGroup_RenamedDomainAdminsStillFlagged(t *testing.T) {
	dn := "CN=Admins du domaine,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-512"
	u := types.User{
		SAMAccountName: "renamed-member",
		MemberOf:       []string{dn},
		AccountExpires: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	data := &audit.DetectorData{
		Now:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Groups: []types.Group{{CN: "Admins du domaine", SAMAccountName: "Admins du domaine", DN: dn, ObjectSID: sid}},
		Users:  []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewExpiredAdminGroupDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (renamed -512 group member, expired, must be flagged)", f.Count)
	}
}

// TestExpiredAdminGroup_OrdinaryGroupNamedDomainAdminsDecoyNotFlagged: a
// group literally named "Domain Admins Decoy" with an ordinary RID grants
// no real privilege, so its expired member must not be flagged.
func TestExpiredAdminGroup_OrdinaryGroupNamedDomainAdminsDecoyNotFlagged(t *testing.T) {
	dn := "CN=Domain Admins Decoy,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-9201"
	u := types.User{
		SAMAccountName: "decoy-member",
		MemberOf:       []string{dn},
		AccountExpires: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	data := &audit.DetectorData{
		Now:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Groups: []types.Group{{CN: "Domain Admins Decoy", SAMAccountName: "Domain Admins Decoy", DN: dn, ObjectSID: sid}},
		Users:  []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewExpiredAdminGroupDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (\"Domain Admins Decoy\" with an ordinary RID must not count as an admin group)", f.Count)
	}
}

// TestExpiredAdminGroup_EnterpriseAdminsSuffixFlagged covers the -519
// Enterprise Admins RID in isolation.
func TestExpiredAdminGroup_EnterpriseAdminsSuffixFlagged(t *testing.T) {
	dn := "CN=Enterprise Admins,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-519"
	u := types.User{
		SAMAccountName: "ea-member",
		MemberOf:       []string{dn},
		AccountExpires: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	data := &audit.DetectorData{
		Now:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Groups: []types.Group{{CN: "Enterprise Admins", SAMAccountName: "Enterprise Admins", DN: dn, ObjectSID: sid}},
		Users:  []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewExpiredAdminGroupDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (-519 Enterprise Admins member, expired, must be flagged)", f.Count)
	}
}

// TestExpiredAdminGroup_SchemaAdminsSuffixFlagged covers the -518 Schema
// Admins RID in isolation.
func TestExpiredAdminGroup_SchemaAdminsSuffixFlagged(t *testing.T) {
	dn := "CN=Schema Admins,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-518"
	u := types.User{
		SAMAccountName: "sa-member",
		MemberOf:       []string{dn},
		AccountExpires: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	data := &audit.DetectorData{
		Now:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Groups: []types.Group{{CN: "Schema Admins", SAMAccountName: "Schema Admins", DN: dn, ObjectSID: sid}},
		Users:  []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewExpiredAdminGroupDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (-518 Schema Admins member, expired, must be flagged)", f.Count)
	}
}

// TestExpiredAdminGroup_EmptyMemberOfNotFlagged: an expired user with no
// MemberOf at all must never be flagged, regardless of group resolution.
func TestExpiredAdminGroup_EmptyMemberOfNotFlagged(t *testing.T) {
	sid := "S-1-5-21-1111111111-2222222222-3333333333-512"
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	u := types.User{
		SAMAccountName: "no-membership",
		AccountExpires: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	data := &audit.DetectorData{
		Now:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Groups: []types.Group{{CN: "Domain Admins", SAMAccountName: "Domain Admins", DN: dn, ObjectSID: sid}},
		Users:  []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewExpiredAdminGroupDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (empty MemberOf must never be flagged)", f.Count)
	}
}

// TestExpiredAdminGroup_NonExpiredAdminNotFlagged is the detector's own
// condition: a non-expired admin group member must not be flagged.
func TestExpiredAdminGroup_NonExpiredAdminNotFlagged(t *testing.T) {
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-512"
	u := types.User{
		SAMAccountName: "active-admin",
		MemberOf:       []string{dn},
		AccountExpires: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	data := &audit.DetectorData{
		Now:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Groups: []types.Group{{CN: "Domain Admins", SAMAccountName: "Domain Admins", DN: dn, ObjectSID: sid}},
		Users:  []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewExpiredAdminGroupDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (AccountExpires in the future must not be flagged)", f.Count)
	}
}

// TestExpiredAdminGroup_NeverExpiresNotFlagged: a zero-value AccountExpires
// (account never expires) must not be flagged even with admin membership.
func TestExpiredAdminGroup_NeverExpiresNotFlagged(t *testing.T) {
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-512"
	u := types.User{
		SAMAccountName: "never-expires-admin",
		MemberOf:       []string{dn},
	}
	data := &audit.DetectorData{
		Now:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Groups: []types.Group{{CN: "Domain Admins", SAMAccountName: "Domain Admins", DN: dn, ObjectSID: sid}},
		Users:  []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{
			sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewExpiredAdminGroupDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (zero-value AccountExpires means never expires)", f.Count)
	}
}

// TestExpiredAdminGroup_DoubleMembershipCountedOnce: an expired user
// belonging to two admin groups (-512 and -519) must be counted exactly
// once, not twice.
func TestExpiredAdminGroup_DoubleMembershipCountedOnce(t *testing.T) {
	daDN := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	daSID := "S-1-5-21-1111111111-2222222222-3333333333-512"
	eaDN := "CN=Enterprise Admins,CN=Users,DC=example,DC=com"
	eaSID := "S-1-5-21-1111111111-2222222222-3333333333-519"
	u := types.User{
		SAMAccountName: "double-member",
		MemberOf:       []string{daDN, eaDN},
		AccountExpires: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	data := &audit.DetectorData{
		Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
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

	f := NewExpiredAdminGroupDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (double admin-group membership must be counted once)", f.Count)
	}
}
