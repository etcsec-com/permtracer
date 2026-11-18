package other

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestAltSecurityIdentitiesOnDisabledAccount_DisabledMemberFlagged is the
// mirror-image baseline positive: a disabled real Backup Operators member
// (S-1-5-32-551) with a non-empty altSecurityIdentities must be flagged by
// the twin detector.
func TestAltSecurityIdentitiesOnDisabledAccount_DisabledMemberFlagged(t *testing.T) {
	dn := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-551"
	u := types.User{
		SAMAccountName:        "disabled-bo-member",
		Disabled:              true,
		AltSecurityIdentities: []string{"X509:<I>CN=CA<S>CN=disabled-bo-member"},
		MemberOf:              []string{dn},
	}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewAltSecurityIdentitiesOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled real Backup Operators member with altSecurityIdentities)", f.Count)
	}
}

// TestAltSecurityIdentitiesOnDisabledAccount_EnabledMemberNotFlagged proves
// the mirror guard (alt-security-identities-on-disabled-account.go:48-50) is
// load-bearing: an enabled account that would otherwise match must not be
// counted by the twin - it is covered by the active detector instead.
func TestAltSecurityIdentitiesOnDisabledAccount_EnabledMemberNotFlagged(t *testing.T) {
	dn := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-551"
	u := types.User{
		SAMAccountName:        "enabled-bo-member",
		AltSecurityIdentities: []string{"X509:<I>CN=CA<S>CN=enabled-bo-member"},
		MemberOf:              []string{dn},
	}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewAltSecurityIdentitiesOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (enabled account must not be flagged by the disabled-account twin)", f.Count)
	}
}

// TestAltSecurityIdentitiesOnDisabledAccount_EmptyAttributeNotFlagged mirrors
// TestAltSecurityIdentities_EmptyAttributeNotFlagged: no altSecurityIdentities
// value means no finding, regardless of group membership or account state.
func TestAltSecurityIdentitiesOnDisabledAccount_EmptyAttributeNotFlagged(t *testing.T) {
	dn := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-551"
	u := types.User{SAMAccountName: "disabled-no-altsec", Disabled: true, MemberOf: []string{dn}}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewAltSecurityIdentitiesOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (no altSecurityIdentities value)", f.Count)
	}
}

// TestAltSecurityIdentitiesOnDisabledAccount_HomonymGroupNotFlagged mirrors
// TestAltSecurityIdentities_HomonymGroupNotFlagged on a disabled account: a
// group whose CN is literally "Backup Operators" but which carries an
// ordinary domain RID (not -551) grants no real privilege, so the
// privgroups.IsMemberOfAny SID-suffix check on
// alt-security-identities-on-disabled-account.go:55 must not match it.
func TestAltSecurityIdentitiesOnDisabledAccount_HomonymGroupNotFlagged(t *testing.T) {
	fakeDN := "CN=Backup Operators,CN=Users,DC=example,DC=com"
	fakeSID := "S-1-5-21-1111111111-2222222222-3333333333-9112"
	u := types.User{
		SAMAccountName:        "disabled-homonym-member",
		Disabled:              true,
		AltSecurityIdentities: []string{"X509:<I>CN=CA<S>CN=disabled-homonym-member"},
		MemberOf:              []string{fakeDN},
	}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{fakeSID: {DN: fakeDN, SID: fakeSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewAltSecurityIdentitiesOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (Backup-Operators-named group with an ordinary RID must not count as privileged, even on a disabled account)", f.Count)
	}
}

// TestAltSecurityIdentitiesOnDisabledAccount_ExactGroupSet mirrors
// TestAltSecurityIdentities_ExactGroupSet on disabled accounts: the same 8
// suffixes in altSecAdminGroupSIDSuffixes must flag a disabled member, and
// every other suffix in the shared universe must not, exercising
// privgroups.IsMemberOfAny on alt-security-identities-on-disabled-account.go:55
// across the full in/out boundary rather than a single admin group.
func TestAltSecurityIdentitiesOnDisabledAccount_ExactGroupSet(t *testing.T) {
	inSet := []string{"-512", "-519", "-518", "-544", "-548", "-549", "-551", "-550"}
	universe := []string{
		"-512", "-516", "-517", "-518", "-519", "-521", "-526", "-527", "-544",
		"-548", "-549", "-550", "-551", "-552", "-553", "-555", "-556", "-557",
		"-558", "-559", "-560", "-561", "-562", "-569", "-573", "-578", "-579",
		"-580", "-520", "-547",
	}
	inSetIdx := make(map[string]bool, len(inSet))
	for _, s := range inSet {
		inSetIdx[s] = true
	}

	for _, suffix := range inSet {
		suffix := suffix
		t.Run("in_set"+suffix, func(t *testing.T) {
			dn := "CN=Group" + suffix + ",CN=Users,DC=example,DC=com"
			sid := "S-1-5-21-9999999999-8888888888-7777777777" + suffix
			u := types.User{
				SAMAccountName:        "disabled-member" + suffix,
				Disabled:              true,
				AltSecurityIdentities: []string{"X509:<I>CN=CA<S>CN=disabled-member" + suffix},
				MemberOf:              []string{dn},
			}
			data := &audit.DetectorData{
				Users:       []types.User{u},
				ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
			}
			f := NewAltSecurityIdentitiesOnDisabledAccountDetector().Detect(context.Background(), data)[0]
			if f.Count != 1 {
				t.Fatalf("suffix %s is in altSecAdminGroupSIDSuffixes; disabled membership must be flagged, got Count=%d, want 1", suffix, f.Count)
			}
		})
	}

	for _, suffix := range universe {
		if inSetIdx[suffix] {
			continue
		}
		suffix := suffix
		t.Run("out_of_set"+suffix, func(t *testing.T) {
			dn := "CN=Group" + suffix + ",CN=Users,DC=example,DC=com"
			sid := "S-1-5-21-9999999999-8888888888-7777777777" + suffix
			u := types.User{
				SAMAccountName:        "disabled-member" + suffix,
				Disabled:              true,
				AltSecurityIdentities: []string{"X509:<I>CN=CA<S>CN=disabled-member" + suffix},
				MemberOf:              []string{dn},
			}
			data := &audit.DetectorData{
				Users:       []types.User{u},
				ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
			}
			f := NewAltSecurityIdentitiesOnDisabledAccountDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("suffix %s is NOT in altSecAdminGroupSIDSuffixes; disabled membership alone must not be flagged, got Count=%d, want 0", suffix, f.Count)
			}
		})
	}
}

// TestAltSecurityIdentitiesOnDisabledAccount_AffectedEntitiesWhenIncludeDetails
// proves the IncludeDetails guard (alt-security-identities-on-disabled-account.go:69)
// is load-bearing: a disabled real Backup Operators member with
// IncludeDetails=true must carry exactly one AffectedEntity, with that
// user's DN.
func TestAltSecurityIdentitiesOnDisabledAccount_AffectedEntitiesWhenIncludeDetails(t *testing.T) {
	dn := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-551"
	userDN := "CN=disabled-bo-member,CN=Users,DC=example,DC=com"
	u := types.User{
		DN:                    userDN,
		SAMAccountName:        "disabled-bo-member",
		Disabled:              true,
		AltSecurityIdentities: []string{"X509:<I>CN=CA<S>CN=disabled-bo-member"},
		MemberOf:              []string{dn},
	}
	data := &audit.DetectorData{
		Users:          []types.User{u},
		ObjectBySID:    map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
		IncludeDetails: true,
	}

	f := NewAltSecurityIdentitiesOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1", f.Count)
	}
	if len(f.AffectedEntities) != 1 {
		t.Fatalf("len(AffectedEntities) = %d, want 1 (IncludeDetails=true must populate AffectedEntities)", len(f.AffectedEntities))
	}
	if f.AffectedEntities[0].DN != userDN {
		t.Fatalf("AffectedEntities[0].DN = %q, want %q", f.AffectedEntities[0].DN, userDN)
	}
}

// TestAltSecurityIdentitiesOnDisabledAccount_NoEntitiesWhenDetailsExcluded
// proves the other side of the same guard: with IncludeDetails=false, Count
// must still be 1 but AffectedEntities must stay empty.
func TestAltSecurityIdentitiesOnDisabledAccount_NoEntitiesWhenDetailsExcluded(t *testing.T) {
	dn := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-551"
	userDN := "CN=disabled-bo-member,CN=Users,DC=example,DC=com"
	u := types.User{
		DN:                    userDN,
		SAMAccountName:        "disabled-bo-member",
		Disabled:              true,
		AltSecurityIdentities: []string{"X509:<I>CN=CA<S>CN=disabled-bo-member"},
		MemberOf:              []string{dn},
	}
	data := &audit.DetectorData{
		Users:          []types.User{u},
		ObjectBySID:    map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
		IncludeDetails: false,
	}

	f := NewAltSecurityIdentitiesOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1", f.Count)
	}
	if len(f.AffectedEntities) != 0 {
		t.Fatalf("len(AffectedEntities) = %d, want 0 (IncludeDetails=false must not populate AffectedEntities)", len(f.AffectedEntities))
	}
}

// TestAltSecurityIdentitiesOnDisabledAccount_TypeAndSeverityLiteral pins the
// twin's ID and severity against the D1/D2 grid: the disabled account
// retains a domain-level privilege (privileged group membership) and the
// altSecurityIdentities mapping persists as an exposed credential mapping,
// so severity is Medium, not Low.
func TestAltSecurityIdentitiesOnDisabledAccount_TypeAndSeverityLiteral(t *testing.T) {
	dn := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-551"
	u := types.User{
		SAMAccountName:        "disabled-bo-member",
		Disabled:              true,
		AltSecurityIdentities: []string{"X509:<I>CN=CA<S>CN=disabled-bo-member"},
		MemberOf:              []string{dn},
	}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewAltSecurityIdentitiesOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Type != "ALT_SECURITY_IDENTITIES_ON_DISABLED_ACCOUNT" {
		t.Fatalf("Type = %q, want %q", f.Type, "ALT_SECURITY_IDENTITIES_ON_DISABLED_ACCOUNT")
	}
	if string(f.Severity) != "medium" {
		t.Fatalf("Severity = %q, want %q (D1/D2 grid: disabled account retains privileged group membership)", f.Severity, "medium")
	}
}
