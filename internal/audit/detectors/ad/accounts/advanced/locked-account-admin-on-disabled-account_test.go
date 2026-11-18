package advanced

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestLockedAccountAdminOnDisabledAccount_DisabledLockedMemberFlagged is the
// baseline positive: a disabled, locked direct member of an admin group
// (here Domain Admins, -512) must be counted here.
func TestLockedAccountAdminOnDisabledAccount_DisabledLockedMemberFlagged(t *testing.T) {
	daDN := "CN=Domain Admins,CN=Users,DC=corp,DC=local"
	daSID := "S-1-5-21-1111111111-2222222222-3333333333-512"
	u := types.User{
		MemberOf:    []string{daDN},
		LockoutTime: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC),
		Disabled:    true,
	}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{daSID: {DN: daDN, SID: daSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewLockedAccountAdminOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled, locked Domain Admins membership)", f.Count)
	}
}

// TestLockedAccountAdminOnDisabledAccount_ActiveMemberNotFlagged is the
// partition guard from this detector's side: an enabled, locked direct
// member of an admin group must not be counted here - it belongs to
// LockedAccountAdminDetector instead. The opposite side is asserted by
// TestLockedAccountAdmin_DisabledMemberNotFlagged.
func TestLockedAccountAdminOnDisabledAccount_ActiveMemberNotFlagged(t *testing.T) {
	daDN := "CN=Domain Admins,CN=Users,DC=corp,DC=local"
	daSID := "S-1-5-21-1111111111-2222222222-3333333333-512"
	u := types.User{
		MemberOf:    []string{daDN},
		LockoutTime: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC),
	}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{daSID: {DN: daDN, SID: daSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewLockedAccountAdminOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (enabled locked admin must not be counted by the disabled twin)", f.Count)
	}
}

// TestLockedAccountAdminOnDisabledAccount_NotLockedNotFlagged: a disabled
// admin group member with no lockoutTime signal must not be flagged - the
// subject of this detector is the lockout, not merely the disabled state.
func TestLockedAccountAdminOnDisabledAccount_NotLockedNotFlagged(t *testing.T) {
	daDN := "CN=Domain Admins,CN=Users,DC=corp,DC=local"
	daSID := "S-1-5-21-1111111111-2222222222-3333333333-512"
	u := types.User{
		MemberOf: []string{daDN},
		Disabled: true,
	}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{daSID: {DN: daDN, SID: daSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewLockedAccountAdminOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (disabled but never-locked admin must not be flagged)", f.Count)
	}
}

// TestLockedAccountAdminOnDisabledAccount_NonMemberNotFlagged: a disabled,
// locked account that is not a member of any admin group must not be
// flagged.
func TestLockedAccountAdminOnDisabledAccount_NonMemberNotFlagged(t *testing.T) {
	u := types.User{
		LockoutTime: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC),
		Disabled:    true,
	}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{},
	}

	f := NewLockedAccountAdminOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (disabled, locked non-member must not be flagged)", f.Count)
	}
}

// TestLockedAccountAdminOnDisabledAccount_SeverityIsMedium locks this
// detector's severity at Medium: direct membership in a tier 0/tier 1 admin
// group is a domain-level privilege that stays posted on the object and
// returns to full effect the instant the account is re-enabled, distinct
// from the High of the active-member detector.
func TestLockedAccountAdminOnDisabledAccount_SeverityIsMedium(t *testing.T) {
	daDN := "CN=Domain Admins,CN=Users,DC=corp,DC=local"
	daSID := "S-1-5-21-1111111111-2222222222-3333333333-512"
	u := types.User{
		MemberOf:    []string{daDN},
		LockoutTime: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC),
		Disabled:    true,
	}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{daSID: {DN: daDN, SID: daSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewLockedAccountAdminOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Severity != types.SeverityMedium {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityMedium)
	}
}

// TestLockedAccountAdminOnDisabledAccount_PreEpochLockoutTimeNotFlagged
// mirrors TestLockedAccountAdmin_PreEpochLockoutTimeNotFlagged for the
// disabled twin: a non-zero LockoutTime whose year is 1601 - the FILETIME
// epoch (1601-01-01), the sentinel a parser can emit for an all-zero or
// otherwise degenerate FILETIME value - must not be treated as a real
// lockout, even though IsZero() is false for it.
func TestLockedAccountAdminOnDisabledAccount_PreEpochLockoutTimeNotFlagged(t *testing.T) {
	daDN := "CN=Domain Admins,CN=Users,DC=corp,DC=local"
	daSID := "S-1-5-21-1111111111-2222222222-3333333333-512"
	u := types.User{
		MemberOf:    []string{daDN},
		LockoutTime: time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC),
		Disabled:    true,
	}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{daSID: {DN: daDN, SID: daSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewLockedAccountAdminOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (non-zero LockoutTime at the FILETIME epoch year 1601 must not be treated as a real lockout)", f.Count)
	}
}

// TestLockedAccountAdminOnDisabledAccount_ExactGroupSet is the table-driven
// exact-set lock, mirroring TestLockedAccountAdmin_ExactGroupSet but with
// every fixture disabled: inSet is adminGroupSIDSuffixes' 7 suffixes,
// written here as a literal (never read from the package var); universe
// adds two witnesses used by NONE of the admin-by-SID detectors: -520 (Group
// Policy Creator Owners) and -547 (Power Users), confirmed against
// internal/audit/wellknown_sids.go.
func TestLockedAccountAdminOnDisabledAccount_ExactGroupSet(t *testing.T) {
	inSet := []string{"-512", "-519", "-518", "-544", "-548", "-549", "-551"}
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
	lockoutTime := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

	for _, suffix := range inSet {
		suffix := suffix
		t.Run("in_set"+suffix, func(t *testing.T) {
			dn := "CN=Group" + suffix + ",CN=Users,DC=example,DC=com"
			sid := "S-1-5-21-9999999999-8888888888-7777777777" + suffix
			u := types.User{LockoutTime: lockoutTime, MemberOf: []string{dn}, Disabled: true}
			data := &audit.DetectorData{
				Users:       []types.User{u},
				ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
			}
			f := NewLockedAccountAdminOnDisabledAccountDetector().Detect(context.Background(), data)[0]
			if f.Count != 1 {
				t.Fatalf("suffix %s is in adminGroupSIDSuffixes; disabled locked membership must be flagged, got Count=%d, want 1", suffix, f.Count)
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
			u := types.User{LockoutTime: lockoutTime, MemberOf: []string{dn}, Disabled: true}
			data := &audit.DetectorData{
				Users:       []types.User{u},
				ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
			}
			f := NewLockedAccountAdminOnDisabledAccountDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("suffix %s is NOT in adminGroupSIDSuffixes; disabled locked membership must not be flagged, got Count=%d, want 0", suffix, f.Count)
			}
		})
	}
}
