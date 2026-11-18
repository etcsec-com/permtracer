package security

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestComputerStaleWithAdminGroups_RealMembershipStillFlagged is a baseline
// positive: a stale, enabled computer directly in the real Backup
// Operators group (S-1-5-32-551) must be flagged.
func TestComputerStaleWithAdminGroups_RealMembershipStillFlagged(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	dn := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-551"
	c := types.Computer{
		SAMAccountName:     "STALE-PC$",
		MemberOf:           []string{dn},
		LastLogonTimestamp: now.AddDate(0, 0, -120),
	}
	data := &audit.DetectorData{
		Now:         now,
		Computers:   []types.Computer{c},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewComputerStaleWithAdminGroupsDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (real stale Backup Operators computer member)", f.Count)
	}
}

// TestComputerStaleWithAdminGroups_HomonymGroupNotFlagged is the
// homonym-group case: a group whose CN is literally "Backup Operators" but which
// carries an ordinary domain RID (not -551) grants no real privilege.
func TestComputerStaleWithAdminGroups_HomonymGroupNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	fakeDN := "CN=Backup Operators,CN=Users,DC=example,DC=com"
	fakeSID := "S-1-5-21-1111111111-2222222222-3333333333-9114"
	c := types.Computer{
		SAMAccountName:     "HOMONYM-PC$",
		MemberOf:           []string{fakeDN},
		LastLogonTimestamp: now.AddDate(0, 0, -120),
	}
	data := &audit.DetectorData{
		Now:         now,
		Computers:   []types.Computer{c},
		ObjectBySID: map[string]*audit.ObjectMeta{fakeSID: {DN: fakeDN, SID: fakeSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewComputerStaleWithAdminGroupsDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (Backup-Operators-named group with an ordinary RID must not count as admin)", f.Count)
	}
}

// TestComputerStaleWithAdminGroups_RenamedGroupStillFlagged is the
// renamed-group case: the real Backup Operators group renamed to its French
// localized display name must still be recognized by SID suffix.
func TestComputerStaleWithAdminGroups_RenamedGroupStillFlagged(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	localizedDN := "CN=Opérateurs de sauvegarde,CN=Builtin,DC=example,DC=com"
	realSID := "S-1-5-32-551"
	c := types.Computer{
		SAMAccountName:     "LOCALIZED-PC$",
		MemberOf:           []string{localizedDN},
		LastLogonTimestamp: now.AddDate(0, 0, -120),
	}
	data := &audit.DetectorData{
		Now:         now,
		Computers:   []types.Computer{c},
		ObjectBySID: map[string]*audit.ObjectMeta{realSID: {DN: localizedDN, SID: realSID, EntityType: types.EntityTypeGroup}},
	}

	f := NewComputerStaleWithAdminGroupsDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (real Backup Operators group under a localized name must still be flagged)", f.Count)
	}
}

// TestComputerStaleWithAdminGroups_ExactGroupSet is the table-driven
// exact-set lock: inSet is staleAdminGroupSIDSuffixes' 8 suffixes, written
// here as a literal (never read from the package var) and cross-checked
// against docs/security-validation/results/privileged-by-sid/VERDICT.md §1.
// universe is the union of RID suffixes used by any of the ten detectors
// that share this package's privgroups SID-suffix resolver (28 suffixes),
// plus two witnesses used by NONE of them: -520 (Group Policy Creator
// Owners) and -547 (Power Users), both confirmed against
// internal/audit/wellknown_sids.go.
func TestComputerStaleWithAdminGroups_ExactGroupSet(t *testing.T) {
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
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)

	for _, suffix := range inSet {
		suffix := suffix
		t.Run("in_set"+suffix, func(t *testing.T) {
			dn := "CN=Group" + suffix + ",CN=Users,DC=example,DC=com"
			sid := "S-1-5-21-9999999999-8888888888-7777777777" + suffix
			c := types.Computer{
				SAMAccountName:     "PC" + suffix + "$",
				MemberOf:           []string{dn},
				LastLogonTimestamp: now.AddDate(0, 0, -120),
			}
			data := &audit.DetectorData{
				Now:         now,
				Computers:   []types.Computer{c},
				ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
			}
			f := NewComputerStaleWithAdminGroupsDetector().Detect(context.Background(), data)[0]
			if f.Count != 1 {
				t.Fatalf("suffix %s is in staleAdminGroupSIDSuffixes; stale computer membership must be flagged, got Count=%d, want 1", suffix, f.Count)
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
			c := types.Computer{
				SAMAccountName:     "PC" + suffix + "$",
				MemberOf:           []string{dn},
				LastLogonTimestamp: now.AddDate(0, 0, -120),
			}
			data := &audit.DetectorData{
				Now:         now,
				Computers:   []types.Computer{c},
				ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
			}
			f := NewComputerStaleWithAdminGroupsDetector().Detect(context.Background(), data)[0]
			if f.Count != 0 {
				t.Fatalf("suffix %s is NOT in staleAdminGroupSIDSuffixes; membership alone must not be flagged, got Count=%d, want 0", suffix, f.Count)
			}
		})
	}
}

// TestComputerStaleWithAdminGroups_NotStaleNotFlagged pins existing
// behavior: a recent logon must not be flagged even with real admin
// membership.
func TestComputerStaleWithAdminGroups_NotStaleNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	dn := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-551"
	c := types.Computer{
		SAMAccountName:     "RECENT-PC$",
		MemberOf:           []string{dn},
		LastLogonTimestamp: now.AddDate(0, 0, -10),
	}
	data := &audit.DetectorData{
		Now:         now,
		Computers:   []types.Computer{c},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewComputerStaleWithAdminGroupsDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (recent logon must not be flagged)", f.Count)
	}
}

// TestComputerStaleWithAdminGroups_DisabledNotFlagged is the Disabled guard:
// a stale computer directly in the real Domain Admins group (S-1-5-21-...-512)
// must not be flagged while Disabled is true.
func TestComputerStaleWithAdminGroups_DisabledNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-512"
	c := types.Computer{
		SAMAccountName:     "DISABLED-ADMIN-PC$",
		MemberOf:           []string{dn},
		Disabled:           true,
		LastLogonTimestamp: now.AddDate(0, 0, -120),
	}
	data := &audit.DetectorData{
		Now:         now,
		Computers:   []types.Computer{c},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewComputerStaleWithAdminGroupsDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (Disabled stale admin-group computer must not be flagged)", f.Count)
	}
}

// TestComputerStaleWithAdminGroups_ServerTrustAccountNotFlagged is the
// SERVER_TRUST_ACCOUNT (0x2000) guard: a stale computer directly in the real
// Domain Admins group must not be flagged while bit 0x2000 is set.
func TestComputerStaleWithAdminGroups_ServerTrustAccountNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-512"
	c := types.Computer{
		SAMAccountName:     "DC-ADMIN-PC$",
		MemberOf:           []string{dn},
		UserAccountControl: 0x2000,
		LastLogonTimestamp: now.AddDate(0, 0, -120),
	}
	data := &audit.DetectorData{
		Now:         now,
		Computers:   []types.Computer{c},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewComputerStaleWithAdminGroupsDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (SERVER_TRUST_ACCOUNT stale admin-group computer must not be flagged)", f.Count)
	}
}

// TestComputerStaleWithAdminGroups_NoTimestampNotFlagged is the double-zero
// case: a computer directly in the real Domain Admins group with neither
// LastLogonTimestamp nor LastLogon set must not be flagged.
func TestComputerStaleWithAdminGroups_NoTimestampNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-512"
	c := types.Computer{
		SAMAccountName: "NEVER-LOGGED-ON-ADMIN-PC$",
		MemberOf:       []string{dn},
	}
	data := &audit.DetectorData{
		Now:         now,
		Computers:   []types.Computer{c},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewComputerStaleWithAdminGroupsDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (no LastLogonTimestamp and no LastLogon must not be flagged)", f.Count)
	}
}

// TestComputerStaleWithAdminGroups_LastLogonFallbackFlagged is the fallback
// case: LastLogonTimestamp is zero but LastLogon alone is stale (-120 days)
// on a real Domain Admins member, so the fallback must still flag it.
func TestComputerStaleWithAdminGroups_LastLogonFallbackFlagged(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-512"
	c := types.Computer{
		SAMAccountName: "FALLBACK-ADMIN-PC$",
		MemberOf:       []string{dn},
		LastLogon:      now.AddDate(0, 0, -120),
	}
	data := &audit.DetectorData{
		Now:         now,
		Computers:   []types.Computer{c},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewComputerStaleWithAdminGroupsDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (LastLogon fallback on a stale real admin-group computer must be flagged)", f.Count)
	}
}

// TestComputerStaleWithAdminGroups_NinetyOneDaysFlagged pins the boundary
// just past the 90-day threshold: LastLogonTimestamp = now-91d on a real
// Domain Admins member must be flagged.
func TestComputerStaleWithAdminGroups_NinetyOneDaysFlagged(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-512"
	c := types.Computer{
		SAMAccountName:     "NINETY-ONE-DAYS-ADMIN-PC$",
		MemberOf:           []string{dn},
		LastLogonTimestamp: now.AddDate(0, 0, -91),
	}
	data := &audit.DetectorData{
		Now:         now,
		Computers:   []types.Computer{c},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewComputerStaleWithAdminGroupsDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (91 days inactive on a real admin-group computer must be flagged)", f.Count)
	}
}

// TestComputerStaleWithAdminGroups_EightyNineDaysNotFlagged pins the
// boundary just short of the 90-day threshold: LastLogonTimestamp = now-89d
// on a real Domain Admins member must not be flagged.
func TestComputerStaleWithAdminGroups_EightyNineDaysNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	dn := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1111111111-2222222222-3333333333-512"
	c := types.Computer{
		SAMAccountName:     "EIGHTY-NINE-DAYS-ADMIN-PC$",
		MemberOf:           []string{dn},
		LastLogonTimestamp: now.AddDate(0, 0, -89),
	}
	data := &audit.DetectorData{
		Now:         now,
		Computers:   []types.Computer{c},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewComputerStaleWithAdminGroupsDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (89 days inactive is within the 90-day threshold, must not be flagged)", f.Count)
	}
}
