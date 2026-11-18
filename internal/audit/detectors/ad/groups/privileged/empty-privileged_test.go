package privileged

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

const emptyPrivilegedTestDomainSID = "S-1-5-21-7777777777-8888888888-9999999999"

// TestEmptyPrivileged_LocalizedProtectedGroupCounted proves the SID fix: a
// localized forest's empty Domain Admins (French name, real RID -512) is
// recognized and counted. Main's strings.EqualFold(name, pg) never matches
// a non-English name, and its strings.Contains(group.DistinguishedName,
// ...) half reads a field the real LDAP parser never populates - so main
// misses this empty privileged group entirely.
func TestEmptyPrivileged_LocalizedProtectedGroupCounted(t *testing.T) {
	groupSID := emptyPrivilegedTestDomainSID + "-512"
	groupDN := "CN=Admins du domaine,CN=Users,DC=corp,DC=local"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{
				DN:             groupDN,
				SAMAccountName: "Admins du domaine",
				Member:         nil,
			},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewEmptyPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (localized Domain Admins CN, real RID -512, empty - main's English name/DistinguishedName match never finds this group)", f.Count)
	}
}

// TestEmptyPrivileged_EnglishHomonymDifferentSIDNotCounted proves the
// homonym fix: a group named exactly "Domain Admins" in English but
// carrying a different, non-512 RID is not the real Domain Admins group.
// Main's strings.EqualFold(name, "Domain Admins") matches it by name alone
// and counts it, even though its SID shows it is not the real privileged
// group.
func TestEmptyPrivileged_EnglishHomonymDifferentSIDNotCounted(t *testing.T) {
	homonymSID := emptyPrivilegedTestDomainSID + "-3003"
	homonymDN := "CN=Domain Admins,OU=Decommissioned,DC=corp,DC=local"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{
				DN:             homonymDN,
				SAMAccountName: "Domain Admins",
				Member:         nil,
			},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			homonymSID: {DN: homonymDN, SID: homonymSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewEmptyPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (homonym group's SID does not end in -512 - not the real Domain Admins, main's name match false-positives here)", f.Count)
	}
}

// TestEmptyPrivileged_DnsAdminsStillMatchedByName is a regression guard:
// DnsAdmins has no fixed well-known RID, so it must still be recognized by
// exact name after the SID refactor.
func TestEmptyPrivileged_DnsAdminsStillMatchedByName(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{
				DN:             "CN=DnsAdmins,CN=Users,DC=corp,DC=local",
				SAMAccountName: "DnsAdmins",
				Member:         nil,
			},
		},
	}

	f := NewEmptyPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (DnsAdmins has no well-known RID and must stay matched by exact name)", f.Count)
	}
}

// TestEmptyPrivileged_EmptyGroupPopulatesDetailsAndEntities proves the
// len(affected) > 0 gate's true side: with one empty privileged group and
// IncludeDetails=true, Details["groups"] must list its name and
// AffectedEntities must be populated.
func TestEmptyPrivileged_EmptyGroupPopulatesDetailsAndEntities(t *testing.T) {
	groupSID := emptyPrivilegedTestDomainSID + "-512"
	groupDN := "CN=Domain Admins,CN=Users,DC=corp,DC=local"
	data := &audit.DetectorData{
		IncludeDetails: true,
		Groups: []types.Group{
			{DN: groupDN, SAMAccountName: "Domain Admins", Member: nil},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewEmptyPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1", f.Count)
	}
	if len(f.AffectedEntities) != 1 {
		t.Fatalf("AffectedEntities = %v, want 1 entity (one empty privileged group, IncludeDetails=true)", f.AffectedEntities)
	}
	groups, ok := f.Details["groups"].([]string)
	if !ok || len(groups) != 1 || groups[0] != "Domain Admins" {
		t.Fatalf("Details[\"groups\"] = %v, want [\"Domain Admins\"]", f.Details["groups"])
	}
}

// TestEmptyPrivileged_NoEmptyGroupDetailsNil proves the len(affected) > 0
// gate's false side: with a privileged group that is NOT empty (so no
// privileged group qualifies as affected), Details must stay nil - not a map
// with an empty "groups" list.
func TestEmptyPrivileged_NoEmptyGroupDetailsNil(t *testing.T) {
	groupSID := emptyPrivilegedTestDomainSID + "-512"
	groupDN := "CN=Domain Admins,CN=Users,DC=corp,DC=local"
	data := &audit.DetectorData{
		IncludeDetails: true,
		Groups: []types.Group{
			{DN: groupDN, SAMAccountName: "Domain Admins", Member: []string{"CN=Alice,CN=Users,DC=corp,DC=local"}},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewEmptyPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (the only privileged group has a member)", f.Count)
	}
	if f.Details != nil {
		t.Fatalf("Details = %v, want nil (no empty privileged group)", f.Details)
	}
	if f.AffectedEntities != nil {
		t.Fatalf("AffectedEntities = %v, want nil (no empty privileged group)", f.AffectedEntities)
	}
}

// TestEmptyPrivileged_TypeAndSeverity locks the finding's identifying
// fields.
func TestEmptyPrivileged_TypeAndSeverity(t *testing.T) {
	data := &audit.DetectorData{}
	f := NewEmptyPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Type != "GROUP_EMPTY_PRIVILEGED" {
		t.Fatalf("Type = %q, want %q", f.Type, "GROUP_EMPTY_PRIVILEGED")
	}
	if f.Severity != types.SeverityInfo {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityInfo)
	}
}

// TestEmptyPrivileged_PrintOperatorsEmptyCounted proves the "-550" (Print
// Operators) RID suffix is still matched: removing it from
// emptyPrivilegedSIDSuffixes would leave this group unrecognized by both the
// SID path (suffix gone) and the name path (only DnsAdmins is matched by
// name), so Count would drop to 0.
func TestEmptyPrivileged_PrintOperatorsEmptyCounted(t *testing.T) {
	groupSID := emptyPrivilegedTestDomainSID + "-550"
	groupDN := "CN=Print Operators,CN=Builtin,DC=corp,DC=local"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{
				DN:             groupDN,
				SAMAccountName: "Print Operators",
				Member:         nil,
			},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewEmptyPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (empty Print Operators, RID -550, must be matched)", f.Count)
	}
}

// TestEmptyPrivileged_DnsAdminsCaseInsensitive proves the DnsAdmins name
// match is case-insensitive: strings.EqualFold(name, "DnsAdmins") matches a
// differently-cased SAMAccountName. Replacing EqualFold with a strict ==
// would miss this group entirely (Count 0 instead of 1).
func TestEmptyPrivileged_DnsAdminsCaseInsensitive(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{
				DN:             "CN=dnsadmins,CN=Users,DC=corp,DC=local",
				SAMAccountName: "dnsadmins",
				Member:         nil,
			},
		},
	}

	f := NewEmptyPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (DnsAdmins matched case-insensitively against lowercase sAMAccountName)", f.Count)
	}
}

// TestEmptyPrivileged_DisplayNameFallback proves the DisplayName fallback:
// when SAMAccountName is empty, Detect falls back to DisplayName before the
// name match. Removing that fallback leaves name == "", which never matches
// "DnsAdmins", dropping Count to 0.
func TestEmptyPrivileged_DisplayNameFallback(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{
				DN:             "CN=DnsAdmins,CN=Users,DC=corp,DC=local",
				SAMAccountName: "",
				DisplayName:    "DnsAdmins",
				Member:         nil,
			},
		},
	}

	f := NewEmptyPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (empty SAMAccountName must fall back to DisplayName \"DnsAdmins\")", f.Count)
	}
}

// TestEmptyPrivileged_OneMemberNotCounted proves the emptiness check is
// strictly len(group.Member) == 0: a privileged group (RID -548, Account
// Operators) with exactly one member must NOT be counted. Relaxing the
// check to <= 1 would count it (Count 1 instead of 0).
func TestEmptyPrivileged_OneMemberNotCounted(t *testing.T) {
	groupSID := emptyPrivilegedTestDomainSID + "-548"
	groupDN := "CN=Account Operators,CN=Builtin,DC=corp,DC=local"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{
				DN:             groupDN,
				SAMAccountName: "Account Operators",
				Member:         []string{"CN=Someone,CN=Users,DC=corp,DC=local"},
			},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewEmptyPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (Account Operators has one member, not empty)", f.Count)
	}
}

// TestEmptyPrivileged_NonEmptyPrivilegedNotCounted proves Count reflects the
// number of EMPTY privileged groups, not the number of privileged groups
// found. With one non-empty privileged group (Domain Admins, RID -512) next
// to one empty privileged group (Enterprise Admins, RID -519), Count must be
// 1. Setting Count to the number of matched privileged groups instead of
// len(affected) would make it 2.
func TestEmptyPrivileged_NonEmptyPrivilegedNotCounted(t *testing.T) {
	nonEmptySID := emptyPrivilegedTestDomainSID + "-512"
	nonEmptyDN := "CN=Domain Admins,CN=Users,DC=corp,DC=local"
	emptySID := emptyPrivilegedTestDomainSID + "-519"
	emptyDN := "CN=Enterprise Admins,CN=Users,DC=corp,DC=local"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{
				DN:             nonEmptyDN,
				SAMAccountName: "Domain Admins",
				Member:         []string{"CN=Alice,CN=Users,DC=corp,DC=local"},
			},
			{
				DN:             emptyDN,
				SAMAccountName: "Enterprise Admins",
				Member:         nil,
			},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			nonEmptySID: {DN: nonEmptyDN, SID: nonEmptySID, EntityType: types.EntityTypeGroup},
			emptySID:    {DN: emptyDN, SID: emptySID, EntityType: types.EntityTypeGroup},
		},
	}

	f := NewEmptyPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (only the empty privileged group counted, not both privileged groups found)", f.Count)
	}
}
