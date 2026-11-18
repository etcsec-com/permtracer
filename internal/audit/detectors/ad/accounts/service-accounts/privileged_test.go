package serviceaccounts

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

const privilegedGroupDN = "CN=Admins du domaine,CN=Users,DC=contoso,DC=com"

// TestPrivileged_LocalizedGroupNameFlagged covers the well-known-SID fix:
// the old code matched "CN=Domain Admins" as an English literal substring,
// so a domain with a localized or renamed Domain Admins group (still SID
// ...-512) was never detected. Resolving via the group's ObjectSID fixes
// this regardless of display name/locale.
func TestPrivileged_LocalizedGroupNameFlagged(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Groups: []types.Group{
			{DN: privilegedGroupDN, SAMAccountName: "Admins du domaine", ObjectSID: "S-1-5-21-1-2-3-512"},
		},
		Users: []types.User{
			{
				SAMAccountName:        "svc-backup",
				ServicePrincipalNames: []string{"HOST/svc-backup"},
				MemberOf:              []string{privilegedGroupDN},
			},
		},
	}

	findings := NewPrivilegedDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: localized Domain Admins (SID ...-512) must still be caught", findings[0].Count)
	}
}

// TestPrivileged_NonPrivilegedGroupNotFlagged guards against over-matching:
// a service account in an ordinary group must not fire.
func TestPrivileged_NonPrivilegedGroupNotFlagged(t *testing.T) {
	dn := "CN=Backup Job Runners,CN=Users,DC=contoso,DC=com"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{DN: dn, SAMAccountName: "Backup Job Runners", ObjectSID: "S-1-5-21-1-2-3-1500"},
		},
		Users: []types.User{
			{SAMAccountName: "svc-backup", ServicePrincipalNames: []string{"HOST/svc-backup"}, MemberOf: []string{dn}},
		},
	}

	findings := NewPrivilegedDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: an ordinary group is not privileged", findings[0].Count)
	}
}

// TestPrivileged_NonServiceAccountNotFlagged is the isServiceAccount guard
// on the active side: an active ordinary user, with no SPN and a name
// outside the naming patterns, must not be counted even as a direct member
// of a privileged group - only the witness service account in the same
// group belongs in the finding.
func TestPrivileged_NonServiceAccountNotFlagged(t *testing.T) {
	dn := "CN=Account Operators,CN=Builtin,DC=contoso,DC=com"
	data := &audit.DetectorData{
		IncludeDetails: true,
		Groups: []types.Group{
			{DN: dn, SAMAccountName: "Account Operators", ObjectSID: "S-1-5-21-1-2-3-548"},
		},
		Users: []types.User{
			{SAMAccountName: "jdupont", MemberOf: []string{dn}},
			{SAMAccountName: "svc-backup", ServicePrincipalNames: []string{"HOST/svc-backup"}, MemberOf: []string{dn}},
		},
	}

	f := NewPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1: the ordinary active user must not be counted", f.Count)
	}
	if len(f.AffectedEntities) != 1 || f.AffectedEntities[0].SAMAccountName != "svc-backup" {
		t.Fatalf("AffectedEntities = %+v, want only svc-backup", f.AffectedEntities)
	}
}

// TestPrivileged_MultiplePrivilegedGroupsCountedOnce guards against the
// break after the first privileged group being removed: a service account
// that is a direct member of TWO privileged groups must still be counted
// once, not once per matching group.
func TestPrivileged_MultiplePrivilegedGroupsCountedOnce(t *testing.T) {
	dn1 := "CN=Domain Admins,CN=Users,DC=contoso,DC=com"
	dn2 := "CN=Account Operators,CN=Builtin,DC=contoso,DC=com"
	data := &audit.DetectorData{
		IncludeDetails: true,
		Groups: []types.Group{
			{DN: dn1, SAMAccountName: "Domain Admins", ObjectSID: "S-1-5-21-1-2-3-512"},
			{DN: dn2, SAMAccountName: "Account Operators", ObjectSID: "S-1-5-21-1-2-3-548"},
		},
		Users: []types.User{
			{SAMAccountName: "svc-backup", ServicePrincipalNames: []string{"HOST/svc-backup"}, MemberOf: []string{dn1, dn2}},
		},
	}

	f := NewPrivilegedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1: membership in two privileged groups must be counted once", f.Count)
	}
	if len(f.AffectedEntities) != 1 {
		t.Fatalf("AffectedEntities = %+v, want exactly one entity", f.AffectedEntities)
	}
}
