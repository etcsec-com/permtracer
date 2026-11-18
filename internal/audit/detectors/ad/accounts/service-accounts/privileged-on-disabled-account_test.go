package serviceaccounts

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

const privilegedOnDisabledGroupDN = "CN=Domain Admins,CN=Users,DC=contoso,DC=com"

// TestPrivilegedOnDisabledAccount_DisabledMemberFlagged is the baseline
// positive: a disabled service account that is a direct member of a
// privileged group (resolved by well-known RID suffix) must be counted
// here.
func TestPrivilegedOnDisabledAccount_DisabledMemberFlagged(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Groups: []types.Group{
			{DN: privilegedOnDisabledGroupDN, SAMAccountName: "Domain Admins", ObjectSID: "S-1-5-21-1-2-3-512"},
		},
		Users: []types.User{
			{
				SAMAccountName:        "svc-backup",
				ServicePrincipalNames: []string{"HOST/svc-backup"},
				Disabled:              true,
				MemberOf:              []string{privilegedOnDisabledGroupDN},
			},
		},
	}

	f := NewPrivilegedOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled service account in a privileged group)", f.Count)
	}
	if f.Type != "SERVICE_ACCOUNT_PRIVILEGED_ON_DISABLED_ACCOUNT" {
		t.Fatalf("Type = %q, want SERVICE_ACCOUNT_PRIVILEGED_ON_DISABLED_ACCOUNT", f.Type)
	}
	if f.Severity != types.SeverityMedium {
		t.Fatalf("Severity = %q, want Medium", f.Severity)
	}
}

// TestPrivilegedOnDisabledAccount_ActiveMemberNotFlagged is the partition
// guard: the same privileged-group membership must be split strictly
// between the two detectors by account state - an enabled account belongs
// to PrivilegedDetector only, never to this twin.
func TestPrivilegedOnDisabledAccount_ActiveMemberNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{DN: privilegedOnDisabledGroupDN, SAMAccountName: "Domain Admins", ObjectSID: "S-1-5-21-1-2-3-512"},
		},
		Users: []types.User{
			{
				SAMAccountName:        "svc-backup",
				ServicePrincipalNames: []string{"HOST/svc-backup"},
				Disabled:              false,
				MemberOf:              []string{privilegedOnDisabledGroupDN},
			},
		},
	}

	twin := NewPrivilegedOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if twin.Count != 0 {
		t.Fatalf("twin Count = %d, want 0 (active account must not be counted by the disabled-account twin)", twin.Count)
	}

	active := NewPrivilegedDetector().Detect(context.Background(), data)[0]
	if active.Count != 1 {
		t.Fatalf("active Count = %d, want 1 (active account belongs to PrivilegedDetector)", active.Count)
	}
}

// TestPrivilegedOnDisabledAccount_DisabledExcludedFromActive is the
// partition guard from the active detector's side: a disabled service
// account in a privileged group must not be counted by PrivilegedDetector
// - only by this twin.
func TestPrivilegedOnDisabledAccount_DisabledExcludedFromActive(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{DN: privilegedOnDisabledGroupDN, SAMAccountName: "Domain Admins", ObjectSID: "S-1-5-21-1-2-3-512"},
		},
		Users: []types.User{
			{
				SAMAccountName:        "svc-backup",
				ServicePrincipalNames: []string{"HOST/svc-backup"},
				Disabled:              true,
				MemberOf:              []string{privilegedOnDisabledGroupDN},
			},
		},
	}

	active := NewPrivilegedDetector().Detect(context.Background(), data)[0]
	if active.Count != 0 {
		t.Fatalf("active Count = %d, want 0 (disabled account must not be counted by PrivilegedDetector)", active.Count)
	}

	twin := NewPrivilegedOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if twin.Count != 1 {
		t.Fatalf("twin Count = %d, want 1 (disabled account belongs to the twin)", twin.Count)
	}
}

// TestPrivilegedOnDisabledAccount_NonServiceAccountNotFlagged pins the
// isServiceAccount exclusion through to the twin: a disabled ordinary user
// in the same privileged group is not a service account and must not be
// counted.
func TestPrivilegedOnDisabledAccount_NonServiceAccountNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{DN: privilegedOnDisabledGroupDN, SAMAccountName: "Domain Admins", ObjectSID: "S-1-5-21-1-2-3-512"},
		},
		Users: []types.User{
			{SAMAccountName: "jdupont", Disabled: true, MemberOf: []string{privilegedOnDisabledGroupDN}},
		},
	}

	f := NewPrivilegedOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (ordinary disabled user is not a service account)", f.Count)
	}
}

// TestPrivilegedOnDisabledAccount_NonPrivilegedGroupNotFlagged guards
// against over-matching: a disabled service account in an ordinary group
// must not fire.
func TestPrivilegedOnDisabledAccount_NonPrivilegedGroupNotFlagged(t *testing.T) {
	dn := "CN=Backup Job Runners,CN=Users,DC=contoso,DC=com"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{DN: dn, SAMAccountName: "Backup Job Runners", ObjectSID: "S-1-5-21-1-2-3-1500"},
		},
		Users: []types.User{
			{SAMAccountName: "svc-backup", ServicePrincipalNames: []string{"HOST/svc-backup"}, Disabled: true, MemberOf: []string{dn}},
		},
	}

	f := NewPrivilegedOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0: an ordinary group is not privileged", f.Count)
	}
}

// TestPrivilegedOnDisabledAccount_MultiplePrivilegedGroupsCountedOnce
// mirrors the active-side guard: a disabled service account that is a
// direct member of TWO privileged groups must still be counted once, not
// once per matching group.
func TestPrivilegedOnDisabledAccount_MultiplePrivilegedGroupsCountedOnce(t *testing.T) {
	dn1 := "CN=Domain Admins,CN=Users,DC=contoso,DC=com"
	dn2 := "CN=Account Operators,CN=Builtin,DC=contoso,DC=com"
	data := &audit.DetectorData{
		IncludeDetails: true,
		Groups: []types.Group{
			{DN: dn1, SAMAccountName: "Domain Admins", ObjectSID: "S-1-5-21-1-2-3-512"},
			{DN: dn2, SAMAccountName: "Account Operators", ObjectSID: "S-1-5-21-1-2-3-548"},
		},
		Users: []types.User{
			{SAMAccountName: "svc-backup", ServicePrincipalNames: []string{"HOST/svc-backup"}, Disabled: true, MemberOf: []string{dn1, dn2}},
		},
	}

	f := NewPrivilegedOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1: membership in two privileged groups must be counted once", f.Count)
	}
	if len(f.AffectedEntities) != 1 {
		t.Fatalf("AffectedEntities = %+v, want exactly one entity", f.AffectedEntities)
	}
}
