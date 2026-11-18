package advanced

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestDangerousBuiltinMembershipOnDisabledAccount_DisabledMembershipFlagged
// is the baseline positive: a disabled account directly in one of the 15
// dangerous built-in groups must be counted here.
func TestDangerousBuiltinMembershipOnDisabledAccount_DisabledMembershipFlagged(t *testing.T) {
	dn := "CN=Hyper-V Administrators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-578"
	u := types.User{SAMAccountName: "hv-member", Disabled: true, MemberOf: []string{dn}}
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users:          []types.User{u},
		ObjectBySID:    map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewDangerousBuiltinMembershipOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled Hyper-V Administrators membership)", f.Count)
	}
	if f.Type != "DANGEROUS_BUILTIN_MEMBERSHIP_ON_DISABLED_ACCOUNT" {
		t.Fatalf("Type = %q, want DANGEROUS_BUILTIN_MEMBERSHIP_ON_DISABLED_ACCOUNT", f.Type)
	}
	if f.Severity != types.SeverityLow {
		t.Fatalf("Severity = %q, want Low", f.Severity)
	}
}

// TestDangerousBuiltinMembershipOnDisabledAccount_ActiveMembershipNotFlagged
// is the partition guard: the same membership must be split strictly
// between the two detectors by account state - an enabled account belongs
// to DangerousBuiltinMembershipDetector only, never to this twin.
func TestDangerousBuiltinMembershipOnDisabledAccount_ActiveMembershipNotFlagged(t *testing.T) {
	dn := "CN=Hyper-V Administrators,CN=Builtin,DC=example,DC=com"
	sid := "S-1-5-32-578"
	u := types.User{SAMAccountName: "hv-member", Disabled: false, MemberOf: []string{dn}}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	twin := NewDangerousBuiltinMembershipOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if twin.Count != 0 {
		t.Fatalf("twin Count = %d, want 0 (active account must not be counted by the disabled-account twin)", twin.Count)
	}

	active := NewDangerousBuiltinMembershipDetector().Detect(context.Background(), data)[0]
	if active.Count != 1 {
		t.Fatalf("active Count = %d, want 1 (active account belongs to DangerousBuiltinMembershipDetector)", active.Count)
	}
}

// TestDangerousBuiltinMembershipOnDisabledAccount_NoMembershipNotFlagged
// guards against over-matching: a disabled account with no group
// membership must not fire.
func TestDangerousBuiltinMembershipOnDisabledAccount_NoMembershipNotFlagged(t *testing.T) {
	u := types.User{SAMAccountName: "disabled-no-groups", Disabled: true}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewDangerousBuiltinMembershipOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (no group membership at all)", f.Count)
	}
}

// TestDangerousBuiltinMembershipOnDisabledAccount_OrdinaryGroupNotFlagged
// guards against over-matching: a disabled account in an ordinary group
// must not fire.
func TestDangerousBuiltinMembershipOnDisabledAccount_OrdinaryGroupNotFlagged(t *testing.T) {
	dn := "CN=Backup Job Runners,CN=Users,DC=example,DC=com"
	sid := "S-1-5-21-1-2-3-1500"
	u := types.User{SAMAccountName: "disabled-ordinary", Disabled: true, MemberOf: []string{dn}}
	data := &audit.DetectorData{
		Users:       []types.User{u},
		ObjectBySID: map[string]*audit.ObjectMeta{sid: {DN: dn, SID: sid, EntityType: types.EntityTypeGroup}},
	}

	f := NewDangerousBuiltinMembershipOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (an ordinary group is not dangerous)", f.Count)
	}
}

// TestDangerousBuiltinMembershipOnDisabledAccount_DetailsNamesDeriveFromSingleTable
// pins Details["dangerousGroups"] through to the twin, derived from the
// SAME table as the active detector.
func TestDangerousBuiltinMembershipOnDisabledAccount_DetailsNamesDeriveFromSingleTable(t *testing.T) {
	want := dangerousBuiltinGroupNames()

	u := types.User{SAMAccountName: "disabled-no-groups", Disabled: true}
	data := &audit.DetectorData{IncludeDetails: true, Users: []types.User{u}}

	f := NewDangerousBuiltinMembershipOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	got, ok := f.Details["dangerousGroups"].([]string)
	if !ok {
		t.Fatalf("Details[\"dangerousGroups\"] type = %T, want []string", f.Details["dangerousGroups"])
	}
	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
