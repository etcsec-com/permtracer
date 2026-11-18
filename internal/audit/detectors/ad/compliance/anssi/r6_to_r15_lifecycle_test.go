package anssi

import (
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestUsersToEntities_PopulatesEnabled: usersToEntities built
// AffectedEntity literals without setting Enabled, so every entity defaulted
// to Go's zero value (false). response.go's annotateDisabledAccounts reads
// that same field to report how many affected accounts can't authenticate -
// with the field never set, a fully active/enabled user was published and
// scored as if it were disabled, for every detector routing through this
// helper (anssi-r6-inactive-accounts.go, anssi-r7-stale-accounts-not-
// removed.go, anssi-r8-service-accounts-as-users.go, anssi-r9-service-
// account-secret-rotation.go).
func TestUsersToEntities_PopulatesEnabled(t *testing.T) {
	active := types.User{DN: "CN=Active,DC=lab,DC=local", SAMAccountName: "active", Disabled: false}
	disabled := types.User{DN: "CN=Disabled,DC=lab,DC=local", SAMAccountName: "disabled", Disabled: true}

	entities := usersToEntities([]types.User{active, disabled}, true)
	if len(entities) != 2 {
		t.Fatalf("expected 2 entities, got %d", len(entities))
	}
	if !entities[0].Enabled {
		t.Errorf("active user: Enabled = false, want true (DN=%s)", entities[0].DN)
	}
	if entities[1].Enabled {
		t.Errorf("disabled user: Enabled = true, want false (DN=%s)", entities[1].DN)
	}
}

// TestComputersToEntities_PopulatesRealFields covers a bug where a prior
// hand-built AffectedEntity here only set Type/DN/SAMAccountName, leaving
// Enabled/PasswordLastSet/LastLogon/MemberOf at their Go zero values
// (false/nil/nil/nil) - indistinguishable in the published JSON from a real
// disabled, never-logged-on, group-less computer account. R19
// (ANSSI_R19_SERVER_CORE_NOT_USED) and R43 (ANSSI_R43_DC_PASSWORD_OLD) both
// call this helper; a zeroed Enabled also fed response.go's
// annotateDisabledAccounts and silently zeroed their compliance-score
// contribution for an active DC.
func TestComputersToEntities_PopulatesRealFields(t *testing.T) {
	pwdLastSet := time.Date(2026, 8, 10, 13, 39, 22, 0, time.UTC)
	lastLogon := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	comp := types.Computer{
		DN:              "CN=DC-01,OU=Domain Controllers,DC=lab,DC=local",
		SAMAccountName:  "DC-01$",
		OperatingSystem: "Windows Server 2022 Datacenter Evaluation",
		Disabled:        false, // active machine account
		MemberOf:        []string{"CN=Domain Controllers,CN=Users,DC=lab,DC=local"},
		PasswordLastSet: pwdLastSet,
		LastLogon:       lastLogon,
	}

	ents := computersToEntities([]types.Computer{comp}, true)
	if len(ents) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(ents))
	}
	got := ents[0]

	if !got.Enabled {
		t.Error("Enabled = false, want true - an active DC must not be published as disabled")
	}
	if got.PasswordLastSet == nil || *got.PasswordLastSet == "" {
		t.Error("PasswordLastSet not populated, want the real pwdLastSet timestamp")
	}
	if got.LastLogon == nil || *got.LastLogon == "" {
		t.Error("LastLogon not populated, want the real lastLogon timestamp")
	}
	if len(got.MemberOf) != 1 || got.MemberOf[0] != comp.MemberOf[0] {
		t.Errorf("MemberOf = %v, want %v", got.MemberOf, comp.MemberOf)
	}
}

// TestWrapFinding_EntitiesOnlyWhenCountPositive covers the AffectedEntities
// gate: entities must only be attached when both count > 0 and the entities
// slice is non-empty, never on count alone or entities alone.
func TestWrapFinding_EntitiesOnlyWhenCountPositive(t *testing.T) {
	d := NewR14RBCDAuditDetector()
	someEntities := []types.AffectedEntity{{Type: "computer", DN: "CN=Fixture,DC=lab,DC=local"}}

	t.Run("count zero with non-empty entities stays empty", func(t *testing.T) {
		got := wrapFinding(d, "title", "desc", types.SeverityLow, 0, someEntities)
		if len(got[0].AffectedEntities) != 0 {
			t.Errorf("AffectedEntities = %v, want empty (count=0)", got[0].AffectedEntities)
		}
	})

	t.Run("count positive with entities attaches them", func(t *testing.T) {
		got := wrapFinding(d, "title", "desc", types.SeverityLow, 1, someEntities)
		if len(got[0].AffectedEntities) != len(someEntities) {
			t.Errorf("AffectedEntities = %v, want %v", got[0].AffectedEntities, someEntities)
		}
	})

	t.Run("count positive with no entities stays empty", func(t *testing.T) {
		got := wrapFinding(d, "title", "desc", types.SeverityLow, 1, nil)
		if len(got[0].AffectedEntities) != 0 {
			t.Errorf("AffectedEntities = %v, want empty (no entities)", got[0].AffectedEntities)
		}
	})
}

// TestUsersToEntities_NilWithoutDetails covers the IncludeDetails gate:
// usersToEntities must return nil when details are suppressed and real
// entities when they are requested.
func TestUsersToEntities_NilWithoutDetails(t *testing.T) {
	users := []types.User{{DN: "CN=Fixture,DC=lab,DC=local", SAMAccountName: "fixture"}}

	if got := usersToEntities(users, false); got != nil {
		t.Errorf("includeDetails=false: got %v, want nil", got)
	}
	if got := usersToEntities(users, true); len(got) != len(users) {
		t.Errorf("includeDetails=true: got %d entities, want %d", len(got), len(users))
	}
}

// TestUsersToEntities_CappedAt100 covers the JSON-size cap: more than 100
// users must be truncated to exactly 100 entities.
func TestUsersToEntities_CappedAt100(t *testing.T) {
	users := make([]types.User, 150)
	for i := range users {
		users[i] = types.User{DN: "CN=Fixture", SAMAccountName: "fixture"}
	}

	got := usersToEntities(users, true)
	if len(got) != 100 {
		t.Errorf("got %d entities, want 100", len(got))
	}
}

// TestComputersToEntities_CappedAt100 covers both the IncludeDetails gate
// and the 100-entity cap for computersToEntities.
func TestComputersToEntities_CappedAt100(t *testing.T) {
	comps := make([]types.Computer, 150)
	for i := range comps {
		comps[i] = types.Computer{DN: "CN=Fixture", SAMAccountName: "fixture$"}
	}

	if got := computersToEntities(comps, false); got != nil {
		t.Errorf("includeDetails=false: got %v, want nil", got)
	}
	if got := computersToEntities(comps, true); len(got) != 100 {
		t.Errorf("includeDetails=true: got %d entities, want 100", len(got))
	}
}

// TestUsersToEntities_CappedAt100_Boundary101 is the exact boundary case:
// 101 users (not 150) must still truncate to exactly 100 entities. A cap
// mutated from 100 to 101 would pass TestUsersToEntities_CappedAt100 (150 is
// still > 101, so it still truncates to 100) without this narrower input.
func TestUsersToEntities_CappedAt100_Boundary101(t *testing.T) {
	users := make([]types.User, 101)
	for i := range users {
		users[i] = types.User{DN: "CN=Fixture", SAMAccountName: "fixture"}
	}

	got := usersToEntities(users, true)
	if len(got) != 100 {
		t.Errorf("got %d entities, want 100 (101 users is exactly one past the cap)", len(got))
	}
}

// TestComputersToEntities_CappedAt100_Boundary101 mirrors
// TestUsersToEntities_CappedAt100_Boundary101 for computersToEntities: 101
// computers must still truncate to exactly 100 entities.
func TestComputersToEntities_CappedAt100_Boundary101(t *testing.T) {
	comps := make([]types.Computer, 101)
	for i := range comps {
		comps[i] = types.Computer{DN: "CN=Fixture", SAMAccountName: "fixture$"}
	}

	got := computersToEntities(comps, true)
	if len(got) != 100 {
		t.Errorf("got %d entities, want 100 (101 computers is exactly one past the cap)", len(got))
	}
}

// TestIsWellKnownAdminTrustee covers acceptance §3: the "s-1-5-21-" substring
// excluded every domain principal - the exact population these checks target.
func TestIsWellKnownAdminTrustee(t *testing.T) {
	cases := []struct {
		trustee string
		want    bool
		why     string
	}{
		{sidHelpdesk, false, "ordinary domain group must NOT be treated as a built-in admin"},
		{"S-1-5-21-1234567890-1111111111-2222222222-1105", false, "ordinary domain user"},
		{sidDomainAdmins, true, "Domain Admins (-512)"},
		{"S-1-5-21-1234567890-1111111111-2222222222-519", true, "Enterprise Admins (-519)"},
		{"S-1-5-32-544", true, "BUILTIN\\Administrators"},
		{"S-1-5-18", true, "LOCAL SYSTEM"},
		{"S-1-5-10", true, "SELF"},
		{"S-1-3-0", true, "CREATOR OWNER"},
		{sidPreWin2000, false, "Pre-Windows 2000 Compatible Access is NOT an admin principal"},
		{"S-1-1-0", false, "Everyone"},
		{"DOMAIN\\Domain Admins", true, "friendly-name fallback still works"},
	}
	for _, tc := range cases {
		if got := isWellKnownAdminTrustee(tc.trustee); got != tc.want {
			t.Errorf("isWellKnownAdminTrustee(%q) = %v, want %v - %s", tc.trustee, got, tc.want, tc.why)
		}
	}
}
