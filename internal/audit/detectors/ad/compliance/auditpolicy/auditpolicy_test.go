package auditpolicy

import (
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
)

func TestLevel(t *testing.T) {
	legacyCalled := func(v int) func(*audit.EventAudit) int {
		return func(e *audit.EventAudit) int { return v }
	}

	t.Run("subcategory value wins when present, even with ea also set", func(t *testing.T) {
		adv := map[string]int{"guid-a": 3}
		ea := &audit.EventAudit{}
		v, ok := Level(adv, "guid-a", ea, legacyCalled(0))
		if !ok || v != 3 {
			t.Fatalf("got (%d, %v), want (3, true)", v, ok)
		}
	})

	t.Run("falls back to legacy when subcategory absent but ea present", func(t *testing.T) {
		adv := map[string]int{"guid-other": 3}
		ea := &audit.EventAudit{}
		v, ok := Level(adv, "guid-a", ea, legacyCalled(1))
		if !ok || v != 1 {
			t.Fatalf("got (%d, %v), want (1, true)", v, ok)
		}
	})

	t.Run("no evidence at all: not ok, legacy not invoked", func(t *testing.T) {
		called := false
		legacy := func(e *audit.EventAudit) int { called = true; return 0 }
		_, ok := Level(nil, "guid-a", nil, legacy)
		if ok {
			t.Fatal("expected ok=false when neither audit.csv nor [Event Audit] has data")
		}
		if called {
			t.Fatal("legacy getter must not be invoked when ea is nil - it would panic on a real field access")
		}
	})

	t.Run("empty adv map behaves like nil", func(t *testing.T) {
		ea := &audit.EventAudit{}
		v, ok := Level(map[string]int{}, "guid-a", ea, legacyCalled(2))
		if !ok || v != 2 {
			t.Fatalf("got (%d, %v), want (2, true)", v, ok)
		}
	})
}

func TestGetAdvancedAudit(t *testing.T) {
	t.Run("prefers DC policy over domain policy and any other GPO", func(t *testing.T) {
		policies := map[string]*audit.GPOPolicy{
			"{other}":               {AdvancedAudit: map[string]int{"x": 9}},
			defaultDomainPolicyGUID: {AdvancedAudit: map[string]int{"x": 1}},
			defaultDCPolicyGUID:     {AdvancedAudit: map[string]int{"x": 2}},
		}
		got := GetAdvancedAudit(policies)
		if got["x"] != 2 {
			t.Fatalf("got %v, want DC policy's map (x=2)", got)
		}
	})

	t.Run("falls back to domain policy when DC policy has none", func(t *testing.T) {
		policies := map[string]*audit.GPOPolicy{
			defaultDomainPolicyGUID: {AdvancedAudit: map[string]int{"x": 1}},
		}
		got := GetAdvancedAudit(policies)
		if got["x"] != 1 {
			t.Fatalf("got %v, want domain policy's map (x=1)", got)
		}
	})

	t.Run("falls back to any GPO when neither default policy has one", func(t *testing.T) {
		policies := map[string]*audit.GPOPolicy{
			"{some-other-gpo}": {AdvancedAudit: map[string]int{"x": 5}},
		}
		got := GetAdvancedAudit(policies)
		if got["x"] != 5 {
			t.Fatalf("got %v, want the only GPO's map (x=5)", got)
		}
	})

	t.Run("nil when no GPO has audit.csv data", func(t *testing.T) {
		policies := map[string]*audit.GPOPolicy{
			"{some-gpo}": {},
		}
		if got := GetAdvancedAudit(policies); got != nil {
			t.Fatalf("got %v, want nil", got)
		}
	})

	// MUTATION M1 target: auditpolicy.go:54 - removing the
	// `p == nil || p.AdvancedAudit == nil` guard makes the switch below
	// dereference p unconditionally once its GUID matches a default
	// policy key, so a nil GPO entry at that key must panic rather than be
	// skipped.
	t.Run("nil GPO entry at the DC policy key is skipped, not dereferenced", func(t *testing.T) {
		policies := map[string]*audit.GPOPolicy{
			defaultDCPolicyGUID:     nil,
			defaultDomainPolicyGUID: {AdvancedAudit: map[string]int{"catA": 7}},
		}
		got := GetAdvancedAudit(policies)
		if got["catA"] != 7 {
			t.Fatalf("got %v, want the domain policy's map (catA=7); a nil GPO entry at the DC key must be skipped, not dereferenced", got)
		}
	})

	// MUTATION M3 target: auditpolicy.go:71 - forcing the final fallback
	// loop's body to run unconditionally makes it dereference a nil GPO
	// pointer on its very first iteration. Every entry here is nil and
	// none is keyed as a default policy, so dc and domain both stay nil
	// and this fallback loop is reached no matter the map's iteration
	// order.
	t.Run("generic fallback never dereferences a nil GPO entry unconditionally", func(t *testing.T) {
		policies := map[string]*audit.GPOPolicy{
			"{11111111-0000-0000-0000-000000000001}": nil,
			"{22222222-0000-0000-0000-000000000002}": nil,
		}
		got := GetAdvancedAudit(policies)
		if got != nil {
			t.Fatalf("got %v, want nil: no GPO here has audit.csv data", got)
		}
	})

	// MUTATION M2 target: auditpolicy.go:67 - disabling the domain-policy
	// return makes GetAdvancedAudit fall through to the final "any GPO"
	// loop, where the Default Domain Policy's own entry then competes, on
	// equal footing, with a second GPO that also carries audit.csv data.
	// Map iteration order is randomized per call, so a single invocation
	// could land on the domain entry by accident even under the mutation;
	// repeating the call makes that accident vanishingly unlikely, while
	// correct code (which returns the domain policy before this loop is
	// ever reached) can never fail any iteration.
	t.Run("domain policy returns directly without consulting the generic fallback", func(t *testing.T) {
		policies := map[string]*audit.GPOPolicy{
			defaultDomainPolicyGUID:                  {AdvancedAudit: map[string]int{"catA": 1}},
			"{33333333-0000-0000-0000-000000000003}": {AdvancedAudit: map[string]int{"catB": 2}},
		}
		for i := 0; i < 50; i++ {
			got := GetAdvancedAudit(policies)
			if _, hasB := got["catB"]; hasB || got["catA"] != 1 {
				t.Fatalf("call %d: got %v, want the domain policy's own map (catA=1) every time, not whatever the generic fallback happens to iterate to first", i, got)
			}
		}
	})

	// Target: auditpolicy.go's generic fallback loop condition
	// `p != nil && p.AdvancedAudit != nil` - dropping the AdvancedAudit
	// subterm makes it return the first non-nil *GPOPolicy regardless of
	// whether it carries audit.csv data. Neither default policy key is
	// used, so dc and domain both stay nil and this loop is reached no
	// matter the map's iteration order. One GPO has no AdvancedAudit at
	// all; the other carries data. Correct code always finds the data
	// carrier; the mutation has only a 1-in-2 chance per call of doing
	// so by accident, so repeating the call defeats that chance.
	t.Run("generic fallback skips a GPO without audit.csv data", func(t *testing.T) {
		policies := map[string]*audit.GPOPolicy{
			"{aaaaaaaa-0000-0000-0000-00000000000a}": {},
			"{bbbbbbbb-0000-0000-0000-00000000000b}": {AdvancedAudit: map[string]int{"catC": 9}},
		}
		for i := 0; i < 50; i++ {
			got := GetAdvancedAudit(policies)
			if got["catC"] != 9 {
				t.Fatalf("call %d: got %v, want the single GPO carrying audit.csv data (catC=9) every time, not a nil map from the GPO without audit.csv", i, got)
			}
		}
	})
}

// Subcategory GUIDs are referenced by symbol everywhere else in this
// package's tests, so a wrong literal in the constant itself would pass
// unnoticed. These compare against the literal copied from Microsoft's
// Advanced Audit Policy Configuration reference, not the constant under test.
func TestSubcategoryGUIDsMatchMicrosoftReference(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"AuditPolicyChange", AuditPolicyChange, "{0cce922f-69ae-11d9-bed3-505054503030}"},
		{"UserAccountManagement", UserAccountManagement, "{0cce9235-69ae-11d9-bed3-505054503030}"},
		{"CredentialValidation", CredentialValidation, "{0cce923f-69ae-11d9-bed3-505054503030}"},
		{"Logon", Logon, "{0cce9215-69ae-11d9-bed3-505054503030}"},
		{"SecurityStateChange", SecurityStateChange, "{0cce9210-69ae-11d9-bed3-505054503030}"},
		{"DirectoryServiceAccess", DirectoryServiceAccess, "{0cce923b-69ae-11d9-bed3-505054503030}"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %q, want the Microsoft-documented subcategory GUID %q", c.name, c.got, c.want)
		}
	}
}

// Same reasoning as above, for the two well-known default GPO GUIDs.
func TestDefaultGPOGUIDsMatchWellKnownValues(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"defaultDomainPolicyGUID", defaultDomainPolicyGUID, "{31B2F340-016D-11D2-945F-00C04FB984F9}"},
		{"defaultDCPolicyGUID", defaultDCPolicyGUID, "{6AC1786C-016F-11D2-945F-00C04FB984F9}"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %q, want the well-known default GPO GUID %q", c.name, c.got, c.want)
		}
	}
}
