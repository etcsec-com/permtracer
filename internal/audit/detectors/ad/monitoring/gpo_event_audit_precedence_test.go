package monitoring

import (
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
)

// MUTATION M4 target: helpers/gpo_policy.go:59 - disabling the Default
// Domain Policy's priority check makes GetEventAudit fall through to the
// DC-policy branch instead. Both lookups match by exact GUID key, so the
// expected winner is deterministic regardless of map iteration order.
func TestGetEventAudit_DomainPolicyPriorityOverDCPolicy(t *testing.T) {
	policies := map[string]*audit.GPOPolicy{
		helpers.DefaultDomainPolicyGUID: {EventAudit: &audit.EventAudit{AuditPolicyChange: 1}},
		helpers.DefaultDCPolicyGUID:     {EventAudit: &audit.EventAudit{AuditPolicyChange: 2}},
	}
	got := helpers.GetEventAudit(policies)
	if got == nil || got.AuditPolicyChange != 1 {
		t.Fatalf("got %+v, want the Default Domain Policy's EventAudit (AuditPolicyChange=1), not the DC policy's", got)
	}
}

// MUTATION M5 target: helpers/gpo_policy.go:63 - disabling the DC policy's
// priority check makes GetEventAudit fall through to the generic "any GPO"
// loop, where the DC policy's own entry then competes, on equal footing,
// with a second GPO that also carries [Event Audit] data. No Default
// Domain Policy entry is present, so lines 58-61 never short-circuit this
// path. Map iteration order is randomized per call, so a single invocation
// could land on the DC entry by accident even under the mutation;
// repeating the call makes that accident vanishingly unlikely, while
// correct code (which returns the DC policy before this loop is ever
// reached) can never fail any iteration.
func TestGetEventAudit_DCPolicyPriorityOverGenericFallback(t *testing.T) {
	policies := map[string]*audit.GPOPolicy{
		helpers.DefaultDCPolicyGUID:              {EventAudit: &audit.EventAudit{AuditPolicyChange: 3}},
		"{44444444-0000-0000-0000-000000000004}": {EventAudit: &audit.EventAudit{AuditPolicyChange: 4}},
	}
	for i := 0; i < 50; i++ {
		got := helpers.GetEventAudit(policies)
		if got == nil || got.AuditPolicyChange != 3 {
			t.Fatalf("call %d: got %+v, want the DC policy's own EventAudit (AuditPolicyChange=3) every time, not whatever the generic fallback happens to iterate to first", i, got)
		}
	}
}

// MUTATION M6 target: helpers/gpo_policy.go:67 - forcing the generic
// fallback loop's body to run unconditionally on its first iteration makes
// it return whichever GPO happens to come first, data or not. Neither
// default policy is present here, so only this loop is in play. One GPO
// carries [Event Audit] data and four others deliberately don't, so
// correct code always finds that single carrier regardless of order,
// while the mutation has only a 1-in-5 chance of doing so by accident on
// any one call; repeating the call defeats that chance.
func TestGetEventAudit_GenericFallbackSkipsGPOsWithoutEventAudit(t *testing.T) {
	policies := map[string]*audit.GPOPolicy{
		"{55555555-0000-0000-0000-000000000005}": {EventAudit: &audit.EventAudit{AuditPolicyChange: 9}},
		"{66666666-0000-0000-0000-000000000006}": {},
		"{77777777-0000-0000-0000-000000000007}": {},
		"{88888888-0000-0000-0000-000000000008}": {},
		"{99999999-0000-0000-0000-000000000009}": {},
	}
	for i := 0; i < 50; i++ {
		got := helpers.GetEventAudit(policies)
		if got == nil || got.AuditPolicyChange != 9 {
			t.Fatalf("call %d: got %+v, want the single GPO carrying [Event Audit] data (AuditPolicyChange=9) every time", i, got)
		}
	}
}

// Target: helpers/gpo_policy.go GetEventAudit's Default Domain Policy branch
// (`if ddp != nil && ddp.EventAudit != nil`) - dropping the EventAudit
// subterm makes it return nil as soon as the DDP exists, even without
// [Event Audit]. A DDP present WITHOUT [Event Audit] (a real-world shape
// seen in production domains) must fall through to the DC policy, not mask it.
func TestGetEventAudit_DomainPolicyWithoutDataFallsThroughToDCPolicy(t *testing.T) {
	policies := map[string]*audit.GPOPolicy{
		helpers.DefaultDomainPolicyGUID: {},
		helpers.DefaultDCPolicyGUID:     {EventAudit: &audit.EventAudit{AuditPolicyChange: 5}},
	}
	got := helpers.GetEventAudit(policies)
	if got == nil || got.AuditPolicyChange != 5 {
		t.Fatalf("got %+v, want the DC policy's EventAudit (AuditPolicyChange=5): a Default Domain Policy present without [Event Audit] must fall through to the DC policy, not return nil", got)
	}
}

// Target: helpers/gpo_policy.go GetEventAudit's DC policy branch
// (`if dcPolicy != nil && dcPolicy.EventAudit != nil`) - dropping the
// EventAudit subterm makes it return nil as soon as the DC policy exists,
// even without [Event Audit]. A DC policy present WITHOUT [Event Audit]
// (a real-world shape seen in production domains) must fall through to the
// generic search, not mask it.
func TestGetEventAudit_DCPolicyWithoutDataFallsThroughToGenericFallback(t *testing.T) {
	policies := map[string]*audit.GPOPolicy{
		helpers.DefaultDomainPolicyGUID:          {},
		helpers.DefaultDCPolicyGUID:              {},
		"{cccccccc-0000-0000-0000-00000000000c}": {EventAudit: &audit.EventAudit{AuditPolicyChange: 7}},
	}
	got := helpers.GetEventAudit(policies)
	if got == nil || got.AuditPolicyChange != 7 {
		t.Fatalf("got %+v, want the fallback GPO's EventAudit (AuditPolicyChange=7): a DC policy present without [Event Audit] must fall through to the generic search, not return nil", got)
	}
}

// Target: helpers/gpo_policy.go's exported DefaultDomainPolicyGUID and
// DefaultDCPolicyGUID constants. Every other test here references them by
// symbol, so a wrong literal would pass unnoticed; this compares against the
// literal well-known GUIDs instead of the constants under test.
func TestDefaultGPOGUIDsMatchWellKnownValues(t *testing.T) {
	if helpers.DefaultDomainPolicyGUID != "{31B2F340-016D-11D2-945F-00C04FB984F9}" {
		t.Fatalf("helpers.DefaultDomainPolicyGUID = %q, want the well-known Default Domain Policy GUID", helpers.DefaultDomainPolicyGUID)
	}
	if helpers.DefaultDCPolicyGUID != "{6AC1786C-016F-11D2-945F-00C04FB984F9}" {
		t.Fatalf("helpers.DefaultDCPolicyGUID = %q, want the well-known Default Domain Controllers Policy GUID", helpers.DefaultDCPolicyGUID)
	}
}
