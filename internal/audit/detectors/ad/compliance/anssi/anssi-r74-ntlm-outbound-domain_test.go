package anssi

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func r74DenyAll() *int {
	v := 2
	return &v
}

func r74AuditOnly() *int {
	v := 1
	return &v
}

func r74Value(v int) *int {
	return &v
}

// Branch 1: no GPO data at all -> flagged, Count=1, Severity=low.
// Also freezes Count and Severity on the finding (mutation targets: Count 0/2, Severity Medium).
func TestR74NTLMOutboundDomain_NoGPO_Flagged(t *testing.T) {
	domainDN := "DC=example,DC=com"
	data := &audit.DetectorData{
		DomainInfo:  &types.DomainInfo{DomainDN: domainDN},
		GPOPolicies: map[string]*audit.GPOPolicy{},
	}
	d := NewR74NTLMOutboundDomainDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (%+v)", len(findings), findings)
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityLow {
		t.Errorf("Severity = %v, want %v", findings[0].Severity, types.SeverityLow)
	}
}

// Branch 2: GPO at value 2, linked only to OU=Domain Controllers (not the
// domain root) -> R74+ not satisfied despite R73 being satisfied. Count=1.
func TestR74NTLMOutboundDomain_LinkedToTier0OUOnly_Flagged(t *testing.T) {
	domainDN := "DC=example,DC=com"
	gpo := &audit.GPOPolicy{
		GUID:             "11111111-1111-1111-1111-111111111111",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: r74DenyAll()},
	}
	data := &audit.DetectorData{
		DomainInfo:  &types.DomainInfo{DomainDN: domainDN},
		GPOPolicies: map[string]*audit.GPOPolicy{gpo.GUID: gpo},
		GPOLinks: []audit.GPOLink{
			{GPOGuid: gpo.GUID, LinkedTo: "OU=Domain Controllers," + domainDN, LinkEnabled: true},
		},
	}
	d := NewR74NTLMOutboundDomainDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Errorf("expected flagged with Count=1, got %+v", findings)
	}
}

// Branch 3: GPO at value 2, link enabled, at the domain root -> R74+ met,
// no finding.
func TestR74NTLMOutboundDomain_LinkedToDomainRoot_NotFlagged(t *testing.T) {
	domainDN := "DC=example,DC=com"
	gpo := &audit.GPOPolicy{
		GUID:             "22222222-2222-2222-2222-222222222222",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: r74DenyAll()},
	}
	data := &audit.DetectorData{
		DomainInfo:  &types.DomainInfo{DomainDN: domainDN},
		GPOPolicies: map[string]*audit.GPOPolicy{gpo.GUID: gpo},
		GPOLinks: []audit.GPOLink{
			{GPOGuid: gpo.GUID, LinkedTo: domainDN, LinkEnabled: true},
		},
	}
	d := NewR74NTLMOutboundDomainDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Errorf("expected no finding (R74+ met), got %+v", findings)
	}
}

// Branch 4a: value 1 (audit-only) linked at the domain root -> insufficient,
// flagged, Count=1. Kills the `< 1` threshold mutation.
func TestR74NTLMOutboundDomain_AuditOnlyAtDomainRoot_Flagged(t *testing.T) {
	domainDN := "DC=example,DC=com"
	gpo := &audit.GPOPolicy{
		GUID:             "33333333-3333-3333-3333-333333333333",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: r74AuditOnly()},
	}
	data := &audit.DetectorData{
		DomainInfo:  &types.DomainInfo{DomainDN: domainDN},
		GPOPolicies: map[string]*audit.GPOPolicy{gpo.GUID: gpo},
		GPOLinks: []audit.GPOLink{
			{GPOGuid: gpo.GUID, LinkedTo: domainDN, LinkEnabled: true},
		},
	}
	d := NewR74NTLMOutboundDomainDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Errorf("expected flagged with Count=1 (audit-only insufficient), got %+v", findings)
	}
}

// Branch 4b: value 3 at the domain root -> still met (>= 2), no finding.
// Kills the `*...RestrictSendingNTLMTraffic != 2` mutation of the threshold guard.
func TestR74NTLMOutboundDomain_ValueThreeAtDomainRoot_NotFlagged(t *testing.T) {
	domainDN := "DC=example,DC=com"
	gpo := &audit.GPOPolicy{
		GUID:             "44444444-4444-4444-4444-444444444444",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: r74Value(3)},
	}
	data := &audit.DetectorData{
		DomainInfo:  &types.DomainInfo{DomainDN: domainDN},
		GPOPolicies: map[string]*audit.GPOPolicy{gpo.GUID: gpo},
		GPOLinks: []audit.GPOLink{
			{GPOGuid: gpo.GUID, LinkedTo: domainDN, LinkEnabled: true},
		},
	}
	d := NewR74NTLMOutboundDomainDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Errorf("expected no finding (value=3 still satisfies >= 2), got %+v", findings)
	}
}

// Branch 5a: value 2 at the domain root but LinkEnabled=false -> not counted,
// flagged.
func TestR74NTLMOutboundDomain_DomainRootLinkDisabled_Flagged(t *testing.T) {
	domainDN := "DC=example,DC=com"
	gpo := &audit.GPOPolicy{
		GUID:             "55555555-5555-5555-5555-555555555555",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: r74DenyAll()},
	}
	data := &audit.DetectorData{
		DomainInfo:  &types.DomainInfo{DomainDN: domainDN},
		GPOPolicies: map[string]*audit.GPOPolicy{gpo.GUID: gpo},
		GPOLinks: []audit.GPOLink{
			{GPOGuid: gpo.GUID, LinkedTo: domainDN, LinkEnabled: false},
		},
	}
	d := NewR74NTLMOutboundDomainDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Errorf("expected flagged with Count=1 (link disabled), got %+v", findings)
	}
}

// Branch 5b: value 2 at the domain root, LinkEnabled=true but Disabled=true
// -> not counted, flagged. Kills the `link.Disabled` subterm independently
// of `!link.LinkEnabled`.
func TestR74NTLMOutboundDomain_DomainRootLinkMarkedDisabled_Flagged(t *testing.T) {
	domainDN := "DC=example,DC=com"
	gpo := &audit.GPOPolicy{
		GUID:             "66666666-6666-6666-6666-666666666666",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: r74DenyAll()},
	}
	data := &audit.DetectorData{
		DomainInfo:  &types.DomainInfo{DomainDN: domainDN},
		GPOPolicies: map[string]*audit.GPOPolicy{gpo.GUID: gpo},
		GPOLinks: []audit.GPOLink{
			{GPOGuid: gpo.GUID, LinkedTo: domainDN, LinkEnabled: true, Disabled: true},
		},
	}
	d := NewR74NTLMOutboundDomainDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Errorf("expected flagged with Count=1 (link.Disabled=true), got %+v", findings)
	}
}

// Branch 6a: RegistrySettings is nil on the only GPO, linked at the domain
// root -> skipped by the first guard, flagged.
func TestR74NTLMOutboundDomain_RegistrySettingsNil_Flagged(t *testing.T) {
	domainDN := "DC=example,DC=com"
	gpo := &audit.GPOPolicy{
		GUID:             "77777777-7777-7777-7777-777777777777",
		RegistrySettings: nil,
	}
	data := &audit.DetectorData{
		DomainInfo:  &types.DomainInfo{DomainDN: domainDN},
		GPOPolicies: map[string]*audit.GPOPolicy{gpo.GUID: gpo},
		GPOLinks: []audit.GPOLink{
			{GPOGuid: gpo.GUID, LinkedTo: domainDN, LinkEnabled: true},
		},
	}
	d := NewR74NTLMOutboundDomainDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Errorf("expected flagged with Count=1 (RegistrySettings nil), got %+v", findings)
	}
}

// Branch 6b: RestrictSendingNTLMTraffic is nil (RegistrySettings present but
// unset) -> skipped by the second guard, flagged. Kills the
// `RestrictSendingNTLMTraffic == nil` subterm independently of the `< 2` part.
func TestR74NTLMOutboundDomain_RestrictSendingNTLMTrafficNil_Flagged(t *testing.T) {
	domainDN := "DC=example,DC=com"
	gpo := &audit.GPOPolicy{
		GUID:             "88888888-8888-8888-8888-888888888888",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: nil},
	}
	data := &audit.DetectorData{
		DomainInfo:  &types.DomainInfo{DomainDN: domainDN},
		GPOPolicies: map[string]*audit.GPOPolicy{gpo.GUID: gpo},
		GPOLinks: []audit.GPOLink{
			{GPOGuid: gpo.GUID, LinkedTo: domainDN, LinkEnabled: true},
		},
	}
	d := NewR74NTLMOutboundDomainDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Errorf("expected flagged with Count=1 (RestrictSendingNTLMTraffic nil), got %+v", findings)
	}
}

// Branch 6c: a nil *GPOPolicy entry in the map, alongside a conforming GPO
// linked at the domain root -> the nil entry must not panic or short-circuit
// the loop; the conforming GPO is still found -> no finding. Kills the
// `p == nil` subterm independently of `p.RegistrySettings == nil`.
func TestR74NTLMOutboundDomain_NilPolicyEntryInMap_NotFlagged(t *testing.T) {
	domainDN := "DC=example,DC=com"
	conforming := &audit.GPOPolicy{
		GUID:             "99999999-9999-9999-9999-999999999999",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: r74DenyAll()},
	}
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: domainDN},
		GPOPolicies: map[string]*audit.GPOPolicy{
			"nil-entry":     nil,
			conforming.GUID: conforming,
		},
		GPOLinks: []audit.GPOLink{
			{GPOGuid: conforming.GUID, LinkedTo: domainDN, LinkEnabled: true},
		},
	}
	d := NewR74NTLMOutboundDomainDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Errorf("expected no finding (nil map entry must be skipped, conforming GPO found), got %+v", findings)
	}
}

// Branch 6c-bis: a nil *GPOPolicy entry is the ONLY entry in the map ->
// deterministic kill of the `p == nil` subterm independent of Go's
// randomized map iteration order. The NilPolicyEntryInMap test above also
// carries a conforming GPO, so removing `p == nil` only panics there when
// the nil entry happens to be visited before the conforming one returns
// early, making that kill probabilistic. With a single entry there is no
// "before": the nil entry is always visited, and the unmutated guard
// simply skips it, leaving no conforming GPO -> flagged, Count=1. With
// `p == nil` removed, `p.RegistrySettings` dereferences the nil pointer
// on that same, only, iteration and panics every time.
func TestR74NTLMOutboundDomain_NilPolicyEntryOnly_Flagged(t *testing.T) {
	domainDN := "DC=example,DC=com"
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: domainDN},
		GPOPolicies: map[string]*audit.GPOPolicy{
			"nil-entry": nil,
		},
	}
	d := NewR74NTLMOutboundDomainDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Errorf("expected flagged with Count=1 (sole map entry is nil, no conforming GPO found), got %+v", findings)
	}
}

// Branch 7: two GPOs in the same dataset - one non-conforming (linked to a
// Tier 0 OU only) and one conforming (linked at the domain root) - no
// finding, proving the loop does not short-circuit on the first,
// non-satisfying GPO. Replayed with -count=5 by the verification step
// because Go map iteration order is randomized.
func TestR74NTLMOutboundDomain_TwoGPOs_OneConforming_NotFlagged(t *testing.T) {
	domainDN := "DC=example,DC=com"
	nonConforming := &audit.GPOPolicy{
		GUID:             "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: r74DenyAll()},
	}
	conforming := &audit.GPOPolicy{
		GUID:             "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: r74DenyAll()},
	}
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: domainDN},
		GPOPolicies: map[string]*audit.GPOPolicy{
			nonConforming.GUID: nonConforming,
			conforming.GUID:    conforming,
		},
		GPOLinks: []audit.GPOLink{
			{GPOGuid: nonConforming.GUID, LinkedTo: "OU=Domain Controllers," + domainDN, LinkEnabled: true},
			{GPOGuid: conforming.GUID, LinkedTo: domainDN, LinkEnabled: true},
		},
	}
	d := NewR74NTLMOutboundDomainDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Errorf("expected no finding (one conforming GPO present, no short-circuit on the other), got %+v", findings)
	}
}

// Branch 8: DomainInfo is nil -> domainDN stays "" (documented fallback).
// A GPO linked to "" would only match LinkedToDomain if LinkedTo is also "",
// which ComputeGPOScope explicitly rejects (empty target is skipped), so a
// GPO that would otherwise be conforming at the (unknown) domain root cannot
// be recognized as such: flagged, Count=1.
func TestR74NTLMOutboundDomain_DomainInfoNil_Flagged(t *testing.T) {
	gpo := &audit.GPOPolicy{
		GUID:             "cccccccc-cccc-cccc-cccc-cccccccccccc",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: r74DenyAll()},
	}
	data := &audit.DetectorData{
		DomainInfo:  nil,
		GPOPolicies: map[string]*audit.GPOPolicy{gpo.GUID: gpo},
		GPOLinks: []audit.GPOLink{
			{GPOGuid: gpo.GUID, LinkedTo: "DC=example,DC=com", LinkEnabled: true},
		},
	}
	d := NewR74NTLMOutboundDomainDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Errorf("expected flagged with Count=1 (DomainInfo nil -> domainDN empty, no match), got %+v", findings)
	}
}

// Branch 9: ComputeGPOScope's own-GUID filter boundary, exercised through
// R74+: misLinked (value 2) is linked ONLY outside the domain root; a
// second, unrelated GPO (no registry value) is linked at the domain root.
// Disabling ComputeGPOScope's GUID filter would let the unrelated GPO's
// domain-root link leak into misLinked's own scope (LinkedToDomain=true),
// satisfying R74+ for a GPO that is not actually linked at the domain root -
// a false negative.
func TestR74NTLMOutboundDomain_TwoGPOs_MisLinkedValueTwoNotMadeConformingByUnrelatedRootLink(t *testing.T) {
	domainDN := "DC=example,DC=com"
	misLinked := &audit.GPOPolicy{
		GUID:             "dddddddd-dddd-dddd-dddd-dddddddddddd",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: r74DenyAll()},
	}
	unrelatedRootLinked := &audit.GPOPolicy{
		GUID:             "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
		RegistrySettings: nil,
	}
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: domainDN},
		GPOPolicies: map[string]*audit.GPOPolicy{
			misLinked.GUID:           misLinked,
			unrelatedRootLinked.GUID: unrelatedRootLinked,
		},
		GPOLinks: []audit.GPOLink{
			{GPOGuid: misLinked.GUID, LinkedTo: "OU=Workstations," + domainDN, LinkEnabled: true},
			{GPOGuid: unrelatedRootLinked.GUID, LinkedTo: domainDN, LinkEnabled: true},
		},
	}
	d := NewR74NTLMOutboundDomainDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Errorf("expected the finding to be raised (misLinked's own GUID-scoped link is Workstations only; unrelatedRootLinked's domain-root link belongs to a different GPO and must not satisfy misLinked), got %+v", findings)
	}
}
