package anssi

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func denyAll() *int {
	v := 2
	return &v
}

func auditOnly() *int {
	v := 1
	return &v
}

// R73 previously matched on ANY GPO setting the registry value,
// with zero check that the GPO was actually linked to Tier 0. A GPO with
// the right value linked to an unrelated OU used to pass R73 - a false
// negative. It must now require the GPO to be link-enabled at the domain
// root, a Tier 0 OU, or the Domain Controllers container.
func TestR73NTLMOutboundTier0_Detect(t *testing.T) {
	domainDN := "DC=test,DC=local"

	gpoLinkedNowhereUseful := &audit.GPOPolicy{
		GUID:             "11111111-1111-1111-1111-111111111111",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: denyAll()},
	}
	gpoLinkedToDC := &audit.GPOPolicy{
		GUID:             "22222222-2222-2222-2222-222222222222",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: denyAll()},
	}
	gpoLinkedToDomainRoot := &audit.GPOPolicy{
		GUID:             "33333333-3333-3333-3333-333333333333",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: denyAll()},
	}
	gpoAuditOnlyLinkedToDC := &audit.GPOPolicy{
		GUID:             "44444444-4444-4444-4444-444444444444",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: auditOnly()},
	}

	cases := []struct {
		name        string
		policies    map[string]*audit.GPOPolicy
		links       []audit.GPOLink
		wantFlagged bool
	}{
		{
			name:     "value set but linked to an unrelated OU -> still flagged (was the  false negative)",
			policies: map[string]*audit.GPOPolicy{gpoLinkedNowhereUseful.GUID: gpoLinkedNowhereUseful},
			links: []audit.GPOLink{
				{GPOGuid: gpoLinkedNowhereUseful.GUID, LinkedTo: "OU=Workstations," + domainDN, LinkEnabled: true},
			},
			wantFlagged: true,
		},
		{
			name:     "value set and linked to Domain Controllers OU -> met",
			policies: map[string]*audit.GPOPolicy{gpoLinkedToDC.GUID: gpoLinkedToDC},
			links: []audit.GPOLink{
				{GPOGuid: gpoLinkedToDC.GUID, LinkedTo: "OU=Domain Controllers," + domainDN, LinkEnabled: true},
			},
			wantFlagged: false,
		},
		{
			name:     "value set and linked to domain root -> met (domain-wide is a superset of Tier 0)",
			policies: map[string]*audit.GPOPolicy{gpoLinkedToDomainRoot.GUID: gpoLinkedToDomainRoot},
			links: []audit.GPOLink{
				{GPOGuid: gpoLinkedToDomainRoot.GUID, LinkedTo: domainDN, LinkEnabled: true},
			},
			wantFlagged: false,
		},
		{
			name:     "audit-only (=1) even when linked to DC OU -> not enough, flagged",
			policies: map[string]*audit.GPOPolicy{gpoAuditOnlyLinkedToDC.GUID: gpoAuditOnlyLinkedToDC},
			links: []audit.GPOLink{
				{GPOGuid: gpoAuditOnlyLinkedToDC.GUID, LinkedTo: "OU=Domain Controllers," + domainDN, LinkEnabled: true},
			},
			wantFlagged: true,
		},
		{
			name:     "link disabled -> not counted, flagged",
			policies: map[string]*audit.GPOPolicy{gpoLinkedToDC.GUID: gpoLinkedToDC},
			links: []audit.GPOLink{
				{GPOGuid: gpoLinkedToDC.GUID, LinkedTo: "OU=Domain Controllers," + domainDN, LinkEnabled: false},
			},
			wantFlagged: true,
		},
		{
			name:        "no GPO at all -> flagged",
			policies:    map[string]*audit.GPOPolicy{},
			links:       nil,
			wantFlagged: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{
				DomainInfo:  &types.DomainInfo{DomainDN: domainDN},
				GPOPolicies: tc.policies,
				GPOLinks:    tc.links,
			}
			d := NewR73NTLMOutboundTier0Detector()
			findings := d.Detect(context.Background(), data)
			flagged := len(findings) == 1 && findings[0].Count > 0
			if flagged != tc.wantFlagged {
				t.Errorf("flagged = %v, want %v (findings=%+v)", flagged, tc.wantFlagged, findings)
			}
		})
	}
}

func TestR73NTLMOutboundTier0_CustomTier0OU(t *testing.T) {
	domainDN := "DC=test,DC=local"
	gpo := &audit.GPOPolicy{
		GUID:             "55555555-5555-5555-5555-555555555555",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: denyAll()},
	}
	data := &audit.DetectorData{
		DomainInfo:  &types.DomainInfo{DomainDN: domainDN},
		GPOPolicies: map[string]*audit.GPOPolicy{gpo.GUID: gpo},
		GPOLinks: []audit.GPOLink{
			{GPOGuid: gpo.GUID, LinkedTo: "OU=SecureAdmin," + domainDN, LinkEnabled: true},
		},
		Tier0Config: &audit.Tier0HelperConfig{OUs: []string{"OU=SecureAdmin," + domainDN}},
	}
	d := NewR73NTLMOutboundTier0Detector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Errorf("expected R73 met via tier0_groups.yaml custom OU, got %+v", findings)
	}
}

// TestR73NTLMOutboundTier0_NilGuards_NoPanic covers the detector's nil-guard
// chain: the GPOPolicies map holds a nil entry, a GPO with a nil RegistrySettings,
// and a GPO with a nil RestrictSendingNTLMTraffic, all linked to the domain
// root. On real collected data (a GPO with no Machine Registry.pol at all, or
// one without the NTLM value) this is exactly the shape CollectGPOPolicies
// produces; removing any of the three nil-guard sub-terms at detector:58
// dereferences a nil pointer and panics instead of returning the finding.
func TestR73NTLMOutboundTier0_NilGuards_NoPanic(t *testing.T) {
	domainDN := "DC=test,DC=local"

	gpoNoRegistrySettings := &audit.GPOPolicy{
		GUID:             "66666666-6666-6666-6666-666666666666",
		RegistrySettings: nil,
	}
	gpoNilNTLMValue := &audit.GPOPolicy{
		GUID:             "77777777-7777-7777-7777-777777777777",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: nil},
	}

	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: domainDN},
		GPOPolicies: map[string]*audit.GPOPolicy{
			"nil-entry":                nil,
			gpoNoRegistrySettings.GUID: gpoNoRegistrySettings,
			gpoNilNTLMValue.GUID:       gpoNilNTLMValue,
		},
		GPOLinks: []audit.GPOLink{
			{GPOGuid: gpoNoRegistrySettings.GUID, LinkedTo: domainDN, LinkEnabled: true},
			{GPOGuid: gpoNilNTLMValue.GUID, LinkedTo: domainDN, LinkEnabled: true},
		},
	}

	d := NewR73NTLMOutboundTier0Detector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Errorf("expected exactly one finding with Count=1 (no GPO sets RestrictSendingNTLMTraffic>=2), got %+v", findings)
	}
}

// TestR73NTLMOutboundTier0_LinkedTier0OUOnly_NoFinding covers the
// scope.LinkedTier0OU sub-term at detector:66 as an independent path to
// "met", distinct from scope.LinkedToDomain. A GPO set to deny-all (2),
// linked ONLY to an OU that helpers.isTier0OUDN recognizes as a Tier 0
// marker (here "OU=Tier0,...", not the domain root, not "OU=Domain
// Controllers", not a Tier0Config.OUs entry) must still satisfy R73.
func TestR73NTLMOutboundTier0_LinkedTier0OUOnly_NoFinding(t *testing.T) {
	domainDN := "DC=test,DC=local"
	gpo := &audit.GPOPolicy{
		GUID:             "88888888-8888-8888-8888-888888888888",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: denyAll()},
	}
	data := &audit.DetectorData{
		DomainInfo:  &types.DomainInfo{DomainDN: domainDN},
		GPOPolicies: map[string]*audit.GPOPolicy{gpo.GUID: gpo},
		GPOLinks: []audit.GPOLink{
			{GPOGuid: gpo.GUID, LinkedTo: "OU=Tier0," + domainDN, LinkEnabled: true},
		},
	}
	d := NewR73NTLMOutboundTier0Detector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Errorf("expected R73 met via the isTier0OUDN marker alone (scope.LinkedTier0OU), got %+v", findings)
	}
}

// TestR73NTLMOutboundTier0_Severity asserts the finding's Severity is high,
// not any lower value.
func TestR73NTLMOutboundTier0_Severity(t *testing.T) {
	domainDN := "DC=test,DC=local"
	data := &audit.DetectorData{
		DomainInfo:  &types.DomainInfo{DomainDN: domainDN},
		GPOPolicies: map[string]*audit.GPOPolicy{},
		GPOLinks:    nil,
	}
	d := NewR73NTLMOutboundTier0Detector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly one finding, got %+v", findings)
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Errorf("Severity = %v, want %v", findings[0].Severity, types.SeverityHigh)
	}
}

// TestR73NTLMOutboundTier0_DisabledLinkToDCOU_Flagged covers gpoLinkedToAny's
// link.Disabled sub-term, honored independently of LinkEnabled. A
// GPO set to deny-all (2) whose only link to "OU=Domain Controllers" has
// Disabled=true (and LinkEnabled=true - a link can be enforced-disabled
// without LinkEnabled itself being false) must NOT satisfy R73.
func TestR73NTLMOutboundTier0_DisabledLinkToDCOU_Flagged(t *testing.T) {
	domainDN := "DC=test,DC=local"
	gpo := &audit.GPOPolicy{
		GUID:             "99999999-9999-9999-9999-999999999999",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: denyAll()},
	}
	data := &audit.DetectorData{
		DomainInfo:  &types.DomainInfo{DomainDN: domainDN},
		GPOPolicies: map[string]*audit.GPOPolicy{gpo.GUID: gpo},
		GPOLinks: []audit.GPOLink{
			{GPOGuid: gpo.GUID, LinkedTo: "OU=Domain Controllers," + domainDN, LinkEnabled: true, Disabled: true},
		},
	}
	d := NewR73NTLMOutboundTier0Detector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Errorf("expected the finding to be raised (link.Disabled=true must not count as a valid Tier 0 link), got %+v", findings)
	}
}

// TestR73NTLMOutboundTier0_MisLinkedValueTwoNotSatisfiedByUnrelatedGPOLinkedToDCOU
// covers gpoLinkedToAny's own-GUID filter (`!strings.Contains(ref, guidLower)`)
// as an isolation boundary between two different GPOs, not just a no-op on a
// single-GPO dataset. misLinked (value 2) is linked ONLY to OU=Workstations;
// a second, unrelated GPO (no registry value at all) is linked to
// OU=Domain Controllers. Disabling the GUID filter would let gpoLinkedToAny
// match misLinked's call against the unrelated GPO's link to the DC OU and
// wrongly report misLinked as satisfying R73 - a false negative, since the
// GPO that actually sets the value is still only linked to Workstations.
func TestR73NTLMOutboundTier0_MisLinkedValueTwoNotSatisfiedByUnrelatedGPOLinkedToDCOU(t *testing.T) {
	domainDN := "DC=test,DC=local"
	misLinked := &audit.GPOPolicy{
		GUID:             "f0000001-0000-0000-0000-000000000001",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: denyAll()},
	}
	unrelatedDCLinked := &audit.GPOPolicy{
		GUID:             "f0000002-0000-0000-0000-000000000002",
		RegistrySettings: nil,
	}
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: domainDN},
		GPOPolicies: map[string]*audit.GPOPolicy{
			misLinked.GUID:         misLinked,
			unrelatedDCLinked.GUID: unrelatedDCLinked,
		},
		GPOLinks: []audit.GPOLink{
			{GPOGuid: misLinked.GUID, LinkedTo: "OU=Workstations," + domainDN, LinkEnabled: true},
			{GPOGuid: unrelatedDCLinked.GUID, LinkedTo: "OU=Domain Controllers," + domainDN, LinkEnabled: true},
		},
	}
	d := NewR73NTLMOutboundTier0Detector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Errorf("expected the finding to be raised (misLinked's own GUID-scoped link is Workstations only; unrelatedDCLinked's link to Domain Controllers belongs to a different GPO and must not satisfy misLinked), got %+v", findings)
	}
}

// TestR73NTLMOutboundTier0_RealGPOCNFormat_LinkedToDCOU_NotFlagged exercises
// gpoLinkedToAny through a link whose GPOCN is populated in the real
// collected shape (braced GUID), with GPOGuid holding the same GUID without
// braces - the form every other R73 test leaves empty, falling back to
// GPOGuid instead. Forcing the ref selection onto GPOGuid unconditionally
// would compare the unbraced GPOGuid against the GPO's own braced GUID,
// which never matches, and wrongly flag an actually-compliant GPO.
func TestR73NTLMOutboundTier0_RealGPOCNFormat_LinkedToDCOU_NotFlagged(t *testing.T) {
	domainDN := "DC=test,DC=local"
	guidNoBraces := "c0000003-0000-0000-0000-000000000003"
	guidBraced := "{" + guidNoBraces + "}"
	gpo := &audit.GPOPolicy{
		GUID:             guidBraced,
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: denyAll()},
	}
	data := &audit.DetectorData{
		DomainInfo:  &types.DomainInfo{DomainDN: domainDN},
		GPOPolicies: map[string]*audit.GPOPolicy{gpo.GUID: gpo},
		GPOLinks: []audit.GPOLink{
			{GPOCN: guidBraced, GPOGuid: guidNoBraces, LinkedTo: "OU=Domain Controllers," + domainDN, LinkEnabled: true},
		},
	}
	d := NewR73NTLMOutboundTier0Detector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Errorf("expected R73 met (GPO properly linked to Domain Controllers via a real-format GPOCN link), got %+v", findings)
	}
}

// TestR73NTLMOutboundTier0_TwoGPOs_MisLinkedValueTwoNotMadeConformingByUnrelatedRootLink
// is ComputeGPOScope's own-GUID filter boundary, exercised through R73: misLinked
// (value 2) is linked ONLY to a non-Tier-0 OU; a second, unrelated GPO (no
// registry value) is linked at the domain root. Disabling ComputeGPOScope's
// GUID filter would let the unrelated GPO's domain-root link leak into
// misLinked's own scope (LinkedToDomain=true), satisfying R73 for a GPO
// that is not actually linked anywhere near Tier 0 - a false negative.
func TestR73NTLMOutboundTier0_TwoGPOs_MisLinkedValueTwoNotMadeConformingByUnrelatedRootLink(t *testing.T) {
	domainDN := "DC=test,DC=local"
	misLinked := &audit.GPOPolicy{
		GUID:             "a0000004-0000-0000-0000-000000000004",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: denyAll()},
	}
	unrelatedRootLinked := &audit.GPOPolicy{
		GUID:             "a0000005-0000-0000-0000-000000000005",
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
	d := NewR73NTLMOutboundTier0Detector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Errorf("expected the finding to be raised (misLinked's own GUID-scoped link is Workstations only; unrelatedRootLinked's domain-root link belongs to a different GPO and must not satisfy misLinked), got %+v", findings)
	}
}
