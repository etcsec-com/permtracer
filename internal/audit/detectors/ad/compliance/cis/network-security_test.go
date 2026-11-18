package cis

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func intp(v int) *int { return &v }

func gpoWith(rs *audit.RegistrySettings) map[string]*audit.GPOPolicy {
	return map[string]*audit.GPOPolicy{
		"{gpo}": {GUID: "{gpo}", DisplayName: "Default Domain Controllers Policy", RegistrySettings: rs},
	}
}

// TestNetworkSecurity_NoGPODataAtAll_NoFalsePositive: when
// data.GPOPolicies is nil (SMB/SYSVOL not collected this run), the 4
// registry-based checks must not be evaluated at all - "never looked" is not
// "looked and found nothing configured".
func TestNetworkSecurity_NoGPODataAtAll_NoFalsePositive(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: nil}
	findings := NewNetworkSecurityDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("got %+v, want Count=0 when no GPO data was collected", findings)
	}
}

// TestNetworkSecurity_ConfiguredButAbsentSetting_Flagged: a
// domain WAS audited (GPO data collected) but a specific setting was never
// explicitly configured. CIS Benchmark items read "Ensure X is set to Y" -
// not configured is a finding, not a silent pass. Before the fix, a nil
// RequireSMBSigningServer was treated as compliant.
func TestNetworkSecurity_ConfiguredButAbsentSetting_Flagged(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{})}
	findings := NewNetworkSecurityDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	// All 4 registry checks should be flagged since none is configured.
	if findings[0].Count != 4 {
		t.Errorf("Count = %d, want 4 (all 4 unconfigured registry settings flagged)", findings[0].Count)
	}
}

// TestNetworkSecurity_FullyCompliant_NoFinding is the regression check for a
// properly configured domain.
func TestNetworkSecurity_FullyCompliant_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: gpoWith(&audit.RegistrySettings{
			RequireSMBSigningServer: intp(1),
			RequireSMBSigningClient: intp(1),
			LDAPServerIntegrity:     intp(2),
			LDAPChannelBinding:      intp(2),
		}),
		DomainInfo: &types.DomainInfo{FunctionalLevelInt: 7},
	}
	findings := NewNetworkSecurityDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("got %+v, want Count=0 for a fully compliant domain", findings)
	}
}

// TestNetworkSecurity_FunctionalLevel_NotAttributedToCIS: no CIS
// Windows Server Benchmark contains a domain-functional-level control. This
// product-level check must not be labeled as a CIS requirement.
func TestNetworkSecurity_FunctionalLevel_NotAttributedToCIS(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: gpoWith(&audit.RegistrySettings{
			RequireSMBSigningServer: intp(1),
			RequireSMBSigningClient: intp(1),
			LDAPServerIntegrity:     intp(2),
			LDAPChannelBinding:      intp(2),
		}),
		DomainInfo: &types.DomainInfo{FunctionalLevelInt: 3},
	}
	findings := NewNetworkSecurityDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (only the functional-level note)", findings)
	}
	violations, _ := findings[0].Details["violations"].([]string)
	if len(violations) != 1 || violations[0][:4] == "CIS " {
		t.Errorf("functional-level violation must not be attributed to CIS, got %v", violations)
	}
}

// TestNetworkSecurity_LDAPSigningCitesServerSideSection: the
// old citation "CIS 2.3.11.8" is the LDAP CLIENT signing control; this
// detector reads the SERVER-side (Domain controller) setting, which belongs
// under section 2.3.5.
func TestNetworkSecurity_LDAPSigningCitesServerSideSection(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{
		RequireSMBSigningServer: intp(1),
		RequireSMBSigningClient: intp(1),
		LDAPChannelBinding:      intp(2),
		LDAPServerIntegrity:     intp(0),
	})}
	findings := NewNetworkSecurityDetector().Detect(context.Background(), data)
	violations, _ := findings[0].Details["violations"].([]string)
	found := false
	for _, v := range violations {
		if v == "CIS 2.3.5 (Domain controller: LDAP server signing requirements): not set to Require signing" {
			found = true
		}
		if len(v) >= 14 && v[:14] == "CIS 2.3.11.8: " {
			t.Errorf("violation still cites the wrong (client-side) CIS section: %q", v)
		}
	}
	if !found {
		t.Errorf("expected the corrected 2.3.5 LDAP server-signing violation, got %v", violations)
	}
}

// TestNetworkSecurity_LDAPServerIntegrityBoundaryValue1Flagged kills the
// threshold mutation `< 2` -> `< 1` on the LDAP server signing check.
// LDAPServerIntegrity=1 ("negotiate") does not meet CIS's "Require signing"
// (2) and must be flagged; a `< 1` threshold would silently accept it.
func TestNetworkSecurity_LDAPServerIntegrityBoundaryValue1Flagged(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: gpoWith(&audit.RegistrySettings{
			RequireSMBSigningServer: intp(1),
			RequireSMBSigningClient: intp(1),
			LDAPServerIntegrity:     intp(1),
			LDAPChannelBinding:      intp(2),
		}),
		DomainInfo: &types.DomainInfo{FunctionalLevelInt: 7},
	}
	findings := NewNetworkSecurityDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (LDAPServerIntegrity=1 must be flagged, not treated as compliant)", findings)
	}
	violations, _ := findings[0].Details["violations"].([]string)
	if len(violations) != 1 || violations[0] != "CIS 2.3.5 (Domain controller: LDAP server signing requirements): not set to Require signing" {
		t.Fatalf("violations = %v, want the LDAP server signing violation", violations)
	}
}

// TestNetworkSecurity_LDAPChannelBindingBoundaryValue1Flagged kills the
// threshold mutation `< 2` -> `< 1` on the LDAP channel binding check.
// LDAPChannelBinding=1 ("when supported") does not meet "Always" (2) and
// must be flagged.
func TestNetworkSecurity_LDAPChannelBindingBoundaryValue1Flagged(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: gpoWith(&audit.RegistrySettings{
			RequireSMBSigningServer: intp(1),
			RequireSMBSigningClient: intp(1),
			LDAPServerIntegrity:     intp(2),
			LDAPChannelBinding:      intp(1),
		}),
		DomainInfo: &types.DomainInfo{FunctionalLevelInt: 7},
	}
	findings := NewNetworkSecurityDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (LDAPChannelBinding=1 must be flagged, not treated as compliant)", findings)
	}
	violations, _ := findings[0].Details["violations"].([]string)
	if len(violations) != 1 || violations[0] != "CIS 2.3.5.3 (Domain controller: LDAP server channel binding token requirements): not set to Always" {
		t.Fatalf("violations = %v, want the channel binding violation", violations)
	}
}

// TestNetworkSecurity_FunctionalLevelBoundaryValue6Flagged kills the
// threshold mutation `< 7` -> `< 6` on the functional-level note.
// FunctionalLevelInt=6 (Windows Server 2012 R2) is below the Windows
// Server 2016 (7) baseline and must still be flagged.
func TestNetworkSecurity_FunctionalLevelBoundaryValue6Flagged(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: gpoWith(&audit.RegistrySettings{
			RequireSMBSigningServer: intp(1),
			RequireSMBSigningClient: intp(1),
			LDAPServerIntegrity:     intp(2),
			LDAPChannelBinding:      intp(2),
		}),
		DomainInfo: &types.DomainInfo{FunctionalLevelInt: 6},
	}
	findings := NewNetworkSecurityDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (functional level 6 must still be flagged, not treated as compliant)", findings)
	}
}

// TestNetworkSecurity_ServerClientGettersDistinct kills both the SMB-server
// getter mutation (reading RequireSMBSigningClient instead of
// RequireSMBSigningServer) and the SMB-client getter mutation (reading
// RequireSMBSigningServer instead of RequireSMBSigningClient). Server and
// client are set to different, non-equal values on purpose: any swap
// between the two fields changes which check fires and therefore Count.
func TestNetworkSecurity_ServerClientGettersDistinct(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: gpoWith(&audit.RegistrySettings{
			RequireSMBSigningServer: intp(1),
			RequireSMBSigningClient: nil,
			LDAPServerIntegrity:     intp(2),
			LDAPChannelBinding:      intp(2),
		}),
		DomainInfo: &types.DomainInfo{FunctionalLevelInt: 7},
	}
	findings := NewNetworkSecurityDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (only the SMB client check must fire; server=1 is compliant, client=nil is not)", findings)
	}
	violations, _ := findings[0].Details["violations"].([]string)
	if len(violations) != 1 || violations[0] != "CIS 2.3.8.1: SMB client signing not required" {
		t.Fatalf("violations = %v, want only the SMB client signing violation", violations)
	}
}

// TestNetworkSecurity_ChannelBindingGetterDistinctFromLDAPSigning kills the
// channel-binding getter mutation (reading LDAPServerIntegrity instead of
// LDAPChannelBinding). CB=2 (compliant) and LDAPServerIntegrity=1
// (non-compliant) are set to different values on purpose: if the channel
// binding check reads the wrong field, it would wrongly re-flag the
// already-counted LDAP-signing violation a second time under its own label.
func TestNetworkSecurity_ChannelBindingGetterDistinctFromLDAPSigning(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: gpoWith(&audit.RegistrySettings{
			RequireSMBSigningServer: intp(1),
			RequireSMBSigningClient: intp(1),
			LDAPServerIntegrity:     intp(1),
			LDAPChannelBinding:      intp(2),
		}),
		DomainInfo: &types.DomainInfo{FunctionalLevelInt: 7},
	}
	findings := NewNetworkSecurityDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (only LDAP signing must fire; channel binding=2 is compliant)", findings)
	}
	violations, _ := findings[0].Details["violations"].([]string)
	if len(violations) != 1 || violations[0] != "CIS 2.3.5 (Domain controller: LDAP server signing requirements): not set to Require signing" {
		t.Fatalf("violations = %v, want only the LDAP server signing violation (not a duplicate channel-binding one)", violations)
	}
}

// TestNetworkSecurity_SeverityIsMedium kills the Severity mutation
// (SeverityMedium -> SeverityHigh). Severity is an observable output field,
// explicitly in scope per the ticket arbitration.
func TestNetworkSecurity_SeverityIsMedium(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: gpoWith(&audit.RegistrySettings{})}
	findings := NewNetworkSecurityDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityMedium {
		t.Fatalf("Severity = %q, want %q", findings[0].Severity, types.SeverityMedium)
	}
}

// TestNetworkSecurity_CompliantDetailsOmitViolationsAndRecommendation kills
// the final-block mutation `if len(violations) > 0` -> `if true ||
// (len(violations) > 0)`. For a fully compliant domain, Details must not
// carry a "violations" or "recommendation" key at all.
func TestNetworkSecurity_CompliantDetailsOmitViolationsAndRecommendation(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: gpoWith(&audit.RegistrySettings{
			RequireSMBSigningServer: intp(1),
			RequireSMBSigningClient: intp(1),
			LDAPServerIntegrity:     intp(2),
			LDAPChannelBinding:      intp(2),
		}),
		DomainInfo: &types.DomainInfo{FunctionalLevelInt: 7},
	}
	findings := NewNetworkSecurityDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if _, ok := findings[0].Details["violations"]; ok {
		t.Errorf("Details must not contain \"violations\" for a compliant domain, got %v", findings[0].Details)
	}
	if _, ok := findings[0].Details["recommendation"]; ok {
		t.Errorf("Details must not contain \"recommendation\" for a compliant domain, got %v", findings[0].Details)
	}
}

// conflictingGPO returns a minimal GPOPolicy with only LDAPServerIntegrity
// set, used as "noise" GPOs that conflict with the DC/Domain policy value
// in the precedence tests below.
func conflictingGPO(guid string, ldapServerIntegrity int) *audit.GPOPolicy {
	return &audit.GPOPolicy{
		GUID:             guid,
		RegistrySettings: &audit.RegistrySettings{LDAPServerIntegrity: intp(ldapServerIntegrity)},
	}
}

// TestNetworkSecurity_DCPolicyPrecedenceOverConflictingGPO kills the
// FindRegistrySettingInt DC-tier mutation (helpers/gpo_policy.go:136,
// `if false && (dcPolicy != nil ...)`). The Default DC Policy (known GUID)
// carries a compliant LDAPServerIntegrity=2; five other, non-DC/non-Domain
// GPOs all carry a conflicting, non-compliant value=1. With the DC tier
// present, the DC Policy's value must win regardless of Go's randomized map
// iteration order. Detect() is replayed 5 times against the SAME map
// (Go's map iteration order is randomized per range, not just per process)
// to expose an order-dependent kill.
func TestNetworkSecurity_DCPolicyPrecedenceOverConflictingGPO(t *testing.T) {
	policies := map[string]*audit.GPOPolicy{
		helpers.DefaultDCPolicyGUID: {
			GUID: helpers.DefaultDCPolicyGUID,
			RegistrySettings: &audit.RegistrySettings{
				RequireSMBSigningServer: intp(1),
				RequireSMBSigningClient: intp(1),
				LDAPServerIntegrity:     intp(2),
				LDAPChannelBinding:      intp(2),
			},
		},
		"{AAAAAAAA-0000-0000-0000-000000000001}": conflictingGPO("{AAAAAAAA-0000-0000-0000-000000000001}", 1),
		"{AAAAAAAA-0000-0000-0000-000000000002}": conflictingGPO("{AAAAAAAA-0000-0000-0000-000000000002}", 1),
		"{AAAAAAAA-0000-0000-0000-000000000003}": conflictingGPO("{AAAAAAAA-0000-0000-0000-000000000003}", 1),
		"{AAAAAAAA-0000-0000-0000-000000000004}": conflictingGPO("{AAAAAAAA-0000-0000-0000-000000000004}", 1),
		"{AAAAAAAA-0000-0000-0000-000000000005}": conflictingGPO("{AAAAAAAA-0000-0000-0000-000000000005}", 1),
	}
	data := &audit.DetectorData{GPOPolicies: policies, DomainInfo: &types.DomainInfo{FunctionalLevelInt: 7}}
	for i := 0; i < 5; i++ {
		findings := NewNetworkSecurityDetector().Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Count != 0 {
			t.Fatalf("replay %d: got %+v, want Count=0 (DC Policy LDAPServerIntegrity=2 must take precedence over 5 conflicting non-DC/non-Domain GPOs reporting 1)", i, findings)
		}
	}
}

// TestNetworkSecurity_DomainPolicyPrecedenceOverConflictingGPO kills the
// FindRegistrySettingInt Domain-tier mutation (helpers/gpo_policy.go:143,
// `if false && (ddp != nil ...)`). No DC Policy is present (so the DC tier
// is naturally inert here). The Default Domain Policy (known GUID) carries
// a compliant LDAPServerIntegrity=2; five other, non-DC/non-Domain GPOs all
// carry a conflicting value=1. Replayed 5 times for the same map-order
// sensitivity reason as the DC-tier test above.
func TestNetworkSecurity_DomainPolicyPrecedenceOverConflictingGPO(t *testing.T) {
	policies := map[string]*audit.GPOPolicy{
		helpers.DefaultDomainPolicyGUID: {
			GUID: helpers.DefaultDomainPolicyGUID,
			RegistrySettings: &audit.RegistrySettings{
				RequireSMBSigningServer: intp(1),
				RequireSMBSigningClient: intp(1),
				LDAPServerIntegrity:     intp(2),
				LDAPChannelBinding:      intp(2),
			},
		},
		"{BBBBBBBB-0000-0000-0000-000000000001}": conflictingGPO("{BBBBBBBB-0000-0000-0000-000000000001}", 1),
		"{BBBBBBBB-0000-0000-0000-000000000002}": conflictingGPO("{BBBBBBBB-0000-0000-0000-000000000002}", 1),
		"{BBBBBBBB-0000-0000-0000-000000000003}": conflictingGPO("{BBBBBBBB-0000-0000-0000-000000000003}", 1),
		"{BBBBBBBB-0000-0000-0000-000000000004}": conflictingGPO("{BBBBBBBB-0000-0000-0000-000000000004}", 1),
		"{BBBBBBBB-0000-0000-0000-000000000005}": conflictingGPO("{BBBBBBBB-0000-0000-0000-000000000005}", 1),
	}
	data := &audit.DetectorData{GPOPolicies: policies, DomainInfo: &types.DomainInfo{FunctionalLevelInt: 7}}
	for i := 0; i < 5; i++ {
		findings := NewNetworkSecurityDetector().Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Count != 0 {
			t.Fatalf("replay %d: got %+v, want Count=0 (Domain Policy LDAPServerIntegrity=2 must take precedence over 5 conflicting non-DC/non-Domain GPOs reporting 1)", i, findings)
		}
	}
}
