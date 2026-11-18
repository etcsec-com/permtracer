package cis

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestUserRights_ExcessiveAdminGroupMembership_NoLongerFlagged:
// the detector used to flag domains with many Domain/Enterprise/Schema Admins
// against unsourced thresholds (5/2/1) - not a CIS 2.2.x User Rights
// Assignment check at all. Group membership counts, with no PrivilegeRights
// data present, must no longer produce a finding here (that concern belongs
// to other, dedicated privileged-group detectors).
func TestUserRights_ExcessiveAdminGroupMembership_NoLongerFlagged(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: nil}
	findings := NewUserRightsDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("got %+v, want Count=0 (no PrivilegeRights data collected)", findings)
	}
}

// TestUserRights_ActAsPartOfOS_Flagged: CIS 2.2.4 requires "Act
// as part of the operating system" (SeTcbPrivilege) to be granted to no one.
// This real User Rights Assignment signal was previously ignored entirely.
func TestUserRights_ActAsPartOfOS_Flagged(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {PrivilegeRights: &audit.PrivilegeRights{
			SeTcbPrivilege: []string{"S-1-5-21-1-2-3-1105"},
		}},
	}}
	findings := NewUserRightsDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (SeTcbPrivilege granted to a non-empty SID list)", findings)
	}
}

// TestUserRights_DelegationTrust_Flagged: CIS 2.2.29 requires
// "Enable computer and user accounts to be trusted for delegation"
// (SeEnableDelegationPrivilege) to be granted to no one - unconstrained
// delegation is a well-known AD privilege-escalation vector.
func TestUserRights_DelegationTrust_Flagged(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {PrivilegeRights: &audit.PrivilegeRights{
			SeEnableDelegationPrivilege: []string{"S-1-5-21-1-2-3-1105"},
		}},
	}}
	findings := NewUserRightsDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (SeEnableDelegationPrivilege granted to a non-empty SID list)", findings)
	}
}

// TestUserRights_BothEmpty_NoFinding is the regression check for the
// compliant "No One" state on both rights.
func TestUserRights_BothEmpty_NoFinding(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {PrivilegeRights: &audit.PrivilegeRights{}},
	}}
	findings := NewUserRightsDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("got %+v, want Count=0", findings)
	}
}

// TestUserRights_SeverityIsHigh pins the finding's severity to High: a CIS
// 2.2.4/2.2.29 user-rights misconfiguration is a direct privilege-escalation
// and lateral-movement path, not a medium-severity concern.
func TestUserRights_SeverityIsHigh(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {PrivilegeRights: &audit.PrivilegeRights{
			SeTcbPrivilege: []string{"S-1-5-21-1-2-3-4001"},
		}},
	}}
	findings := NewUserRightsDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Fatalf("Severity = %q, want %q", findings[0].Severity, types.SeverityHigh)
	}
}

// TestUserRights_ActAsPartOfOS_DetailsIsolatedFromDelegation exercises the
// SeTcbPrivilege-only case end to end: the CIS 2.2.4 SIDs must land in
// actAsPartOfOSGrantedTo (and nowhere else), delegationTrustGrantedTo must
// stay empty, and the 2.2.4 violation label - not the 2.2.29 one - must be
// the one recorded.
func TestUserRights_ActAsPartOfOS_DetailsIsolatedFromDelegation(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {PrivilegeRights: &audit.PrivilegeRights{
			SeTcbPrivilege: []string{"S-1-5-21-1-2-3-4001"},
		}},
	}}
	findings := NewUserRightsDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	d := findings[0].Details

	tcb, _ := d["actAsPartOfOSGrantedTo"].([]string)
	if len(tcb) != 1 || tcb[0] != "S-1-5-21-1-2-3-4001" {
		t.Fatalf("actAsPartOfOSGrantedTo = %v, want [S-1-5-21-1-2-3-4001]", tcb)
	}
	delegation, _ := d["delegationTrustGrantedTo"].([]string)
	if len(delegation) != 0 {
		t.Fatalf("delegationTrustGrantedTo = %v, want empty", delegation)
	}

	violations, _ := d["violations"].([]string)
	want := "CIS 2.2.4: 'Act as part of the operating system' is not set to 'No One'"
	if len(violations) != 1 || violations[0] != want {
		t.Fatalf("violations = %v, want [%q]", violations, want)
	}
}

// TestUserRights_DelegationTrust_DetailsIsolatedFromActAsPartOfOS mirrors the
// test above for SeEnableDelegationPrivilege alone: the CIS 2.2.29 SIDs must
// land in delegationTrustGrantedTo (and nowhere else), actAsPartOfOSGrantedTo
// must stay empty, and the 2.2.29 violation label - not the 2.2.4 one - must
// be the one recorded.
func TestUserRights_DelegationTrust_DetailsIsolatedFromActAsPartOfOS(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {PrivilegeRights: &audit.PrivilegeRights{
			SeEnableDelegationPrivilege: []string{"S-1-5-21-1-2-3-4002"},
		}},
	}}
	findings := NewUserRightsDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	d := findings[0].Details

	delegation, _ := d["delegationTrustGrantedTo"].([]string)
	if len(delegation) != 1 || delegation[0] != "S-1-5-21-1-2-3-4002" {
		t.Fatalf("delegationTrustGrantedTo = %v, want [S-1-5-21-1-2-3-4002]", delegation)
	}
	tcb, _ := d["actAsPartOfOSGrantedTo"].([]string)
	if len(tcb) != 0 {
		t.Fatalf("actAsPartOfOSGrantedTo = %v, want empty", tcb)
	}

	violations, _ := d["violations"].([]string)
	want := "CIS 2.2.29: 'Enable computer and user accounts to be trusted for delegation' is not set to 'No One'"
	if len(violations) != 1 || violations[0] != want {
		t.Fatalf("violations = %v, want [%q]", violations, want)
	}
}

// TestUserRights_Compliant_NoViolationsKeyInDetails confirms that when both
// rights are empty (compliant), Details carries no "violations" key at all -
// not even an empty one - since the detector only populates it inside the
// len(issues) > 0 branch.
func TestUserRights_Compliant_NoViolationsKeyInDetails(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {PrivilegeRights: &audit.PrivilegeRights{}},
	}}
	findings := NewUserRightsDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if v, exists := findings[0].Details["violations"]; exists {
		t.Fatalf("Details[\"violations\"] = %v, want key absent", v)
	}
}

// TestUserRights_NilAndMissingPrivilegeRightsDoNotPanic exercises the loop's
// nil guards with a nil *GPOPolicy entry and a GPOPolicy with a nil
// PrivilegeRights - both real shapes for GPOs without a [Privilege Rights]
// section - alongside one real entry, confirming no panic and that only the
// real entry is counted.
func TestUserRights_NilAndMissingPrivilegeRightsDoNotPanic(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{nil-policy}":     nil,
		"{no-priv-rights}": {PrivilegeRights: nil},
		"{real}": {PrivilegeRights: &audit.PrivilegeRights{
			SeTcbPrivilege: []string{"S-1-5-21-1-2-3-4003"},
		}},
	}}
	findings := NewUserRightsDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (only the real entry contributes)", findings)
	}
}
