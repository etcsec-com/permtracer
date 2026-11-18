package kerberos

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestKerberoastingRiskOnDisabledAccount_Tier0Split mirrors
// TestKerberoasting_Tier0Split on the disabled half of the population: a
// disabled Tier 0 admin with SPN lands in a Medium finding (domain-level
// privilege retained per the D1/D2 severity grid), a disabled non-Tier-0
// service account with SPN lands in a Low finding, and an active account is
// excluded regardless of Tier 0 status - it belongs to
// KerberoastingRiskDetector instead.
func TestKerberoastingRiskOnDisabledAccount_Tier0Split(t *testing.T) {
	tier0DN := "CN=alice,OU=Admins,DC=test,DC=local"
	svcDN := "CN=svc,OU=Services,DC=test,DC=local"
	const domainAdminsSID = "S-1-5-21-4004336348-4177238915-4682003330-512"

	cases := []struct {
		name            string
		data            *audit.DetectorData
		wantTier0Count  int
		wantOthersCount int
		wantTier0Sev    types.Severity
		wantOthersSev   types.Severity
	}{
		{
			name: "Disabled Tier 0 admin with SPN → 1 Medium finding only",
			data: &audit.DetectorData{
				Groups: []types.Group{
					{SAMAccountName: "Domain Admins", DN: "CN=DA,DC=test,DC=local", ObjectSID: domainAdminsSID, Members: []string{tier0DN}},
				},
				Users: []types.User{
					{DN: tier0DN, SAMAccountName: "alice", ServicePrincipalNames: []string{"http/web01"}, Disabled: true},
				},
				IncludeDetails: true,
			},
			wantTier0Count: 1,
			wantTier0Sev:   types.SeverityMedium,
		},
		{
			name: "Disabled service account with SPN (non-Tier 0) → 1 Low finding only",
			data: &audit.DetectorData{
				Groups: []types.Group{
					{SAMAccountName: "Domain Admins", DN: "CN=DA,DC=test,DC=local", ObjectSID: domainAdminsSID, Members: nil},
				},
				Users: []types.User{
					{DN: svcDN, SAMAccountName: "svc", ServicePrincipalNames: []string{"http/web01"}, Disabled: true},
				},
			},
			wantOthersCount: 1,
			wantOthersSev:   types.SeverityLow,
		},
		{
			name: "Both Tier 0 and non-Tier 0 disabled → 2 distinct findings",
			data: &audit.DetectorData{
				Groups: []types.Group{
					{SAMAccountName: "Domain Admins", DN: "CN=DA,DC=test,DC=local", ObjectSID: domainAdminsSID, Members: []string{tier0DN}},
				},
				Users: []types.User{
					{DN: tier0DN, SAMAccountName: "alice", ServicePrincipalNames: []string{"http/web01"}, Disabled: true},
					{DN: svcDN, SAMAccountName: "svc", ServicePrincipalNames: []string{"mssql/db01"}, Disabled: true},
				},
			},
			wantTier0Count:  1,
			wantTier0Sev:    types.SeverityMedium,
			wantOthersCount: 1,
			wantOthersSev:   types.SeverityLow,
		},
		{
			name: "No Kerberoastable disabled accounts → no findings",
			data: &audit.DetectorData{
				Users: []types.User{
					{DN: svcDN, SAMAccountName: "svc", Disabled: true}, // no SPN
				},
			},
		},
		{
			name: "Active Tier 0 admin with SPN → excluded, belongs to the active detector",
			data: &audit.DetectorData{
				Groups: []types.Group{
					{SAMAccountName: "Domain Admins", DN: "CN=DA,DC=test,DC=local", ObjectSID: domainAdminsSID, Members: []string{tier0DN}},
				},
				Users: []types.User{
					{DN: tier0DN, SAMAccountName: "alice", ServicePrincipalNames: []string{"http/web01"}, Disabled: false},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := NewKerberoastingRiskOnDisabledAccountDetector()
			findings := d.Detect(context.Background(), tc.data)

			var tier0F, othersF *types.Finding
			for i := range findings {
				if findings[i].Severity == types.SeverityMedium {
					tier0F = &findings[i]
				} else {
					othersF = &findings[i]
				}
			}

			if tc.wantTier0Count == 0 && tier0F != nil {
				t.Errorf("expected no Tier 0 finding, got %+v", tier0F)
			}
			if tc.wantTier0Count > 0 {
				if tier0F == nil {
					t.Errorf("expected Tier 0 finding (count=%d, sev=%s), got nil", tc.wantTier0Count, tc.wantTier0Sev)
				} else if tier0F.Count != tc.wantTier0Count || tier0F.Severity != tc.wantTier0Sev {
					t.Errorf("Tier 0 finding mismatch: got count=%d sev=%s, want count=%d sev=%s",
						tier0F.Count, tier0F.Severity, tc.wantTier0Count, tc.wantTier0Sev)
				}
			}
			if tc.wantOthersCount == 0 && othersF != nil {
				t.Errorf("expected no non-Tier-0 finding, got %+v", othersF)
			}
			if tc.wantOthersCount > 0 {
				if othersF == nil {
					t.Errorf("expected non-Tier-0 finding (count=%d, sev=%s), got nil", tc.wantOthersCount, tc.wantOthersSev)
				} else if othersF.Count != tc.wantOthersCount || othersF.Severity != tc.wantOthersSev {
					t.Errorf("non-Tier-0 finding mismatch: got count=%d sev=%s, want count=%d sev=%s",
						othersF.Count, othersF.Severity, tc.wantOthersCount, tc.wantOthersSev)
				}
			}
		})
	}
}

// TestKerberoastingRiskPartition_ExhaustiveAndDisjoint proves the acceptance
// criterion that both halves of the split share exactly the same
// "Kerberoastable" definition and partition the same population without
// overlap: for a fixed set of Tier 0 accounts carrying a SPN, every account
// lands in exactly one of the two detectors, split only on Disabled, and the
// two AffectedEntities sets are disjoint.
func TestKerberoastingRiskPartition_ExhaustiveAndDisjoint(t *testing.T) {
	tier0DN1 := "CN=alice,OU=Admins,DC=test,DC=local"
	tier0DN2 := "CN=bob,OU=Admins,DC=test,DC=local"
	tier0DN3 := "CN=carol,OU=Admins,DC=test,DC=local"
	const domainAdminsSID = "S-1-5-21-4004336348-4177238915-4682003330-512"
	data := &audit.DetectorData{
		IncludeDetails: true,
		Groups: []types.Group{
			{SAMAccountName: "Domain Admins", DN: "CN=DA,DC=test,DC=local", ObjectSID: domainAdminsSID, Members: []string{tier0DN1, tier0DN2, tier0DN3}},
		},
		Users: []types.User{
			{DN: tier0DN1, SAMAccountName: "enabled-1", ServicePrincipalNames: []string{"http/web01"}, Disabled: false},
			{DN: tier0DN2, SAMAccountName: "enabled-2", ServicePrincipalNames: []string{"http/web02"}, Disabled: false},
			{DN: tier0DN3, SAMAccountName: "disabled-1", ServicePrincipalNames: []string{"http/web03"}, Disabled: true},
		},
	}

	active := NewKerberoastingRiskDetector().Detect(context.Background(), data)
	disabled := NewKerberoastingRiskOnDisabledAccountDetector().Detect(context.Background(), data)

	if len(active) != 1 || active[0].Count != 2 {
		t.Fatalf("active findings = %+v, want 1 finding with count 2", active)
	}
	if len(disabled) != 1 || disabled[0].Count != 1 {
		t.Fatalf("disabled findings = %+v, want 1 finding with count 1", disabled)
	}
	if active[0].Count+disabled[0].Count != len(data.Users) {
		t.Fatalf("partition not exhaustive: active=%d + disabled=%d != total=%d", active[0].Count, disabled[0].Count, len(data.Users))
	}

	seen := map[string]bool{}
	for _, e := range active[0].AffectedEntities {
		seen[e.SAMAccountName] = true
	}
	for _, e := range disabled[0].AffectedEntities {
		if seen[e.SAMAccountName] {
			t.Fatalf("%s appears in both the active and disabled-account finding: partition is not disjoint", e.SAMAccountName)
		}
	}
}
