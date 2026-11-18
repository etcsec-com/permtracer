package gpo

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// Microsoft Learn, "Configure Credential Guard" (GPO tab): the "Turn On
// Virtualization Based Security" policy sets
// DeviceGuard\EnableVirtualizationBasedSecurity (the VBS prerequisite),
// while its nested "Credential Guard Configuration" dropdown is what
// actually writes Lsa\LsaCfgFlags to 1 ("Enabled with UEFI lock") or 2
// ("Enabled without lock"). Both must be set together - VBS on its own
// only prepares the platform, it does not turn Credential Guard on.
//
// The detector previously only read CredentialGuardEnabled (the VBS
// switch) and reported Credential Guard as enabled whenever VBS alone was
// on. This test's "VBS on, LsaCfgFlags unset" case fails against that old
// code (Count=0, a false negative: VBS-only is not Credential Guard) and
// passes once the detector also requires LsaCfgFlags to be 1 or 2.
func TestCredentialGuard_RequiresBothVBSAndLsaCfgFlags(t *testing.T) {
	one := 1
	two := 2

	cases := []struct {
		name        string
		vbs         *int
		lsaCfgFlags *int
		wantCount   int
	}{
		{"VBS on, LsaCfgFlags unset -> not real Credential Guard", &one, nil, 1},
		{"VBS on, LsaCfgFlags=1 (UEFI lock) -> enabled", &one, &one, 0},
		{"VBS on, LsaCfgFlags=2 (no lock) -> enabled", &one, &two, 0},
		{"VBS unset, LsaCfgFlags=1 -> not enabled", nil, &one, 1},
		{"both unset -> not enabled", nil, nil, 1},
		{"VBS on, LsaCfgFlags=0 (explicitly off) -> not enabled", &one, func() *int { z := 0; return &z }(), 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{
				GPOPolicies: map[string]*audit.GPOPolicy{
					"GUID": {
						RegistrySettings: &audit.RegistrySettings{
							CredentialGuardEnabled: tc.vbs,
							LsaCfgFlags:            tc.lsaCfgFlags,
						},
					},
				},
			}

			findings := NewCredentialGuardDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding, got %d", len(findings))
			}
			if findings[0].Count != tc.wantCount {
				t.Fatalf("Count = %d, want %d", findings[0].Count, tc.wantCount)
			}
		})
	}
}

// TestCredentialGuard_SeverityIsMedium pins the finding's Severity. Nothing
// else in this package asserts on it, so a change to Severity went
// undetected before this test.
func TestCredentialGuard_SeverityIsMedium(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"GUID": {RegistrySettings: &audit.RegistrySettings{}},
		},
	}

	findings := NewCredentialGuardDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityMedium {
		t.Fatalf("Severity = %q, want %q", findings[0].Severity, types.SeverityMedium)
	}
}

// TestCredentialGuard_DetailsReflectVBSOnlyState pins Details.vbsEnabled and
// Details.credentialGuardConfigured in the "VBS only" state (VBS set,
// LsaCfgFlags unset): vbsEnabled must read true and credentialGuardConfigured
// must read false. Nothing else in this package reads Details.
func TestCredentialGuard_DetailsReflectVBSOnlyState(t *testing.T) {
	one := 1
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"GUID": {
				RegistrySettings: &audit.RegistrySettings{
					CredentialGuardEnabled: &one,
					LsaCfgFlags:            nil,
				},
			},
		},
	}

	findings := NewCredentialGuardDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	details := findings[0].Details
	if details == nil {
		t.Fatal("expected Details to be populated")
	}
	if got := details["vbsEnabled"]; got != true {
		t.Fatalf("Details[\"vbsEnabled\"] = %v, want true", got)
	}
	if got := details["credentialGuardConfigured"]; got != false {
		t.Fatalf("Details[\"credentialGuardConfigured\"] = %v, want false", got)
	}
}

// TestCredentialGuard_DetailsReflectLsaCfgFlagsOnlyState pins the opposite
// state (LsaCfgFlags set, VBS unset): vbsEnabled must read false and
// credentialGuardConfigured must read true.
func TestCredentialGuard_DetailsReflectLsaCfgFlagsOnlyState(t *testing.T) {
	one := 1
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"GUID": {
				RegistrySettings: &audit.RegistrySettings{
					CredentialGuardEnabled: nil,
					LsaCfgFlags:            &one,
				},
			},
		},
	}

	findings := NewCredentialGuardDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	details := findings[0].Details
	if details == nil {
		t.Fatal("expected Details to be populated")
	}
	if got := details["vbsEnabled"]; got != false {
		t.Fatalf("Details[\"vbsEnabled\"] = %v, want false", got)
	}
	if got := details["credentialGuardConfigured"]; got != true {
		t.Fatalf("Details[\"credentialGuardConfigured\"] = %v, want true", got)
	}
}
