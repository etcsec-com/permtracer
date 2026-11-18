package security

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// Kerberoasting a computer account is not practically viable
// (auto-rotated, high-entropy machine password); the prior High severity
// "enables Kerberoasting" claim was noise on nearly every computer with an
// SPN in production.
func TestWithSPNs_NotClaimedAsHighSeverityKerberoasting(t *testing.T) {
	c := types.Computer{DN: "CN=SRV01,DC=example,DC=com", ServicePrincipalNames: []string{"HOST/srv01.example.com"}}
	data := &audit.DetectorData{Computers: []types.Computer{c}}

	findings := NewWithSPNsDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (inventory logic unchanged)", f.Count)
	}
	if f.Severity == types.SeverityHigh {
		t.Fatalf("Severity = %q, want downgraded from High: Kerberoasting a computer account is not practically viable", f.Severity)
	}
}

// TestComputerWithSPNsPartition checks that the active (Info) and
// disabled-account (Info) detectors partition the same population: every
// computer carrying an SPN lands in exactly one of them, or neither, never
// both.
func TestComputerWithSPNsPartition(t *testing.T) {
	cases := []struct {
		name         string
		computer     types.Computer
		wantActive   int
		wantDisabled int
	}{
		{
			name:       "active computer with an SPN fires the active detector only",
			computer:   types.Computer{DN: "CN=SVR01,DC=example,DC=com", ServicePrincipalNames: []string{"HOST/svr01.example.com"}, Disabled: false},
			wantActive: 1, wantDisabled: 0,
		},
		{
			name:       "disabled computer with an SPN fires the disabled-account detector only",
			computer:   types.Computer{DN: "CN=SVR02,DC=example,DC=com", ServicePrincipalNames: []string{"HOST/svr02.example.com"}, Disabled: true},
			wantActive: 0, wantDisabled: 1,
		},
		{
			name:       "active computer without an SPN fires neither",
			computer:   types.Computer{DN: "CN=WKS01,DC=example,DC=com", Disabled: false},
			wantActive: 0, wantDisabled: 0,
		},
		{
			name:       "disabled computer without an SPN fires neither",
			computer:   types.Computer{DN: "CN=WKS02,DC=example,DC=com", Disabled: true},
			wantActive: 0, wantDisabled: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{Computers: []types.Computer{tc.computer}}

			active := NewWithSPNsDetector().Detect(context.Background(), data)
			if active[0].Count != tc.wantActive {
				t.Fatalf("COMPUTER_WITH_SPNS Count = %d, want %d", active[0].Count, tc.wantActive)
			}

			disabled := NewWithSPNsOnDisabledAccountDetector().Detect(context.Background(), data)
			if disabled[0].Count != tc.wantDisabled {
				t.Fatalf("COMPUTER_WITH_SPNS_ON_DISABLED_ACCOUNT Count = %d, want %d", disabled[0].Count, tc.wantDisabled)
			}
		})
	}
}

func TestWithSPNsOnDisabledAccount_SeverityIsInfo(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=SVR02,DC=example,DC=com", SAMAccountName: "SVR02$", ServicePrincipalNames: []string{"HOST/svr02.example.com"}, Disabled: true},
		},
	}
	findings := NewWithSPNsOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Severity != types.SeverityInfo {
		t.Fatalf("Severity = %s, want info", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "SVR02$" {
		t.Fatalf("AffectedEntities = %+v, want only SVR02$", findings[0].AffectedEntities)
	}
}
