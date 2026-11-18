package delegation

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestComputerConstrainedDelegationPartition checks that the active (Critical)
// and disabled-account (Low) detectors partition the same population: every
// computer lands in exactly one of them, or neither, never both.
func TestComputerConstrainedDelegationPartition(t *testing.T) {
	cases := []struct {
		name         string
		computer     types.Computer
		wantActive   int
		wantDisabled int
	}{
		{
			name:     "active computer with the attribute fires the active detector only",
			computer: types.Computer{DN: "CN=SVR01,OU=Servers,DC=example,DC=com", SAMAccountName: "SVR01$", AllowedToDelegateTo: []string{"host/target.example.com"}, Disabled: false},
			wantActive: 1, wantDisabled: 0,
		},
		{
			name:     "disabled computer with the attribute fires the disabled-account detector only",
			computer: types.Computer{DN: "CN=SVR02,OU=Servers,DC=example,DC=com", SAMAccountName: "SVR02$", AllowedToDelegateTo: []string{"host/target.example.com"}, Disabled: true},
			wantActive: 0, wantDisabled: 1,
		},
		{
			name:     "active computer without the attribute fires neither",
			computer: types.Computer{DN: "CN=WKS01,OU=Workstations,DC=example,DC=com", SAMAccountName: "WKS01$", Disabled: false},
			wantActive: 0, wantDisabled: 0,
		},
		{
			name:     "disabled computer without the attribute fires neither",
			computer: types.Computer{DN: "CN=WKS02,OU=Workstations,DC=example,DC=com", SAMAccountName: "WKS02$", Disabled: true},
			wantActive: 0, wantDisabled: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{Computers: []types.Computer{tc.computer}}

			active := NewConstrainedDelegationDetector().Detect(context.Background(), data)
			if active[0].Count != tc.wantActive {
				t.Fatalf("COMPUTER_CONSTRAINED_DELEGATION Count = %d, want %d", active[0].Count, tc.wantActive)
			}

			disabled := NewConstrainedDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
			if disabled[0].Count != tc.wantDisabled {
				t.Fatalf("COMPUTER_CONSTRAINED_DELEGATION_ON_DISABLED_ACCOUNT Count = %d, want %d", disabled[0].Count, tc.wantDisabled)
			}
		})
	}
}

func TestConstrainedDelegationOnDisabledAccount_SeverityIsLow(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=SVR02,OU=Servers,DC=example,DC=com", SAMAccountName: "SVR02$", AllowedToDelegateTo: []string{"host/target.example.com"}, Disabled: true},
		},
	}
	findings := NewConstrainedDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Severity != types.SeverityLow {
		t.Fatalf("Severity = %s, want low", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "SVR02$" {
		t.Fatalf("AffectedEntities = %+v, want only SVR02$", findings[0].AffectedEntities)
	}
}
