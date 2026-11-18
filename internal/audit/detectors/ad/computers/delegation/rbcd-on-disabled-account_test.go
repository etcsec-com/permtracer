package delegation

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestComputerRbcdPartition checks that the active (Critical) and
// disabled-account (Medium) detectors partition the same population: every
// computer lands in exactly one of them, or neither, never both.
func TestComputerRbcdPartition(t *testing.T) {
	cases := []struct {
		name         string
		computer     types.Computer
		wantActive   int
		wantDisabled int
	}{
		{
			name:       "active computer with a non-empty security descriptor fires the active detector only",
			computer:   types.Computer{DN: "CN=SVR01,DC=example,DC=com", AllowedToActOnBehalfOfOtherIdentity: rbcdNonEmptySD, Disabled: false},
			wantActive: 1, wantDisabled: 0,
		},
		{
			name:       "disabled computer with a non-empty security descriptor fires the disabled-account detector only",
			computer:   types.Computer{DN: "CN=SVR02,DC=example,DC=com", AllowedToActOnBehalfOfOtherIdentity: rbcdNonEmptySD, Disabled: true},
			wantActive: 0, wantDisabled: 1,
		},
		{
			name:       "active computer with no security descriptor fires neither",
			computer:   types.Computer{DN: "CN=WKS01,DC=example,DC=com", Disabled: false},
			wantActive: 0, wantDisabled: 0,
		},
		{
			name:       "disabled computer with no security descriptor fires neither",
			computer:   types.Computer{DN: "CN=WKS02,DC=example,DC=com", Disabled: true},
			wantActive: 0, wantDisabled: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{Computers: []types.Computer{tc.computer}}

			active := NewRbcdDetector().Detect(context.Background(), data)
			if active[0].Count != tc.wantActive {
				t.Fatalf("COMPUTER_RBCD Count = %d, want %d", active[0].Count, tc.wantActive)
			}

			disabled := NewRbcdOnDisabledAccountDetector().Detect(context.Background(), data)
			if disabled[0].Count != tc.wantDisabled {
				t.Fatalf("COMPUTER_RBCD_ON_DISABLED_ACCOUNT Count = %d, want %d", disabled[0].Count, tc.wantDisabled)
			}
		})
	}
}

func TestRbcdOnDisabledAccount_SeverityIsMedium(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=SVR02,DC=example,DC=com", SAMAccountName: "SVR02$", AllowedToActOnBehalfOfOtherIdentity: rbcdNonEmptySD, Disabled: true},
		},
	}
	findings := NewRbcdOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Severity != types.SeverityMedium {
		t.Fatalf("Severity = %s, want medium", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "SVR02$" {
		t.Fatalf("AffectedEntities = %+v, want only SVR02$", findings[0].AffectedEntities)
	}
}
