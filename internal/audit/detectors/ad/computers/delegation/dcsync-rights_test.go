package delegation

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestDCSyncRights_Fires confirms the detector counts an active computer
// carrying ReplicationRights.
func TestDCSyncRights_Fires(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=SVR01,DC=example,DC=com", SAMAccountName: "SVR01$", ReplicationRights: true},
		},
	}
	findings := NewDCSyncRightsDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityCritical {
		t.Fatalf("Severity = %s, want critical", findings[0].Severity)
	}
}

// TestComputerDCSyncRightsPartition checks that the active (Critical) and
// disabled-account (Medium) detectors partition the same population: every
// computer lands in exactly one of them, or neither, never both.
func TestComputerDCSyncRightsPartition(t *testing.T) {
	cases := []struct {
		name         string
		computer     types.Computer
		wantActive   int
		wantDisabled int
	}{
		{
			name:       "active computer with replication rights fires the active detector only",
			computer:   types.Computer{DN: "CN=SVR01,DC=example,DC=com", ReplicationRights: true, Disabled: false},
			wantActive: 1, wantDisabled: 0,
		},
		{
			name:       "disabled computer with replication rights fires the disabled-account detector only",
			computer:   types.Computer{DN: "CN=SVR02,DC=example,DC=com", ReplicationRights: true, Disabled: true},
			wantActive: 0, wantDisabled: 1,
		},
		{
			name:       "active computer without replication rights fires neither",
			computer:   types.Computer{DN: "CN=WKS01,DC=example,DC=com", Disabled: false},
			wantActive: 0, wantDisabled: 0,
		},
		{
			name:       "disabled computer without replication rights fires neither",
			computer:   types.Computer{DN: "CN=WKS02,DC=example,DC=com", Disabled: true},
			wantActive: 0, wantDisabled: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{Computers: []types.Computer{tc.computer}}

			active := NewDCSyncRightsDetector().Detect(context.Background(), data)
			if active[0].Count != tc.wantActive {
				t.Fatalf("COMPUTER_DCSYNC_RIGHTS Count = %d, want %d", active[0].Count, tc.wantActive)
			}

			disabled := NewDCSyncRightsOnDisabledAccountDetector().Detect(context.Background(), data)
			if disabled[0].Count != tc.wantDisabled {
				t.Fatalf("COMPUTER_DCSYNC_RIGHTS_ON_DISABLED_ACCOUNT Count = %d, want %d", disabled[0].Count, tc.wantDisabled)
			}
		})
	}
}

func TestDCSyncRightsOnDisabledAccount_SeverityIsMedium(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=SVR02,DC=example,DC=com", SAMAccountName: "SVR02$", ReplicationRights: true, Disabled: true},
		},
	}
	findings := NewDCSyncRightsOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Severity != types.SeverityMedium {
		t.Fatalf("Severity = %s, want medium", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "SVR02$" {
		t.Fatalf("AffectedEntities = %+v, want only SVR02$", findings[0].AffectedEntities)
	}
}
