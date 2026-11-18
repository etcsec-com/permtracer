package obsolete

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func TestObsoleteOS2008OnDisabledAccount_Partition(t *testing.T) {
	tests := []struct {
		name           string
		computer       types.Computer
		wantActive     int
		wantOnDisabled int
	}{
		{
			name:           "active server running Server 2008 fires only the active detector",
			computer:       types.Computer{DN: "CN=SRV01", OperatingSystem: "Windows Server 2008 Standard"},
			wantActive:     1,
			wantOnDisabled: 0,
		},
		{
			name:           "disabled server running Server 2008 fires only the twin",
			computer:       types.Computer{DN: "CN=SRV02", Disabled: true, OperatingSystem: "Windows Server 2008 Standard"},
			wantActive:     0,
			wantOnDisabled: 1,
		},
		{
			name:           "disabled server running Server 2008 R2 fires neither (R2 exclusion)",
			computer:       types.Computer{DN: "CN=SRV03", Disabled: true, OperatingSystem: "Windows Server 2008 R2 Standard"},
			wantActive:     0,
			wantOnDisabled: 0,
		},
		{
			name:           "active server with non-obsolete neighbor OS fires neither",
			computer:       types.Computer{DN: "CN=SRV04", OperatingSystem: "Windows Server 2019"},
			wantActive:     0,
			wantOnDisabled: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &audit.DetectorData{
				Computers: []types.Computer{tt.computer},
			}

			active := NewObsoleteOS2008Detector().Detect(context.Background(), data)
			onDisabled := NewObsoleteOS2008OnDisabledAccountDetector().Detect(context.Background(), data)

			if active[0].Count != tt.wantActive {
				t.Errorf("active count = %d, want %d", active[0].Count, tt.wantActive)
			}
			if onDisabled[0].Count != tt.wantOnDisabled {
				t.Errorf("on-disabled-account count = %d, want %d", onDisabled[0].Count, tt.wantOnDisabled)
			}
		})
	}
}

func TestObsoleteOS2008OnDisabledAccount_Severity(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=SRV05", Disabled: true, OperatingSystem: "Windows Server 2008 Standard"},
		},
	}
	findings := NewObsoleteOS2008OnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityLow {
		t.Errorf("severity = %q, want low", findings[0].Severity)
	}
}
