package obsolete

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func TestObsoleteOSNTOnDisabledAccount_Partition(t *testing.T) {
	tests := []struct {
		name           string
		computer       types.Computer
		wantActive     int
		wantOnDisabled int
	}{
		{
			name:           "active computer running Windows NT 4.0 fires only the active detector",
			computer:       types.Computer{DN: "CN=WKS01", OperatingSystem: "Windows NT 4.0 Workstation"},
			wantActive:     1,
			wantOnDisabled: 0,
		},
		{
			name:           "disabled computer running Windows NT 4.0 fires only the twin",
			computer:       types.Computer{DN: "CN=WKS02", Disabled: true, OperatingSystem: "Windows NT 4.0 Workstation"},
			wantActive:     0,
			wantOnDisabled: 1,
		},
		{
			name:           "disabled computer running Windows 2000 fires only the twin",
			computer:       types.Computer{DN: "CN=WKS03", Disabled: true, OperatingSystem: "Windows 2000 Professional"},
			wantActive:     0,
			wantOnDisabled: 1,
		},
		{
			name:           "disabled computer with non-obsolete neighbor OS fires neither",
			computer:       types.Computer{DN: "CN=WKS04", Disabled: true, OperatingSystem: "Windows 10"},
			wantActive:     0,
			wantOnDisabled: 0,
		},
		{
			name:           "active computer with non-obsolete neighbor OS fires neither",
			computer:       types.Computer{DN: "CN=WKS05", OperatingSystem: "Windows 10"},
			wantActive:     0,
			wantOnDisabled: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &audit.DetectorData{
				Computers: []types.Computer{tt.computer},
			}

			active := NewObsoleteOSNTDetector().Detect(context.Background(), data)
			onDisabled := NewObsoleteOSNTOnDisabledAccountDetector().Detect(context.Background(), data)

			if active[0].Count != tt.wantActive {
				t.Errorf("active count = %d, want %d", active[0].Count, tt.wantActive)
			}
			if onDisabled[0].Count != tt.wantOnDisabled {
				t.Errorf("on-disabled-account count = %d, want %d", onDisabled[0].Count, tt.wantOnDisabled)
			}
		})
	}
}

func TestObsoleteOSNTOnDisabledAccount_Severity(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WKS06", Disabled: true, OperatingSystem: "Windows NT 4.0 Workstation"},
		},
	}
	findings := NewObsoleteOSNTOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityLow {
		t.Errorf("severity = %q, want low", findings[0].Severity)
	}
}
