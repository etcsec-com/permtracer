package other

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func TestPreWindows2000OnDisabledAccount_Partition(t *testing.T) {
	tests := []struct {
		name           string
		computer       types.Computer
		wantActive     int
		wantOnDisabled int
	}{
		{
			name:           "active computer running Windows 95 fires only the active detector",
			computer:       types.Computer{DN: "CN=WKS01", OperatingSystem: "Windows 95"},
			wantActive:     1,
			wantOnDisabled: 0,
		},
		{
			name:           "disabled computer running Windows 98 fires only the twin",
			computer:       types.Computer{DN: "CN=WKS02", Disabled: true, OperatingSystem: "Windows 98"},
			wantActive:     0,
			wantOnDisabled: 1,
		},
		{
			name:           "disabled computer with non-obsolete neighbor OS fires neither",
			computer:       types.Computer{DN: "CN=WKS03", Disabled: true, OperatingSystem: "Windows 10"},
			wantActive:     0,
			wantOnDisabled: 0,
		},
		{
			name:           "active computer with non-obsolete neighbor OS fires neither",
			computer:       types.Computer{DN: "CN=WKS04", OperatingSystem: "Windows 10"},
			wantActive:     0,
			wantOnDisabled: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &audit.DetectorData{
				Computers: []types.Computer{tt.computer},
			}

			active := NewPreWindows2000Detector().Detect(context.Background(), data)
			onDisabled := NewPreWindows2000OnDisabledAccountDetector().Detect(context.Background(), data)

			if active[0].Count != tt.wantActive {
				t.Errorf("active count = %d, want %d", active[0].Count, tt.wantActive)
			}
			if onDisabled[0].Count != tt.wantOnDisabled {
				t.Errorf("on-disabled-account count = %d, want %d", onDisabled[0].Count, tt.wantOnDisabled)
			}
		})
	}
}

func TestPreWindows2000OnDisabledAccount_Severity(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WKS05", Disabled: true, OperatingSystem: "Windows 95"},
		},
	}
	findings := NewPreWindows2000OnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityLow {
		t.Errorf("severity = %q, want low", findings[0].Severity)
	}
}
