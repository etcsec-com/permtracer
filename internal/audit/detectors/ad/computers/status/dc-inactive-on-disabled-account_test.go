package status

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func TestDCInactiveOnDisabledAccount_Partition(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name           string
		dc             types.Computer
		wantActive     int
		wantOnDisabled int
	}{
		{
			name:           "active DC inactive 60 days fires only the active detector",
			dc:             types.Computer{DN: "CN=DC01", LastLogonTimestamp: now.AddDate(0, 0, -60)},
			wantActive:     1,
			wantOnDisabled: 0,
		},
		{
			name:           "disabled DC inactive 60 days fires only the twin",
			dc:             types.Computer{DN: "CN=DC02", Disabled: true, LastLogonTimestamp: now.AddDate(0, 0, -60)},
			wantActive:     0,
			wantOnDisabled: 1,
		},
		{
			name:           "disabled DC never logged on fires only the twin",
			dc:             types.Computer{DN: "CN=DC03", Disabled: true},
			wantActive:     0,
			wantOnDisabled: 1,
		},
		{
			name:           "recent active DC fires neither",
			dc:             types.Computer{DN: "CN=DC04", LastLogonTimestamp: now.AddDate(0, 0, -10)},
			wantActive:     0,
			wantOnDisabled: 0,
		},
		{
			name:           "recent disabled DC fires neither",
			dc:             types.Computer{DN: "CN=DC05", Disabled: true, LastLogonTimestamp: now.AddDate(0, 0, -10)},
			wantActive:     0,
			wantOnDisabled: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &audit.DetectorData{
				Now:               now,
				DomainControllers: []types.Computer{tt.dc},
			}

			active := NewDCInactiveDetector().Detect(context.Background(), data)
			onDisabled := NewDCInactiveOnDisabledAccountDetector().Detect(context.Background(), data)

			if active[0].Count != tt.wantActive {
				t.Errorf("active count = %d, want %d", active[0].Count, tt.wantActive)
			}
			if onDisabled[0].Count != tt.wantOnDisabled {
				t.Errorf("on-disabled-account count = %d, want %d", onDisabled[0].Count, tt.wantOnDisabled)
			}
		})
	}
}

func TestDCInactiveOnDisabledAccount_Severity(t *testing.T) {
	data := &audit.DetectorData{
		Now: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		DomainControllers: []types.Computer{
			{DN: "CN=DC06", Disabled: true, LastLogonTimestamp: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, -60)},
		},
	}
	findings := NewDCInactiveOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityMedium {
		t.Errorf("severity = %q, want medium", findings[0].Severity)
	}
}

func TestDCInactiveOnDisabledAccount_FortyDayThreshold(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	t.Run("40 days inactive (disabled DC) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Now: now,
			DomainControllers: []types.Computer{
				{DN: "CN=DC11", Disabled: true, LastLogonTimestamp: now.AddDate(0, 0, -40)},
			},
		}
		findings := NewDCInactiveOnDisabledAccountDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 0 {
			t.Fatalf("40 days is within the 45-day threshold, got count=%d", findings[0].Count)
		}
	})
}

func TestDCInactiveOnDisabledAccount_LastLogonFallback(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	t.Run("zero LastLogonTimestamp, LastLogon 60 days old (disabled DC) DOES fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Now: now,
			DomainControllers: []types.Computer{
				{DN: "CN=DC12", Disabled: true, LastLogon: now.AddDate(0, 0, -60)},
			},
		}
		findings := NewDCInactiveOnDisabledAccountDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 1 {
			t.Fatalf("zero LastLogonTimestamp must fall back to a 60-day-old LastLogon and fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("zero LastLogonTimestamp, LastLogon 5 days old (disabled DC) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Now: now,
			DomainControllers: []types.Computer{
				{DN: "CN=DC13", Disabled: true, LastLogon: now.AddDate(0, 0, -5)},
			},
		}
		findings := NewDCInactiveOnDisabledAccountDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 0 {
			t.Fatalf("zero LastLogonTimestamp must fall back to a recent 5-day-old LastLogon and NOT fire, got count=%d", findings[0].Count)
		}
	})
}

func TestDCInactiveOnDisabledAccount_CountMatchesAffectedEntitiesLength(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now:            now,
		IncludeDetails: true,
		DomainControllers: []types.Computer{
			{DN: "CN=DC07", Disabled: true, LastLogonTimestamp: now.AddDate(0, 0, -60)},
			{DN: "CN=DC08", Disabled: true, LastLogonTimestamp: now.AddDate(0, 0, -10)},
			{DN: "CN=DC09", Disabled: true},
			{DN: "CN=DC10", LastLogonTimestamp: now.AddDate(0, 0, -60)},
		},
	}
	findings := NewDCInactiveOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 2 {
		t.Fatalf("expected count=2 (DC07 and DC09), got %d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != findings[0].Count {
		t.Fatalf("AffectedEntities length %d must match Count %d", len(findings[0].AffectedEntities), findings[0].Count)
	}
}
