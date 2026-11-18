package status

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func TestStaleInactive_PrefersReplicatedTimestamp(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	staleTime := now.AddDate(0, 0, -120)
	recentTime := now.AddDate(0, 0, -5)

	t.Run("stale LastLogonTimestamp fires even with a recent per-DC LastLogon", func(t *testing.T) {
		// LastLogon is per-DC and never replicated: a recent value on the
		// queried DC does not mean the computer is actually active domain-wide.
		// LastLogonTimestamp (replicated) must take priority.
		data := &audit.DetectorData{
			Now: now,
			Computers: []types.Computer{
				{DN: "CN=WS-05,OU=Workstations,DC=example,DC=com", LastLogonTimestamp: staleTime, LastLogon: recentTime},
			},
		}
		findings := NewStaleInactiveDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 1 {
			t.Fatalf("stale replicated timestamp must fire even with a fresh per-DC value, got count=%d", findings[0].Count)
		}
	})

	t.Run("recent LastLogonTimestamp does not fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Now: now,
			Computers: []types.Computer{
				{DN: "CN=WS-06,OU=Workstations,DC=example,DC=com", LastLogonTimestamp: recentTime, LastLogon: staleTime},
			},
		}
		findings := NewStaleInactiveDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 0 {
			t.Fatalf("a recent replicated timestamp means the computer is active, got count=%d", findings[0].Count)
		}
	})

	t.Run("falls back to LastLogon when LastLogonTimestamp was never populated", func(t *testing.T) {
		data := &audit.DetectorData{
			Now: now,
			Computers: []types.Computer{
				{DN: "CN=WS-07,OU=Workstations,DC=example,DC=com", LastLogon: staleTime},
			},
		}
		findings := NewStaleInactiveDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 1 {
			t.Fatalf("stale LastLogon fallback must still fire, got count=%d", findings[0].Count)
		}
	})
}

func TestStaleInactive_Threshold(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	t.Run("91 days inactive is counted as stale", func(t *testing.T) {
		data := &audit.DetectorData{
			Now: now,
			Computers: []types.Computer{
				{DN: "CN=WS-10,OU=Workstations,DC=example,DC=com", LastLogonTimestamp: now.AddDate(0, 0, -91)},
			},
		}
		findings := NewStaleInactiveDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 1 {
			t.Fatalf("91 days inactive must cross the 90-day threshold, got count=%d", findings[0].Count)
		}
	})

	t.Run("89 days inactive is not counted as stale", func(t *testing.T) {
		data := &audit.DetectorData{
			Now: now,
			Computers: []types.Computer{
				{DN: "CN=WS-11,OU=Workstations,DC=example,DC=com", LastLogonTimestamp: now.AddDate(0, 0, -89)},
			},
		}
		findings := NewStaleInactiveDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 0 {
			t.Fatalf("89 days inactive must not cross the 90-day threshold, got count=%d", findings[0].Count)
		}
	})
}

func TestStaleInactive_DisabledComputerNotCounted(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	data := &audit.DetectorData{
		Now: now,
		Computers: []types.Computer{
			{DN: "CN=WS-12,OU=Workstations,DC=example,DC=com", Disabled: true, LastLogonTimestamp: now.AddDate(0, 0, -120)},
		},
	}
	findings := NewStaleInactiveDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("a disabled computer must not be counted even when inactive for 120 days, got count=%d", findings[0].Count)
	}
}

func TestStaleInactive_NoTimestampsNotCounted(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	data := &audit.DetectorData{
		Now: now,
		Computers: []types.Computer{
			{DN: "CN=WS-13,OU=Workstations,DC=example,DC=com"},
		},
	}
	findings := NewStaleInactiveDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("a computer with neither LastLogonTimestamp nor LastLogon must not be counted, got count=%d", findings[0].Count)
	}
}
