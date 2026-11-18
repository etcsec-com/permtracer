package security

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestComputerNoLaps_CriticalWhenNoActiveComputerUsesLAPS confirms the
// Critical branch fires, with its exact title, when no active non-DC
// computer carries a LAPS attribute.
func TestComputerNoLaps_CriticalWhenNoActiveComputerUsesLAPS(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WKS01,DC=example,DC=com", SAMAccountName: "WKS01$", Disabled: false},
			{DN: "CN=WKS02,DC=example,DC=com", SAMAccountName: "WKS02$", Disabled: false},
		},
	}
	findings := NewNoLapsDetector().Detect(context.Background(), data)
	if findings[0].Severity != types.SeverityCritical {
		t.Fatalf("Severity = %s, want critical", findings[0].Severity)
	}
	if findings[0].Title != "LAPS Not Deployed (No Active Computer Uses LAPS)" {
		t.Fatalf("Title = %q, want %q", findings[0].Title, "LAPS Not Deployed (No Active Computer Uses LAPS)")
	}
	if findings[0].Count != 2 {
		t.Fatalf("Count = %d, want 2", findings[0].Count)
	}
}

// TestComputerNoLaps_HighWhenOneActiveComputerUsesLegacyLAPS confirms the
// High branch fires when at least one active computer uses legacy LAPS,
// even though another active computer still lacks it.
func TestComputerNoLaps_HighWhenOneActiveComputerUsesLegacyLAPS(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WKS01,DC=example,DC=com", SAMAccountName: "WKS01$", Disabled: false},
			{DN: "CN=WKS02,DC=example,DC=com", SAMAccountName: "WKS02$", Disabled: false, HasLegacyLAPS: true},
		},
	}
	findings := NewNoLapsDetector().Detect(context.Background(), data)
	if findings[0].Severity != types.SeverityHigh {
		t.Fatalf("Severity = %s, want high", findings[0].Severity)
	}
	if findings[0].Title != "Computer No LAPS" {
		t.Fatalf("Title = %q, want %q", findings[0].Title, "Computer No LAPS")
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
}

// TestComputerNoLaps_HighWhenOneActiveComputerUsesWindowsLAPS confirms the
// High branch fires when at least one active computer uses Windows LAPS,
// even though another active computer still lacks it.
func TestComputerNoLaps_HighWhenOneActiveComputerUsesWindowsLAPS(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WKS01,DC=example,DC=com", SAMAccountName: "WKS01$", Disabled: false},
			{DN: "CN=WKS02,DC=example,DC=com", SAMAccountName: "WKS02$", Disabled: false, HasWindowsLAPS: true},
		},
	}
	findings := NewNoLapsDetector().Detect(context.Background(), data)
	if findings[0].Severity != types.SeverityHigh {
		t.Fatalf("Severity = %s, want high", findings[0].Severity)
	}
	if findings[0].Title != "Computer No LAPS" {
		t.Fatalf("Title = %q, want %q", findings[0].Title, "Computer No LAPS")
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
}
