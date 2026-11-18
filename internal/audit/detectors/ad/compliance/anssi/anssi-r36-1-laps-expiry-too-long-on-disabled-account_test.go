package anssi

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func TestR361LAPSExpiryOnDisabledAccount_DisabledComputerStale_Counted(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Computers: []types.Computer{
			{
				DistinguishedName:  "CN=WKS08,OU=Computers,DC=example,DC=com",
				SAMAccountName:     "WKS08$",
				Disabled:           true,
				LAPSPasswordExpiry: now.AddDate(0, 0, 90),
			},
		},
	}
	findings := NewR361LAPSExpiryOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityLow {
		t.Errorf("Severity = %v, want Low", findings[0].Severity)
	}
}

func TestR361LAPSExpiryOnDisabledAccount_EnabledComputerStale_NotCounted(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Computers: []types.Computer{
			{
				DistinguishedName:  "CN=WKS09,OU=Computers,DC=example,DC=com",
				SAMAccountName:     "WKS09$",
				LAPSPasswordExpiry: now.AddDate(0, 0, 90),
			},
		},
	}
	findings := NewR361LAPSExpiryOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding for an enabled computer, got %+v", findings)
	}
}

// TestR361LAPSExpiryPartition_ActiveAndDisabledSumToTotal proves the split:
// every stale computer lands in exactly one of the active or disabled
// finding's Count, never both and never neither. WKS13 is within the
// benchmark (fresh) and must be excluded from both populations.
func TestR361LAPSExpiryPartition_ActiveAndDisabledSumToTotal(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	computers := []types.Computer{
		{DistinguishedName: "CN=WKS10,OU=Computers,DC=example,DC=com", SAMAccountName: "WKS10$", LAPSPasswordExpiry: now.AddDate(0, 0, 90)},
		{DistinguishedName: "CN=WKS11,OU=Computers,DC=example,DC=com", SAMAccountName: "WKS11$", Disabled: true, LAPSPasswordExpiry: now.AddDate(0, 0, 90)},
		{DistinguishedName: "CN=WKS12,OU=Computers,DC=example,DC=com", SAMAccountName: "WKS12$", Disabled: true, LAPSPasswordExpiry: now.AddDate(0, 0, 45)},
		{DistinguishedName: "CN=WKS13,OU=Computers,DC=example,DC=com", SAMAccountName: "WKS13$", LAPSPasswordExpiry: now.AddDate(0, 0, 15)},
	}
	data := &audit.DetectorData{Now: now, Computers: computers}

	activeFindings := NewR361LAPSExpiryDetector().Detect(context.Background(), data)
	disabledFindings := NewR361LAPSExpiryOnDisabledAccountDetector().Detect(context.Background(), data)

	activeCount := 0
	if len(activeFindings) == 1 {
		activeCount = activeFindings[0].Count
	}
	disabledCount := 0
	if len(disabledFindings) == 1 {
		disabledCount = disabledFindings[0].Count
	}

	const wantStaleTotal = 3 // WKS10, WKS11, WKS12 are stale; WKS13 is fresh, excluded from both
	if activeCount+disabledCount != wantStaleTotal {
		t.Errorf("active(%d) + disabled(%d) = %d, want %d", activeCount, disabledCount, activeCount+disabledCount, wantStaleTotal)
	}
	if activeCount != 1 {
		t.Errorf("active Count = %d, want 1", activeCount)
	}
	if disabledCount != 2 {
		t.Errorf("disabled Count = %d, want 2", disabledCount)
	}
}

// TestR361LAPSExpiryOnDisabledAccount_ExpiryExactlyAtThreshold_NotCounted
// pins the exclusive boundary of the threshold comparison on the disabled
// twin: an expiry exactly lapsMaxExpiryDaysBenchmark days out is not past
// the benchmark and must not be counted.
func TestR361LAPSExpiryOnDisabledAccount_ExpiryExactlyAtThreshold_NotCounted(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Computers: []types.Computer{
			{
				DistinguishedName:  "CN=WKS17,OU=Computers,DC=example,DC=com",
				SAMAccountName:     "WKS17$",
				Disabled:           true,
				LAPSPasswordExpiry: now.AddDate(0, 0, 30),
			},
		},
	}
	findings := NewR361LAPSExpiryOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding for an expiry exactly at the threshold, got %+v", findings)
	}
}

// TestR361LAPSExpiryOnDisabledAccount_ExpiryOneSecondPastThreshold_Counted
// pins the boundary one second past the threshold on the disabled twin: it
// must be counted.
func TestR361LAPSExpiryOnDisabledAccount_ExpiryOneSecondPastThreshold_Counted(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Computers: []types.Computer{
			{
				DistinguishedName:  "CN=WKS18,OU=Computers,DC=example,DC=com",
				SAMAccountName:     "WKS18$",
				Disabled:           true,
				LAPSPasswordExpiry: now.AddDate(0, 0, 30).Add(time.Second),
			},
		},
	}
	findings := NewR361LAPSExpiryOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1", findings[0].Count)
	}
}

// TestR361LAPSExpiryOnDisabledAccount_ExpiryHalfDayPastThreshold_Counted
// pins a second point past the threshold on the disabled twin, twelve hours
// in: it must also be counted.
func TestR361LAPSExpiryOnDisabledAccount_ExpiryHalfDayPastThreshold_Counted(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Computers: []types.Computer{
			{
				DistinguishedName:  "CN=WKS19,OU=Computers,DC=example,DC=com",
				SAMAccountName:     "WKS19$",
				Disabled:           true,
				LAPSPasswordExpiry: now.AddDate(0, 0, 30).Add(12 * time.Hour),
			},
		},
	}
	findings := NewR361LAPSExpiryOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1", findings[0].Count)
	}
}

