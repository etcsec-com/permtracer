package anssi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// this detector's finding previously claimed "ANSSI R36.1 (sub-reco)
// requires LAPS password rotations no more than 30 days apart". PA-099 has
// no dotted sub-recommendation numbering at all, and R36 is about CA/PKI
// risk, not LAPS. The real, verified source is R30 (p.48), which requires
// automatic local-admin-password rotation but specifies no day threshold.
func TestR361LAPSExpiry_Detect(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	staleComputer := types.Computer{
		SAMAccountName:     "WKS01$",
		LAPSPasswordExpiry: now.AddDate(0, 0, 45), // 45 days out - beyond the 30-day benchmark
	}
	freshComputer := types.Computer{
		SAMAccountName:     "WKS02$",
		LAPSPasswordExpiry: now.AddDate(0, 0, 10), // within benchmark
	}
	outOfScopeComputer := types.Computer{
		SAMAccountName: "WKS03$", // no LAPS expiry set - not managed by LAPS
	}

	cases := []struct {
		name      string
		computers []types.Computer
		wantCount int
	}{
		{"no computers -> no finding", nil, 0},
		{"fresh LAPS expiry -> clean", []types.Computer{freshComputer}, 0},
		{"computer outside LAPS scope -> not flagged", []types.Computer{outOfScopeComputer}, 0},
		{"stale LAPS expiry (>30d) -> flagged", []types.Computer{staleComputer}, 1},
		{"mixed -> only stale counted", []types.Computer{freshComputer, staleComputer, outOfScopeComputer}, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{Now: now, Computers: tc.computers}
			d := NewR361LAPSExpiryDetector()
			findings := d.Detect(context.Background(), data)
			if tc.wantCount == 0 {
				if len(findings) != 0 {
					t.Fatalf("expected no finding, got %+v", findings)
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(findings))
			}
			if findings[0].Count != tc.wantCount {
				t.Errorf("Count = %d, want %d", findings[0].Count, tc.wantCount)
			}
		})
	}
}

func TestR361LAPSExpiry_DoesNotClaimNonexistentANSSISubReco(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Computers: []types.Computer{
			{SAMAccountName: "WKS01$", LAPSPasswordExpiry: now.AddDate(0, 0, 45)},
		},
	}
	d := NewR361LAPSExpiryDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	title := findings[0].Title
	desc := findings[0].Description
	if strings.Contains(title, "R36.1") || strings.Contains(desc, "R36.1") {
		t.Errorf("finding still cites the nonexistent PA-099 R36.1 sub-reco: title=%q desc=%q", title, desc)
	}
	if !strings.Contains(desc, "R30") {
		t.Errorf("description should cite the real source R30, got %q", desc)
	}
	if strings.Contains(desc, "requires LAPS password rotations no more than") {
		t.Errorf("description should not claim ANSSI mandates the 30-day number, got %q", desc)
	}
}

// TestR361LAPSExpiry_EnabledComputerStale_Counted pins branch 1 of the
// detection matrix: an enabled computer with a LAPS expiry beyond the
// benchmark is counted.
func TestR361LAPSExpiry_EnabledComputerStale_Counted(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Computers: []types.Computer{
			{
				DistinguishedName:  "CN=WKS01,OU=Computers,DC=example,DC=com",
				SAMAccountName:     "WKS01$",
				LAPSPasswordExpiry: now.AddDate(0, 0, 90),
			},
		},
	}
	findings := NewR361LAPSExpiryDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1", findings[0].Count)
	}
}

// TestR361LAPSExpiry_DisabledComputerStale_NotCountedByActive pins the fix:
// a disabled computer with the same stale LAPS expiry must no longer be
// counted by the active detector - it is tracked separately by the
// _ON_DISABLED_ACCOUNT twin. On the pre-fix code (no Enabled() guard), this
// computer was counted and the test failed.
func TestR361LAPSExpiry_DisabledComputerStale_NotCountedByActive(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Computers: []types.Computer{
			{
				DistinguishedName:  "CN=WKS02,OU=Computers,DC=example,DC=com",
				SAMAccountName:     "WKS02$",
				Disabled:           true,
				LAPSPasswordExpiry: now.AddDate(0, 0, 90),
			},
		},
	}
	findings := NewR361LAPSExpiryDetector().Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding for a disabled computer, got %+v", findings)
	}
}

// TestR361LAPSExpiry_EnabledComputerFresh_NotCounted pins branch 2: an
// enabled computer whose LAPS expiry is still within the benchmark is not
// counted.
func TestR361LAPSExpiry_EnabledComputerFresh_NotCounted(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Computers: []types.Computer{
			{
				DistinguishedName:  "CN=WKS03,OU=Computers,DC=example,DC=com",
				SAMAccountName:     "WKS03$",
				LAPSPasswordExpiry: now.AddDate(0, 0, 15),
			},
		},
	}
	findings := NewR361LAPSExpiryDetector().Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding, got %+v", findings)
	}
}

// TestR361LAPSExpiry_NoLAPSExpiry_NotCounted pins branch 3: a computer
// without any LAPS expiry attribute stays out of scope.
func TestR361LAPSExpiry_NoLAPSExpiry_NotCounted(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Computers: []types.Computer{
			{
				DistinguishedName: "CN=WKS04,OU=Computers,DC=example,DC=com",
				SAMAccountName:    "WKS04$",
			},
		},
	}
	findings := NewR361LAPSExpiryDetector().Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding, got %+v", findings)
	}
}

// TestR361LAPSExpiry_ThreeEnabledComputersStale_CountIsThree pins branch 5:
// multiple stale enabled computers are counted one for one.
func TestR361LAPSExpiry_ThreeEnabledComputersStale_CountIsThree(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Computers: []types.Computer{
			{DistinguishedName: "CN=WKS05,OU=Computers,DC=example,DC=com", SAMAccountName: "WKS05$", LAPSPasswordExpiry: now.AddDate(0, 0, 90)},
			{DistinguishedName: "CN=WKS06,OU=Computers,DC=example,DC=com", SAMAccountName: "WKS06$", LAPSPasswordExpiry: now.AddDate(0, 0, 91)},
			{DistinguishedName: "CN=WKS07,OU=Computers,DC=example,DC=com", SAMAccountName: "WKS07$", LAPSPasswordExpiry: now.AddDate(0, 0, 92)},
		},
	}
	findings := NewR361LAPSExpiryDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 3 {
		t.Errorf("Count = %d, want 3", findings[0].Count)
	}
}

// TestR361LAPSExpiry_ExpiryExactlyAtThreshold_NotCounted pins the exclusive
// boundary of the threshold comparison: an expiry exactly
// lapsMaxExpiryDaysBenchmark days out is not past the benchmark and must not
// be counted.
func TestR361LAPSExpiry_ExpiryExactlyAtThreshold_NotCounted(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Computers: []types.Computer{
			{
				DistinguishedName:  "CN=WKS14,OU=Computers,DC=example,DC=com",
				SAMAccountName:     "WKS14$",
				LAPSPasswordExpiry: now.AddDate(0, 0, 30),
			},
		},
	}
	findings := NewR361LAPSExpiryDetector().Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding for an expiry exactly at the threshold, got %+v", findings)
	}
}

// TestR361LAPSExpiry_ExpiryOneSecondPastThreshold_Counted pins the boundary
// one second past the threshold: it must be counted.
func TestR361LAPSExpiry_ExpiryOneSecondPastThreshold_Counted(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Computers: []types.Computer{
			{
				DistinguishedName:  "CN=WKS15,OU=Computers,DC=example,DC=com",
				SAMAccountName:     "WKS15$",
				LAPSPasswordExpiry: now.AddDate(0, 0, 30).Add(time.Second),
			},
		},
	}
	findings := NewR361LAPSExpiryDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1", findings[0].Count)
	}
}

// TestR361LAPSExpiry_ExpiryHalfDayPastThreshold_Counted pins a second point
// past the threshold, twelve hours in: it must also be counted.
func TestR361LAPSExpiry_ExpiryHalfDayPastThreshold_Counted(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Computers: []types.Computer{
			{
				DistinguishedName:  "CN=WKS16,OU=Computers,DC=example,DC=com",
				SAMAccountName:     "WKS16$",
				LAPSPasswordExpiry: now.AddDate(0, 0, 30).Add(12 * time.Hour),
			},
		},
	}
	findings := NewR361LAPSExpiryDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1", findings[0].Count)
	}
}
