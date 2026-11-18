package kerberos

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// Confirms the primary measurement path: MaxTicketAge read via
// helpers.GetKerberosPolicy(data.GPOPolicies), covering the recommended
// 10-hour threshold - strictly above is flagged, at the Microsoft default
// and below it is not.
func TestKerberosTicketLifetimeLong_Threshold(t *testing.T) {
	cases := []struct {
		name         string
		maxTicketAge int
		wantCount    int
	}{
		{"12 hours (above recommended 10) -> flagged", 12, 1},
		{"11 hours (lower boundary above threshold) -> flagged", 11, 1},
		{"10 hours (Microsoft default, at threshold) -> not flagged", 10, 0},
		{"8 hours (hardened, below threshold) -> not flagged", 8, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{
				GPOPolicies: map[string]*audit.GPOPolicy{
					"{31B2F340-016D-11D2-945F-00C04FB984F9}": {
						KerberosPolicy: &audit.KerberosPolicy{MaxTicketAge: tc.maxTicketAge},
					},
				},
			}

			findings := NewKerberosTicketLifetimeLongDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding, got %d", len(findings))
			}
			if findings[0].Count != tc.wantCount {
				t.Fatalf("Count = %d, want %d", findings[0].Count, tc.wantCount)
			}
		})
	}
}

// Confirms the behavior when no Kerberos policy is readable at all - no
// GPO data and no DomainInfo: the detector does not panic and returns
// exactly one finding with Count 0, not an empty slice.
func TestKerberosTicketLifetimeLong_NoPolicyReadable(t *testing.T) {
	data := &audit.DetectorData{}

	findings := NewKerberosTicketLifetimeLongDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// Confirms the DomainInfo fallback (data.DomainInfo.MaxTicketAge) fires
// when no GPO Kerberos policy is present at all. No provider in this repo
// populates this field today, but the branch is reachable by direct
// construction of DetectorData, which is exactly what this test does.
func TestKerberosTicketLifetimeLong_DomainInfoFallback(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{MaxTicketAge: 15},
	}

	findings := NewKerberosTicketLifetimeLongDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
}
