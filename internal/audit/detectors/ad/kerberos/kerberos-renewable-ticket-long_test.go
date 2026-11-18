package kerberos

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// Confirms the only currently-reachable measurement path: MaxRenewAge read
// via helpers.GetKerberosPolicy(data.GPOPolicies), which
// internal/providers/smb/gptmpl_parser.go populates from a real
// GptTmpl.inf [Kerberos Policy] section. Microsoft's own Default Domain
// Policy ships this at 7 days; this detector should stay silent at the
// Microsoft default and fire only once a domain raises it above that.
// Not a correction (this path was already implemented correctly) - added
// because empirical confirmation was previously absent (CHECKS.yml:
// status never_observed) and the sibling DomainInfo.MaxRenewAge fallback is
// confirmed dead (see the type doc), so this is the only path worth
// covering.
func TestKerberosRenewableTicketLong_MaxRenewAgeFromGPTemplate(t *testing.T) {
	cases := []struct {
		name        string
		maxRenewAge int
		wantCount   int
	}{
		{"7 days (Microsoft default) -> not flagged", 7, 0},
		{"5 days (hardened, under default) -> not flagged", 5, 0},
		{"8 days (lower boundary above default) -> flagged", 8, 1},
		{"14 days (raised above default) -> flagged", 14, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{
				GPOPolicies: map[string]*audit.GPOPolicy{
					"{31B2F340-016D-11D2-945F-00C04FB984F9}": {
						KerberosPolicy: &audit.KerberosPolicy{MaxRenewAge: tc.maxRenewAge},
					},
				},
			}

			findings := NewKerberosRenewableTicketLongDetector().Detect(context.Background(), data)
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
func TestKerberosRenewableTicketLong_NoPolicyReadable(t *testing.T) {
	data := &audit.DetectorData{}

	findings := NewKerberosRenewableTicketLongDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// Confirms the DomainInfo fallback (data.DomainInfo.MaxRenewAge) fires
// when no GPO Kerberos policy is present at all - declared dead by the
// type doc above (no provider in this repo ever assigns it), but
// reachable by direct construction of DetectorData, which is exactly
// what this test does.
func TestKerberosRenewableTicketLong_DomainInfoFallback(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{MaxRenewAge: 10},
	}

	findings := NewKerberosRenewableTicketLongDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
}
