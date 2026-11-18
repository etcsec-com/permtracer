package privileged

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// proves the frozen-bench reproducibility property: replaying
// the same captured AdminLastLoginDate against the same injected reference
// time (data.Now) yields an identical finding, independent of the real
// wall-clock date the test happens to run on. Detect() no longer calls
// time.Now()/time.Since() at all - data.Now is the only time input it reads.

func detectAdminNativeRecentLogon(now, lastLogin time.Time) types.Finding {
	data := &audit.DetectorData{
		Now: now,
		DomainInfo: &types.DomainInfo{
			AdminLastLoginDate: lastLogin,
		},
	}
	findings := NewAdminNativeRecentLogonDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		panic("expected exactly one finding")
	}
	return findings[0]
}

func TestAdminNativeRecentLogon_ReplayIsDeterministicAcrossRealDates(t *testing.T) {
	lastLogin := time.Date(2026, 7, 29, 9, 31, 0, 0, time.UTC) // the frozen bench's own capture instant
	asOf := lastLogin.Add(17 * 24 * time.Hour)                 // the bench's own "as of" timestamp - 17 days later

	first := detectAdminNativeRecentLogon(asOf, lastLogin)

	// Simulate "replay on a different real calendar day": real wall-clock
	// time has moved on since `first` was computed, but the bench's own AsOf
	// is fixed data, not time.Now() - so the second replay must reproduce
	// byte-for-byte, no matter how much real time elapses between the two.
	time.Sleep(2 * time.Millisecond)
	second := detectAdminNativeRecentLogon(asOf, lastLogin)

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("replaying the identical frozen input produced different findings:\nfirst:  %+v\nsecond: %+v", first, second)
	}

	// Same relative gap (17 days), but the reference time itself is a
	// completely different calendar date - proves the outcome depends only
	// on (Now - AdminLastLoginDate), never on which real date Now is.
	shiftedAsOf := asOf.AddDate(3, 0, 0)
	shiftedLastLogin := lastLogin.AddDate(3, 0, 0)
	shifted := detectAdminNativeRecentLogon(shiftedAsOf, shiftedLastLogin)

	if first.Count != shifted.Count || first.Description != shifted.Description {
		t.Fatalf("shifting both timestamps by the same amount changed the result:\nfirst:   %+v\nshifted: %+v", first, shifted)
	}
}

// the previous 30-day value was itself wrong: the detector's
// own doc comment cites PingCastle's P-AdminLogin reference, which uses 35
// days. That freeze protected against changing the threshold as a side
// effect of an unrelated time-injection refactor; it was never a mandate to
// keep a mismatched value. Realigned to 35 days.
func TestAdminNativeRecentLogon_ThirtyFiveDayThreshold(t *testing.T) {
	if adminRecentThreshold != 35*24*time.Hour {
		t.Fatalf("adminRecentThreshold must be exactly 35 days (P-AdminLogin reference), got %v", adminRecentThreshold)
	}

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name      string
		daysAgo   int
		wantCount int
	}{
		{"34 days ago - within threshold", 34, 1},
		{"exactly 35 days ago - boundary, no longer recent", 35, 0},
		{"36 days ago - outside threshold", 36, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lastLogin := base.Add(-time.Duration(tc.daysAgo) * 24 * time.Hour)
			f := detectAdminNativeRecentLogon(base, lastLogin)
			if f.Count != tc.wantCount {
				t.Fatalf("daysAgo=%d: got Count=%d, want %d", tc.daysAgo, f.Count, tc.wantCount)
			}
		})
	}
}

func TestAdminNativeRecentLogon_ZeroAdminLastLoginDate_NoFinding(t *testing.T) {
	f := detectAdminNativeRecentLogon(time.Now(), time.Time{})
	if f.Count != 0 {
		t.Fatalf("zero AdminLastLoginDate (never collected) should not count as recent, got Count=%d", f.Count)
	}
}

// DomainInfo nil must short-circuit the guard without dereferencing it.
// Mutating the guard `data.DomainInfo != nil && !data.DomainInfo.AdminLastLoginDate.IsZero()`
// into `if true` makes Detect() read data.DomainInfo.AdminLastLoginDate on a nil
// *types.DomainInfo, which panics - a panic is a test failure, so this kills
// mutation (a) directly instead of only comparing Count.
func TestAdminNativeRecentLogon_DomainInfoNil_NoFindingNoPanic(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now:        now,
		DomainInfo: nil,
	}

	findings := NewAdminNativeRecentLogonDetector().Detect(context.Background(), data)

	if len(findings) != 1 {
		t.Fatalf("expected exactly one finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("DomainInfo nil must not count as a recent admin logon, got Count=%d", findings[0].Count)
	}
}

// Same guard, other half: DomainInfo non-nil but AdminLastLoginDate zero
// (attribute never collected) must still report no finding, with a fixed Now
// distinct from time.Now() so the result does not depend on when the test runs.
func TestAdminNativeRecentLogon_DomainInfoNonNilZeroAdminLastLoginDate_NoFinding(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		DomainInfo: &types.DomainInfo{
			AdminLastLoginDate: time.Time{},
		},
	}

	findings := NewAdminNativeRecentLogonDetector().Detect(context.Background(), data)

	if len(findings) != 1 {
		t.Fatalf("expected exactly one finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("zero AdminLastLoginDate with non-nil DomainInfo must not count as recent, got Count=%d", findings[0].Count)
	}
}
