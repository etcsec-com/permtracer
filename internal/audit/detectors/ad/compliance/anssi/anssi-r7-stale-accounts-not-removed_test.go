package anssi

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestR7StaleAccounts_NeverLoggedOnFallsBackToCreated: a
// disabled account that never logged on has LastLogon/LastLogonTimestamp
// both zero. The detector used to require `!last.IsZero()` before comparing
// to the threshold, so a never-used disabled account - the worst case for
// this check, not a safe one - was silently skipped forever. This test would
// have FAILED against the old implementation (no finding) and passes now
// that a zero last-logon falls back to Created (whenCreated).
func TestR7StaleAccounts_NeverLoggedOnFallsBackToCreated(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				DN:             "CN=Never Used,DC=lab,DC=local",
				SAMAccountName: "neverused",
				Disabled:       true,
				Created:        now.AddDate(0, 0, -200), // created 200 days ago, never logged on
			},
		},
	}
	findings := NewR7StaleAccountsNotRemovedDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected a disabled, never-logged-on account created 200 days ago to be flagged, got %+v", findings)
	}
}

// TestR7StaleAccounts_ActiveAccountNotCounted: the detector only ever
// considers disabled accounts (`if !u.Disabled { continue }`). An active
// account idle for 200 days must never be counted, even though its last
// activity alone would clear the 180-day threshold.
func TestR7StaleAccounts_ActiveAccountNotCounted(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				DN:                 "CN=Active Idle,DC=example,DC=com",
				SAMAccountName:     "activeidle",
				Disabled:           false,
				LastLogonTimestamp: now.AddDate(0, 0, -200),
			},
			{
				DN:                 "CN=Disabled Idle,DC=example,DC=com",
				SAMAccountName:     "disabledidle",
				Disabled:           true,
				LastLogonTimestamp: now.AddDate(0, 0, -200),
			},
		},
	}
	findings := NewR7StaleAccountsNotRemovedDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected only the disabled idle account to be flagged (Count 1), got %+v", findings)
	}
}

// TestR7StaleAccounts_MaxOfLastLogonAndTimestamp_LastLogonWins: the detector
// takes the MAX of LastLogonTimestamp and LastLogon
// (`if u.LastLogon.After(last) { last = u.LastLogon }`). A disabled account
// with a stale LastLogonTimestamp but a recent LastLogon must NOT be
// flagged, because the recent LastLogon is the true last activity.
func TestR7StaleAccounts_MaxOfLastLogonAndTimestamp_LastLogonWins(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				DN:                 "CN=Recent Logon,DC=example,DC=com",
				SAMAccountName:     "recentlogon",
				Disabled:           true,
				LastLogonTimestamp: now.AddDate(0, 0, -200),
				LastLogon:          now.AddDate(0, 0, -10),
			},
		},
	}
	findings := NewR7StaleAccountsNotRemovedDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected the recent LastLogon to win over the stale LastLogonTimestamp (Count 0), got %+v", findings)
	}
}

// TestR7StaleAccounts_MaxOfLastLogonAndTimestamp_TimestampWins: the mirror
// case of the MAX comparison - a disabled account with a stale LastLogon but
// a recent LastLogonTimestamp must NOT be flagged either.
func TestR7StaleAccounts_MaxOfLastLogonAndTimestamp_TimestampWins(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				DN:                 "CN=Recent Timestamp,DC=example,DC=com",
				SAMAccountName:     "recenttimestamp",
				Disabled:           true,
				LastLogon:          now.AddDate(0, 0, -200),
				LastLogonTimestamp: now.AddDate(0, 0, -10),
			},
		},
	}
	findings := NewR7StaleAccountsNotRemovedDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected the recent LastLogonTimestamp to win over the stale LastLogon (Count 0), got %+v", findings)
	}
}

// TestR7StaleAccounts_CreatedOnlyWhenNoLogon: the Created fallback
// (`if last.IsZero() { last = u.Created }`) must apply ONLY when both
// LastLogon and LastLogonTimestamp are zero. A disabled account with a long
// Created age but a recent LastLogonTimestamp must NOT be flagged.
func TestR7StaleAccounts_CreatedOnlyWhenNoLogon(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				DN:                 "CN=Old Created Recent Logon,DC=example,DC=com",
				SAMAccountName:     "oldcreatedrecentlogon",
				Disabled:           true,
				Created:            now.AddDate(0, 0, -400),
				LastLogonTimestamp: now.AddDate(0, 0, -10),
			},
		},
	}
	findings := NewR7StaleAccountsNotRemovedDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected the recent LastLogonTimestamp to override the old Created fallback (Count 0), got %+v", findings)
	}
}

// TestR7StaleAccounts_RecentDisabledNotCounted: the final comparison
// (`if !last.IsZero() && last.Before(threshold) { ... }`) must actually
// gate on the computed date. A disabled account whose last activity is
// recent (10 days ago) must NOT be flagged.
func TestR7StaleAccounts_RecentDisabledNotCounted(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				DN:                 "CN=Recent Disabled,DC=example,DC=com",
				SAMAccountName:     "recentdisabled",
				Disabled:           true,
				LastLogonTimestamp: now.AddDate(0, 0, -10),
			},
		},
	}
	findings := NewR7StaleAccountsNotRemovedDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected a disabled account idle only 10 days to NOT be flagged (Count 0), got %+v", findings)
	}
}

// TestR7StaleAccounts_ThresholdBoundary_179DaysNotCounted: the threshold is
// exactly 180 days (`data.Now.AddDate(0, 0, -180)`). An account idle for
// 179 days and 12 hours is on the recent side of the boundary and must NOT
// be flagged.
func TestR7StaleAccounts_ThresholdBoundary_179DaysNotCounted(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				DN:                 "CN=Just Under Threshold,DC=example,DC=com",
				SAMAccountName:     "justunderthreshold",
				Disabled:           true,
				LastLogonTimestamp: now.AddDate(0, 0, -179).Add(-12 * time.Hour),
			},
		},
	}
	findings := NewR7StaleAccountsNotRemovedDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected an account idle 179.5 days to stay under the 180-day threshold (Count 0), got %+v", findings)
	}
}

// TestR7StaleAccounts_ThresholdBoundary_181DaysCounted: the mirror boundary
// case - an account idle for 180 days and 12 hours has cleared the 180-day
// threshold and must be flagged.
func TestR7StaleAccounts_ThresholdBoundary_181DaysCounted(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				DN:                 "CN=Just Over Threshold,DC=example,DC=com",
				SAMAccountName:     "justoverthreshold",
				Disabled:           true,
				LastLogonTimestamp: now.AddDate(0, 0, -180).Add(-12 * time.Hour),
			},
		},
	}
	findings := NewR7StaleAccountsNotRemovedDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected an account idle 180.5 days to clear the 180-day threshold (Count 1), got %+v", findings)
	}
}

// TestR7StaleAccounts_DisabledWithNoDatesAtAll_NotCounted: when LastLogon,
// LastLogonTimestamp AND Created are all zero, the Created fallback
// (`if last.IsZero() { last = u.Created }`) leaves `last` zero too, so the
// guard `!last.IsZero() &&` on the final comparison must still exclude it -
// a zero time.Time is far "before" any threshold, so dropping that guard
// would wrongly flag an account for which no usable date exists at all.
func TestR7StaleAccounts_DisabledWithNoDatesAtAll_NotCounted(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				DN:             "CN=No Dates At All,DC=example,DC=com",
				SAMAccountName: "nodatesatall",
				Disabled:       true,
			},
		},
	}
	findings := NewR7StaleAccountsNotRemovedDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected a disabled account with no usable date at all to NOT be flagged (Count 0), got %+v", findings)
	}
}
