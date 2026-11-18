package anssi

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestR9ServiceAccountRotation_NeverSetPasswordIsFlagged: a
// service account with pwdLastSet=0 (password never actually set through
// normal rotation) is the worst case for secret staleness, not a safe one.
// The detector used to require `!u.PasswordLastSet.IsZero()` before
// comparing to the threshold, silently excluding exactly these accounts.
// This test would have FAILED against the old implementation (no finding)
// and passes now that a zero PasswordLastSet is treated as maximally stale.
func TestR9ServiceAccountRotation_NeverSetPasswordIsFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				DN:                    "CN=svc-legacy,DC=lab,DC=local",
				SAMAccountName:        "svc-legacy",
				Disabled:              false,
				PasswordNeverExpires:  true,
				ServicePrincipalNames: []string{"HTTP/legacy.lab.local"},
				// PasswordLastSet intentionally left zero.
			},
		},
	}
	findings := NewR9ServiceAccountSecretRotationDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected a service account with pwdLastSet=0 to be flagged as never-rotated, got %+v", findings)
	}
}

// TestR9ServiceAccountRotation_DisabledNotCounted kills the mutation removing
// `u.Disabled ||` from the guard at line 24. A disabled service account with
// a stale password must not be counted, while an otherwise-identical active
// service account at the same staleness is. If the Disabled guard is
// dropped, the disabled account is counted too and Count becomes 2 instead
// of 1.
func TestR9ServiceAccountRotation_DisabledNotCounted(t *testing.T) {
	now := time.Date(2027, 6, 15, 0, 0, 0, 0, time.UTC)
	stale := now.AddDate(0, 0, -400)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				DN:              "CN=svc-disabled,DC=example,DC=com",
				SAMAccountName:  "svc-disabled",
				Disabled:        true,
				PasswordLastSet: stale,
			},
			{
				DN:              "CN=svc-active,DC=example,DC=com",
				SAMAccountName:  "svc-active",
				Disabled:        false,
				PasswordLastSet: stale,
			},
		},
	}
	findings := NewR9ServiceAccountSecretRotationDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected only the active service account to be counted (Count=1), got %+v", findings)
	}
}

// TestR9ServiceAccountRotation_NonServiceAccountNotCounted kills the
// mutation removing `|| !looksLikeServiceAccount(u)` from the guard at line
// 24. An active account that is not a service account by any heuristic
// (no svc/srv/service/sa_/s-/app- prefix, no PasswordNeverExpires+SPN
// combination) must not be counted even with a very stale password. If the
// service-account guard is dropped, this account passes through on
// Disabled alone and gets counted.
func TestR9ServiceAccountRotation_NonServiceAccountNotCounted(t *testing.T) {
	now := time.Date(2027, 6, 15, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				DN:                   "CN=alice,DC=example,DC=com",
				SAMAccountName:       "alice",
				Disabled:             false,
				PasswordNeverExpires: false,
				PasswordLastSet:      now.AddDate(0, 0, -400),
			},
		},
	}
	findings := NewR9ServiceAccountSecretRotationDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected a non-service account to never be counted (Count=0), got %+v", findings)
	}
}

// TestR9ServiceAccountRotation_RecentPasswordNotCounted kills the mutation
// forcing the counting condition at line 33 to `if true || (...)`. An
// active service account whose password was rotated recently (10 days ago,
// well inside the 1-year threshold) must not be counted. If the condition
// is forced to always-true, any service account that reaches line 33 is
// counted regardless of password age.
func TestR9ServiceAccountRotation_RecentPasswordNotCounted(t *testing.T) {
	now := time.Date(2027, 6, 15, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				DN:              "CN=svc-recent,DC=example,DC=com",
				SAMAccountName:  "svc-recent",
				Disabled:        false,
				PasswordLastSet: now.AddDate(0, 0, -10),
			},
		},
	}
	findings := NewR9ServiceAccountSecretRotationDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected a recently-rotated service account to never be counted (Count=0), got %+v", findings)
	}
}

// TestR9ServiceAccountRotation_ThresholdBoundaryJustUnderOneYear kills the
// mutation changing the threshold from AddDate(-1, 0, 0) to
// AddDate(0, 0, -364). `now` (2027-06-15) and the 365 days preceding it
// (back to 2026-06-15) fall entirely within non-leap years 2026 and 2027,
// so AddDate(-1, 0, 0) is exactly 365 days before `now` here. A password
// last set 364 days and 12 hours ago is inside that real 365-day threshold
// (not stale) but outside a mutant 364-day threshold (stale), so the
// mutation flips Count from 0 to 1.
func TestR9ServiceAccountRotation_ThresholdBoundaryJustUnderOneYear(t *testing.T) {
	now := time.Date(2027, 6, 15, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				DN:              "CN=svc-boundary-under,DC=example,DC=com",
				SAMAccountName:  "svc-boundary-under",
				Disabled:        false,
				PasswordLastSet: now.AddDate(0, 0, -364).Add(-12 * time.Hour),
			},
		},
	}
	findings := NewR9ServiceAccountSecretRotationDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected a password rotated 364d12h ago (inside the real 1-year threshold) to not be counted (Count=0), got %+v", findings)
	}
}

// TestR9ServiceAccountRotation_ThresholdBoundaryJustOverOneYear kills the
// mutation changing the threshold from AddDate(-1, 0, 0) to
// AddDate(0, 0, -366). Same non-leap window as above. A password last set
// 365 days and 12 hours ago is outside the real 365-day threshold (stale,
// counted) but inside a mutant 366-day threshold (not stale), so the
// mutation flips Count from 1 to 0.
func TestR9ServiceAccountRotation_ThresholdBoundaryJustOverOneYear(t *testing.T) {
	now := time.Date(2027, 6, 15, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				DN:              "CN=svc-boundary-over,DC=example,DC=com",
				SAMAccountName:  "svc-boundary-over",
				Disabled:        false,
				PasswordLastSet: now.AddDate(0, 0, -365).Add(-12 * time.Hour),
			},
		},
	}
	findings := NewR9ServiceAccountSecretRotationDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected a password rotated 365d12h ago (outside the real 1-year threshold) to be counted (Count=1), got %+v", findings)
	}
}
