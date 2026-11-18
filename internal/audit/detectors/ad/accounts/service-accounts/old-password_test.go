package serviceaccounts

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestOldPassword_MustChangeAtNextLogonNotFlagged pins the fix: pwdLastSet
// == 0 means "must change password at next logon" (Microsoft Learn,
// Pwd-Last-Set attribute), not "password not changed in over a year". The
// collector maps that to a Go zero time.Time, which the old code counted
// as an old password - a freshly reset service account was mislabeled.
func TestOldPassword_MustChangeAtNextLogonNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				SAMAccountName:  "svc-newapp",
				PasswordLastSet: time.Time{}, // pwdLastSet=0: must change at next logon
			},
		},
	}

	findings := NewOldPasswordDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: pwdLastSet=0 is a pending forced change, not an old password", findings[0].Count)
	}
}

// TestOldPassword_GenuinelyStaleFlagged pins the surviving positive case: a
// real, non-zero timestamp older than a year must still fire.
func TestOldPassword_GenuinelyStaleFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now:            now,
		IncludeDetails: true,
		Users: []types.User{
			{
				SAMAccountName:  "svc-legacy",
				PasswordLastSet: now.AddDate(-2, 0, 0),
			},
		},
	}

	findings := NewOldPasswordDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: a real 2-year-old password must still fire", findings[0].Count)
	}
}

// TestOldPassword_DisabledServiceAccountNotFlagged pins the Disabled guard:
// a disabled service account with a stale password must not be counted.
func TestOldPassword_DisabledServiceAccountNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				SAMAccountName:  "svc_backup",
				Disabled:        true,
				PasswordLastSet: now.AddDate(-2, 0, 0),
			},
		},
	}

	findings := NewOldPasswordDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a disabled service account must not be counted", findings[0].Count)
	}
}

// TestOldPassword_JustOverOneYearFlagged pins the lower side of the one-year
// boundary: a password one day older than one year must fire.
func TestOldPassword_JustOverOneYearFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				SAMAccountName:  "svc_backup",
				PasswordLastSet: now.AddDate(-1, 0, -1),
			},
		},
	}

	findings := NewOldPasswordDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: a password one day past the one-year threshold must fire", findings[0].Count)
	}
}

// TestOldPassword_JustUnderOneYearNotFlagged pins the other side of the same
// boundary: a password one day short of one year must not fire.
func TestOldPassword_JustUnderOneYearNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				SAMAccountName:  "svc_backup",
				PasswordLastSet: now.AddDate(-1, 0, 1),
			},
		},
	}

	findings := NewOldPasswordDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a password one day short of the one-year threshold must not fire", findings[0].Count)
	}
}

// TestOldPassword_NonServiceAccountNotFlagged pins the isServiceAccount
// guard: an account not recognized as a service account, even with a stale
// password, must not be counted.
func TestOldPassword_NonServiceAccountNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{
				SAMAccountName:  "jsmith",
				PasswordLastSet: now.AddDate(-2, 0, 0),
			},
		},
	}

	findings := NewOldPasswordDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a non-service account must not be counted", findings[0].Count)
	}
}
