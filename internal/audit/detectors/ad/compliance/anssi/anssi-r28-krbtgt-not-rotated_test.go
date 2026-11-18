package anssi

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestR28KrbtgtRotation_270DaysIsCompliant: ANSSI PA-099 R41
// (p.53) requires rotating krbtgt "chaque année" (once a year), not every 180
// days. A krbtgt password changed 270 days ago is within ANSSI's own
// tolerance and must not be flagged Critical. This test would have FAILED
// against the old 180-day threshold (270 > 180 → flagged) and passes now
// that the threshold matches the source (270 < 365 → compliant).
func TestR28KrbtgtRotation_270DaysIsCompliant(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{ObjectSID: "S-1-5-21-1-2-3-502", SAMAccountName: "krbtgt", PasswordLastSet: now.AddDate(0, 0, -270)},
		},
	}
	findings := NewR28KrbtgtRotationDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected krbtgt rotated 270 days ago to be compliant with the 1-year ANSSI R41 threshold, got %+v", findings)
	}
}

// TestR28KrbtgtRotation_400DaysIsFlagged confirms the detector still fires
// once the real ANSSI threshold (1 year) is exceeded.
func TestR28KrbtgtRotation_400DaysIsFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{ObjectSID: "S-1-5-21-1-2-3-502", SAMAccountName: "krbtgt", PasswordLastSet: now.AddDate(0, 0, -400)},
		},
	}
	findings := NewR28KrbtgtRotationDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected krbtgt rotated 400 days ago to be flagged, got %+v", findings)
	}
}

// TestR28Krbtgt_IdentifiedByRIDOnly isolates the RID (-502) identification
// term: the account has been renamed away from "krbtgt", so only the
// ObjectSID suffix can identify it. If that term were removed, the account
// would never be matched and the finding would not fire even though its
// password is 400 days stale.
func TestR28Krbtgt_IdentifiedByRIDOnly(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{ObjectSID: "S-1-5-21-1-2-3-502", SAMAccountName: "svc-renamed-krbtgt-account", PasswordLastSet: now.AddDate(0, 0, -400)},
		},
	}
	findings := NewR28KrbtgtRotationDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected a renamed krbtgt identified by RID -502 alone to be flagged, got %+v", findings)
	}
}

// TestR28Krbtgt_IdentifiedByNameOnly isolates the name identification term:
// the account's ObjectSID does not end with -502, so only the
// SAMAccountName "krbtgt" can identify it. If that term were removed, the
// account would never be matched even though its password is 400 days
// stale.
func TestR28Krbtgt_IdentifiedByNameOnly(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{ObjectSID: "S-1-5-21-1-2-3-9999", SAMAccountName: "krbtgt", PasswordLastSet: now.AddDate(0, 0, -400)},
		},
	}
	findings := NewR28KrbtgtRotationDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected krbtgt identified by name alone to be flagged, got %+v", findings)
	}
}

// TestR28Krbtgt_ExactlyAtThresholdNotFlagged pins the exact boundary: a
// password changed exactly one year ago (Now - 1 year) must NOT be flagged.
// Before(threshold) is false on equality, matching ANSSI's "once a year"
// cadence; the equivalent-looking !After(threshold) would instead flag this
// exact boundary, since equality is not After either.
func TestR28Krbtgt_ExactlyAtThresholdNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{ObjectSID: "S-1-5-21-1-2-3-502", SAMAccountName: "krbtgt", PasswordLastSet: now.AddDate(-1, 0, 0)},
		},
	}
	findings := NewR28KrbtgtRotationDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected a password changed exactly one year ago to be compliant, got %+v", findings)
	}
}

// TestR28Krbtgt_ZeroPasswordLastSetNotFlagged pins the IsZero guard: an
// unset PasswordLastSet (zero time.Time) must not be flagged. Without the
// IsZero guard, the zero value is far in the past and Before(threshold)
// would be true, firing the finding on a value that carries no real
// rotation data.
func TestR28Krbtgt_ZeroPasswordLastSetNotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{ObjectSID: "S-1-5-21-1-2-3-502", SAMAccountName: "krbtgt", PasswordLastSet: time.Time{}},
		},
	}
	findings := NewR28KrbtgtRotationDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected a zero PasswordLastSet to be excluded from the finding, got %+v", findings)
	}
}
