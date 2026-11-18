package password

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestDictAttackRisk_DisabledAccountNotCounted guards the Disabled guard at
// :29: a disabled account with a high bad-password count must not be
// counted, even though its badPwdCount alone would satisfy the :36 threshold.
func TestDictAttackRisk_DisabledAccountNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "svc-backup01", Disabled: true, BadPasswordCount: 10},
		},
	}

	findings := NewDictAttackRiskDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (disabled account must be excluded)", findings[0].Count)
	}
}

// TestDictAttackRisk_ThreeBadAttemptsNotCounted guards the lower boundary of
// :36 (badPwdCount > 3): exactly 3 bad attempts on an active, non-locked
// account must not be counted.
func TestDictAttackRisk_ThreeBadAttemptsNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "jdupont02", Disabled: false, BadPasswordCount: 3},
		},
	}

	findings := NewDictAttackRiskDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (3 bad attempts must not cross the > 3 threshold)", findings[0].Count)
	}
}

// TestDictAttackRisk_FourBadAttemptsCounted guards the upper boundary of :36:
// exactly 4 bad attempts on an active, non-locked account must be counted.
func TestDictAttackRisk_FourBadAttemptsCounted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "mbernard03", Disabled: false, BadPasswordCount: 4},
		},
	}

	findings := NewDictAttackRiskDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (4 bad attempts must cross the > 3 threshold)", findings[0].Count)
	}
}

// TestDictAttackRisk_LockedOutZeroBadCountCounted guards the LockedOut
// sub-term of :36: an active, locked-out account with zero bad attempts
// must still be counted on the LockedOut term alone.
func TestDictAttackRisk_LockedOutZeroBadCountCounted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "slemoine04", Disabled: false, BadPasswordCount: 0, LockedOut: true},
		},
	}

	findings := NewDictAttackRiskDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (LockedOut alone must count, even with 0 bad attempts)", findings[0].Count)
	}
}

// TestDictAttackRisk_MixedAccountsCountExact guards Count against a
// population mixing every exclusion and inclusion reason at once: a disabled
// account with a high bad count, an active account just under the threshold,
// an active account just over the threshold, and an active locked-out
// account with no bad attempts. Exactly 2 of the 4 must be counted.
func TestDictAttackRisk_MixedAccountsCountExact(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "svc-backup05", Disabled: true, BadPasswordCount: 10},
			{SAMAccountName: "jdupont06", Disabled: false, BadPasswordCount: 3},
			{SAMAccountName: "mbernard07", Disabled: false, BadPasswordCount: 4},
			{SAMAccountName: "slemoine08", Disabled: false, BadPasswordCount: 0, LockedOut: true},
		},
	}

	findings := NewDictAttackRiskDetector().Detect(context.Background(), data)
	if findings[0].Count != 2 {
		t.Fatalf("Count = %d, want 2 (only mbernard07 and slemoine08 qualify)", findings[0].Count)
	}
}

// TestDictAttackRisk_IncludeDetailsTrueAffectedEntitiesPresent guards the
// IncludeDetails block: when IncludeDetails is true and accounts qualify,
// AffectedEntities must be populated.
func TestDictAttackRisk_IncludeDetailsTrueAffectedEntitiesPresent(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "attackertarget09", Disabled: false, BadPasswordCount: 5},
		},
	}

	findings := NewDictAttackRiskDetector().Detect(context.Background(), data)
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "attackertarget09" {
		t.Fatalf("AffectedEntities = %+v, want exactly attackertarget09", findings[0].AffectedEntities)
	}
}

// TestDictAttackRisk_IncludeDetailsFalseAffectedEntitiesAbsent guards the
// same block in the other direction: when IncludeDetails is false,
// AffectedEntities must stay empty even though qualifying accounts exist.
func TestDictAttackRisk_IncludeDetailsFalseAffectedEntitiesAbsent(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: false,
		Users: []types.User{
			{SAMAccountName: "attackertarget10", Disabled: false, BadPasswordCount: 5},
		},
	}

	findings := NewDictAttackRiskDetector().Detect(context.Background(), data)
	if len(findings[0].AffectedEntities) != 0 {
		t.Fatalf("AffectedEntities = %+v, want empty (IncludeDetails is false)", findings[0].AffectedEntities)
	}
}

// TestDictAttackRisk_SeverityIsMedium guards the Severity field on :43:
// the finding must be reported at Medium, not a higher or lower severity.
func TestDictAttackRisk_SeverityIsMedium(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "severitycheck12", Disabled: false, BadPasswordCount: 4},
		},
	}

	findings := NewDictAttackRiskDetector().Detect(context.Background(), data)
	if findings[0].Severity != types.SeverityMedium {
		t.Fatalf("Severity = %q, want %q", findings[0].Severity, types.SeverityMedium)
	}
}

// TestDictAttackRisk_IncludeDetailsTrueNoQualifyingAccountAffectedEntitiesNil
// guards the :53 subterm `len(affected) > 0`, distinct from the :53
// `IncludeDetails` subterm already guarded above: when IncludeDetails is
// true but no account qualifies, AffectedEntities must stay nil (the field
// untouched), not an empty, non-nil slice from calling the conversion
// helper on an empty population.
func TestDictAttackRisk_IncludeDetailsTrueNoQualifyingAccountAffectedEntitiesNil(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "cleanuser13", Disabled: false, BadPasswordCount: 0},
		},
	}

	findings := NewDictAttackRiskDetector().Detect(context.Background(), data)
	if findings[0].AffectedEntities != nil {
		t.Fatalf("AffectedEntities = %+v (non-nil, len %d), want nil when IncludeDetails is true but no account qualifies", findings[0].AffectedEntities, len(findings[0].AffectedEntities))
	}
}

// TestDictAttackRisk_ZeroCountDetailsPresent guards the base Finding shape
// when no account qualifies: Count must be 0 and the static Details
// recommendation must still be present.
func TestDictAttackRisk_ZeroCountDetailsPresent(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "cleanuser11", Disabled: false, BadPasswordCount: 0},
		},
	}

	findings := NewDictAttackRiskDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
	rec, ok := findings[0].Details["recommendation"]
	if !ok || rec == "" {
		t.Fatalf("Details[\"recommendation\"] = %q, ok=%v, want a non-empty recommendation", rec, ok)
	}
}
