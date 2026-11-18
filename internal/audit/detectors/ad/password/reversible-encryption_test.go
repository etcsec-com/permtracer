package password

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestReversibleEncryption_DisabledAccountExcluded pins the split: a
// disabled account carrying ENCRYPTED_TEXT_PASSWORD_ALLOWED (0x80) cannot
// authenticate today, so it must not inflate the Critical population - it
// is reported separately by ReversibleEncryptionOnDisabledAccountDetector
// instead.
// Fixtures use realistic multi-bit UAC values (0x280 = NORMAL_ACCOUNT |
// ENCRYPTED_TEXT_PASSWORD_ALLOWED, active ; 0x282 = same | ACCOUNTDISABLE,
// disabled) rather than the bare 0x80 literal: a mono-bit fixture cannot tell
// `(uac & 0x80) != 0` apart from `uac == 0x80` - a stray equality check that
// a mono-bit fixture can never expose.
func TestReversibleEncryption_DisabledAccountExcluded(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "active-reversible", UserAccountControl: 0x280, Disabled: false},
			{SAMAccountName: "stale-reversible", UserAccountControl: 0x282, Disabled: true},
		},
	}

	findings := NewReversibleEncryptionDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled account must be excluded)", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityCritical {
		t.Fatalf("Severity = %s, want critical", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "active-reversible" {
		t.Fatalf("AffectedEntities = %+v, want only active-reversible", findings[0].AffectedEntities)
	}
}

// TestReversibleEncryption_FlagNotSetNotFlagged guards the negative case.
func TestReversibleEncryption_FlagNotSetNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "ordinary", UserAccountControl: 0x0200}}, // NORMAL_ACCOUNT
	}

	findings := NewReversibleEncryptionDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestReversibleEncryption_OtherBitsPreserved guards against a regression
// that would widen the mask past 0x80 (e.g. testing the raw int value
// instead of the isolated bit) and pick up unrelated UAC flags.
func TestReversibleEncryption_OtherBitsPreserved(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			// PASSWD_NOTREQD (0x20) + ACCOUNTDISABLE (0x2) + NORMAL_ACCOUNT (0x200), no 0x80.
			{SAMAccountName: "unrelated-bits", UserAccountControl: 0x222, Disabled: true},
		},
	}

	findings := NewReversibleEncryptionDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (0x80 not set)", findings[0].Count)
	}
}
