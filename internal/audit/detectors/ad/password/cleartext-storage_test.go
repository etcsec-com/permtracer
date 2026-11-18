package password

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestCleartextStorage_ActiveUserPasswordOnlyFires covers an active account
// carrying only userPassword. First case: asserts Type and Severity
// explicitly.
func TestCleartextStorage_ActiveUserPasswordOnlyFires(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "active-userpassword", Disabled: false, UserPassword: true, UnixUserPassword: false},
		},
	}

	findings := NewCleartextStorageDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Type != "PASSWORD_CLEARTEXT_STORAGE" {
		t.Fatalf("Type = %s, want PASSWORD_CLEARTEXT_STORAGE", findings[0].Type)
	}
	if findings[0].Severity != types.SeverityCritical {
		t.Fatalf("Severity = %s, want critical", findings[0].Severity)
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "active-userpassword" {
		t.Fatalf("AffectedEntities = %+v, want only active-userpassword", findings[0].AffectedEntities)
	}
}

// TestCleartextStorage_ActiveUnixUserPasswordOnlyFires mirrors the above for
// the other operand of the OR, alone.
func TestCleartextStorage_ActiveUnixUserPasswordOnlyFires(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "active-unixuserpassword", Disabled: false, UserPassword: false, UnixUserPassword: true},
		},
	}

	findings := NewCleartextStorageDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
}

// TestCleartextStorage_BothAttributesCountedOnce is the grouping requirement:
// a single account carrying both attributes must be counted once, not twice
// - the condition is an OR over two booleans on the same user, not two
// independent triggers.
func TestCleartextStorage_BothAttributesCountedOnce(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "both-attributes", Disabled: false, UserPassword: true, UnixUserPassword: true},
		},
	}

	findings := NewCleartextStorageDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (one account, two attributes)", findings[0].Count)
	}
}

// TestCleartextStorage_DisabledUserPasswordExcluded pins the split: a
// disabled account carrying a cleartext-capable attribute cannot
// authenticate today, so it must not inflate the Critical population - it
// is reported separately by CleartextStorageOnDisabledAccountDetector
// instead.
func TestCleartextStorage_DisabledUserPasswordExcluded(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "active-userpassword", Disabled: false, UserPassword: true, UnixUserPassword: false},
			{SAMAccountName: "disabled-userpassword", Disabled: true, UserPassword: true, UnixUserPassword: false},
		},
	}

	findings := NewCleartextStorageDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled account must be excluded)", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "active-userpassword" {
		t.Fatalf("AffectedEntities = %+v, want only active-userpassword", findings[0].AffectedEntities)
	}
}

// TestCleartextStorage_NeitherAttributeNotFlagged guards the negative case.
func TestCleartextStorage_NeitherAttributeNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "ordinary", Disabled: false, UserPassword: false, UnixUserPassword: false},
		},
	}

	findings := NewCleartextStorageDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}
