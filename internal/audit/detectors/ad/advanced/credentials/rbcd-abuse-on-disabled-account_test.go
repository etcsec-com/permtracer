package credentials

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestRBCDAbuseOnDisabledAccount_DisabledTargetFires is the mirror
// positive of TestRBCDAbuse_DisabledTargetNotFlagged: a disabled computer
// carrying a non-empty msDS-AllowedToActOnBehalfOfOtherIdentity must fire
// here.
func TestRBCDAbuseOnDisabledAccount_DisabledTargetFires(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=t526pos,OU=T526Plants,DC=example,DC=com", SAMAccountName: "t526pos$", Disabled: true, AllowedToActOnBehalfOfOtherIdentity: rbcdAbuseNonEmptySD},
		},
	}
	findings := NewRBCDAbuseOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("disabled computer with the attribute set must fire, got %+v", findings)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].DN != "CN=t526pos,OU=T526Plants,DC=example,DC=com" {
		t.Fatalf("AffectedEntities = %v, want only the disabled target", findings[0].AffectedEntities)
	}
}

// TestRBCDAbuseOnDisabledAccount_EnabledTargetDoesNotFire is the mirror
// negative: an enabled computer carrying the attribute must not fire here
// - it is covered instead by RBCDAbuseDetector (rbcd-abuse.go).
func TestRBCDAbuseOnDisabledAccount_EnabledTargetDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=enabled,DC=example,DC=com", Disabled: false, AllowedToActOnBehalfOfOtherIdentity: rbcdAbuseNonEmptySD},
		},
	}
	findings := NewRBCDAbuseOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (enabled computer must not fire in the disabled-account twin)", findings[0].Count)
	}
}

// TestRBCDAbuseOnDisabledAccount_EmptyAttributeDoesNotFire proves the
// attribute condition still applies: a disabled computer with no
// msDS-AllowedToActOnBehalfOfOtherIdentity must not be counted.
func TestRBCDAbuseOnDisabledAccount_EmptyAttributeDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=disabled-no-attr,DC=example,DC=com", Disabled: true},
		},
	}
	findings := NewRBCDAbuseOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (disabled computer without the attribute must not fire)", findings[0].Count)
	}
}

// TestRBCDAbuseOnDisabledAccount_SingleByteAttributeCounted is the twin of
// TestRBCDAbuse_SingleByteAttributeCounted: a disabled computer whose
// msDS-AllowedToActOnBehalfOfOtherIdentity is exactly 1 byte long must
// still be counted here (len(...) > 0, not > 1).
func TestRBCDAbuseOnDisabledAccount_SingleByteAttributeCounted(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=single-byte-disabled,DC=example,DC=com", Disabled: true, AllowedToActOnBehalfOfOtherIdentity: rbcdAbuseSingleByteSD},
		},
	}
	findings := NewRBCDAbuseOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (a 1-byte attribute must be counted)", findings[0].Count)
	}
}

// TestRBCDAbuseOnDisabledAccount_TypeSeverityCategoryLiteral pins the
// finding's static fields against LITERAL strings, in particular the
// Medium severity mandated by the split severity grid (D1) for a
// computer-identity takeover primitive.
func TestRBCDAbuseOnDisabledAccount_TypeSeverityCategoryLiteral(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=disabled,DC=example,DC=com", Disabled: true, AllowedToActOnBehalfOfOtherIdentity: rbcdAbuseNonEmptySD},
		},
	}
	findings := NewRBCDAbuseOnDisabledAccountDetector().Detect(context.Background(), data)
	if got := findings[0].Type; got != "RBCD_ABUSE_ON_DISABLED_ACCOUNT" {
		t.Fatalf("expected Type literal \"RBCD_ABUSE_ON_DISABLED_ACCOUNT\", got %q", got)
	}
	if got := string(findings[0].Severity); got != "medium" {
		t.Fatalf("expected Severity literal \"medium\", got %q", got)
	}
	if got := findings[0].Category; got != "advanced" {
		t.Fatalf("expected Category literal \"advanced\", got %q", got)
	}
}
