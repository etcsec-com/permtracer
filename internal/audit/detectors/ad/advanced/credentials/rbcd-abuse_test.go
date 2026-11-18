package credentials

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// rbcdAbuseNonEmptySD is a literal placeholder byte slice standing in for a
// real msDS-AllowedToActOnBehalfOfOtherIdentity security descriptor:
// rbcd-abuse.go has no GUID or mask constant to collide with, only a length
// check, so any fixed non-empty slice distinct from "nil" exercises the same
// boundary.
var rbcdAbuseNonEmptySD = []byte{0x01, 0x00, 0x04, 0x80, 0x11, 0x22, 0x33, 0x44}

// rbcdAbuseSingleByteSD is a literal exactly 1 byte long: the length-1
// boundary the "len(...) > 0" check must still count as present. Shared
// with rbcd-abuse-on-disabled-account_test.go (same package).
var rbcdAbuseSingleByteSD = []byte{0x07}

// TestRBCDAbuse_LabPlantWitnesses mirrors the 2 lab plant computers from
// docs/security-validation/results/rbcd-abuse-v2/VERDICT.md (t526pos,
// t526ok): an enabled computer with a non-empty
// msDS-AllowedToActOnBehalfOfOtherIdentity still fires here. The disabled
// case now fires only in RBCDAbuseOnDisabledAccountDetector, covered by
// TestRBCDAbuse_DisabledTargetNotFlagged below and by
// rbcd-abuse-on-disabled-account_test.go. t526ok, which carries no
// attribute, is unaffected and still does NOT fire.
func TestRBCDAbuse_LabPlantWitnesses(t *testing.T) {
	t526pos := types.Computer{
		DN:                                  "CN=t526pos,OU=T526Plants,DC=example,DC=com",
		SAMAccountName:                      "t526pos$",
		AllowedToActOnBehalfOfOtherIdentity: rbcdAbuseNonEmptySD,
	}
	t526ok := types.Computer{
		DN:             "CN=t526ok,OU=T526Plants,DC=example,DC=com",
		SAMAccountName: "t526ok$",
	}

	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers:      []types.Computer{t526pos, t526ok},
	}

	findings := NewRBCDAbuseDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (t526pos only - t526ok, attribute-free, must not fire)", f.Count)
	}
	if len(f.AffectedEntities) != 1 || f.AffectedEntities[0].DN != t526pos.DN {
		t.Fatalf("AffectedEntities = %v, want only %q", f.AffectedEntities, t526pos.DN)
	}
}

// TestRBCDAbuse_DisabledTargetNotFlagged is the split guard: a disabled
// computer carrying a non-empty msDS-AllowedToActOnBehalfOfOtherIdentity
// must not fire here - the KDC refuses to issue it a service ticket
// (S4U2Proxy target), so it cannot be exploited today. Covered instead by
// RBCDAbuseOnDisabledAccountDetector (rbcd-abuse-on-disabled-account.go).
func TestRBCDAbuse_DisabledTargetNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=disabled,DC=example,DC=com", Disabled: true, AllowedToActOnBehalfOfOtherIdentity: rbcdAbuseNonEmptySD},
		},
	}
	findings := NewRBCDAbuseDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (disabled computer, even with the attribute set, must not fire here)", findings[0].Count)
	}
}

// TestRBCDAbuse_EmptyNonNilSliceDoesNotFire guards the exact boundary the
// detector relies on: an explicitly non-nil but zero-length slice (as a
// provider could plausibly return instead of nil) must behave identically
// to an absent attribute.
func TestRBCDAbuse_EmptyNonNilSliceDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=empty,DC=example,DC=com", AllowedToActOnBehalfOfOtherIdentity: []byte{}},
		},
	}
	findings := NewRBCDAbuseDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 for an explicit zero-length (non-nil) slice", findings[0].Count)
	}
}

// TestRBCDAbuse_MutationCoverage is the LITERAL fixture the length check in
// rbcd-abuse.go is proven against by a temporary, uncommitted edit of that
// file (condition removed), run, and revert cycle. One computer carries a
// non-empty attribute, one does not:
//   - correct code (`> 0`): only withSD fires, Count == 1.
//   - condition dropped (unconditional append): both fire, Count == 2.
func TestRBCDAbuse_MutationCoverage(t *testing.T) {
	withSD := types.Computer{DN: "CN=withsd,DC=example,DC=com", AllowedToActOnBehalfOfOtherIdentity: rbcdAbuseNonEmptySD}
	withoutSD := types.Computer{DN: "CN=withoutsd,DC=example,DC=com"}

	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers:      []types.Computer{withSD, withoutSD},
	}
	findings := NewRBCDAbuseDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want exactly 1 (withSD only) - kills the condition-removed mutation (both fire, Count=2)", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].DN != withSD.DN {
		t.Fatalf("AffectedEntities = %v, want only %q", findings[0].AffectedEntities, withSD.DN)
	}
}

// TestRBCDAbuse_SingleByteAttributeCounted proves the length-1 boundary:
// an enabled computer whose msDS-AllowedToActOnBehalfOfOtherIdentity is
// exactly 1 byte long must still be counted (len(...) > 0, not > 1). This
// kills a mutation that widens the guard to "> 1", which the existing
// 8-byte fixture (rbcdAbuseNonEmptySD) cannot detect.
func TestRBCDAbuse_SingleByteAttributeCounted(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=single-byte,DC=example,DC=com", AllowedToActOnBehalfOfOtherIdentity: rbcdAbuseSingleByteSD},
		},
	}
	findings := NewRBCDAbuseDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (a 1-byte attribute must be counted)", findings[0].Count)
	}
}

// TestRBCDAbuse_TypeSeverityCategoryLiteral pins the finding's static
// fields against LITERAL strings, not against the detector's own
// constants.
func TestRBCDAbuse_TypeSeverityCategoryLiteral(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=withsd,DC=example,DC=com", AllowedToActOnBehalfOfOtherIdentity: rbcdAbuseNonEmptySD},
		},
	}
	findings := NewRBCDAbuseDetector().Detect(context.Background(), data)
	if got := findings[0].Type; got != "RBCD_ABUSE" {
		t.Fatalf("expected Type literal \"RBCD_ABUSE\", got %q", got)
	}
	if got := string(findings[0].Severity); got != "critical" {
		t.Fatalf("expected Severity literal \"critical\", got %q", got)
	}
	if got := findings[0].Category; got != "advanced" {
		t.Fatalf("expected Category literal \"advanced\", got %q", got)
	}
}
