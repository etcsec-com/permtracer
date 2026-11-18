package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestM29_NameBasedPrincipal_Recognized is a red->green test for the
// name-vs-SID bug: MS-GPSB's ABNF for a [Group Membership] entry allows the
// principal to be written as a bare group name ("Administrators__Members=")
// instead of a SID ("*S-1-5-32-544__Members="). Before the fix, only the SID
// form was matched, so a GPO authored with the name form was invisible and
// M29 fired even though the group genuinely was restricted.
func TestM29_NameBasedPrincipal_Recognized(t *testing.T) {
	d := NewM29LocalAdminNotRestrictedDetector()
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{gpo}": {
				RestrictedGroups: []audit.RestrictedGroupSpec{
					{GroupSID: "Administrators", MembersSIDs: []string{"S-1-5-21-1-2-3-500"}},
				},
			},
		},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding (name-based principal restricts local Administrators), got %+v", findings)
	}
}

// TestM29_ExplicitEmptyMembers_NotFlagged is a red->green test for
// the nil-vs-absent bug: parseGroupMembership's parseSIDList("") returns nil
// for a value-less "*S-1-5-32-544__Members=" line (explicitly restricting
// local Administrators to NOBODY, the strictest possible hardening) - before
// the fix, that was indistinguishable from "never configured" and flagged as
// an M29 violation.
func TestM29_ExplicitEmptyMembers_NotFlagged(t *testing.T) {
	d := NewM29LocalAdminNotRestrictedDetector()
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{gpo}": {
				RestrictedGroups: []audit.RestrictedGroupSpec{
					{GroupSID: builtinAdministratorsSID, MembersSIDs: nil},
				},
			},
		},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding (explicit empty Members restricts local Administrators to nobody), got %+v", findings)
	}
}

// TestM29_NoRestrictedGroupsAtAll_StillFlagged is the sanity check that the
// fix didn't turn the detector into a no-op: a domain with GPO data but no
// [Group Membership] entry for BUILTIN\Administrators at all must still be
// flagged.
func TestM29_NoRestrictedGroupsAtAll_StillFlagged(t *testing.T) {
	d := NewM29LocalAdminNotRestrictedDetector()
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{gpo}": {RestrictedGroups: nil},
		},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected exactly 1 finding with Count=1, got %+v", findings)
	}
}

// TestM29_UnrelatedRestrictedGroup_StillFlagged confirms restricting a
// different group (not BUILTIN\Administrators) doesn't satisfy M29.
func TestM29_UnrelatedRestrictedGroup_StillFlagged(t *testing.T) {
	d := NewM29LocalAdminNotRestrictedDetector()
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{gpo}": {
				RestrictedGroups: []audit.RestrictedGroupSpec{
					{GroupSID: "S-1-5-32-551", MembersSIDs: []string{"S-1-5-21-1-2-3-1000"}}, // Backup Operators
				},
			},
		},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected exactly 1 finding with Count=1, got %+v", findings)
	}
}

// TestM29_NoGPOPoliciesAtAll_NoFinding kills the mutation removing the :39
// guard (`if len(data.GPOPolicies) == 0 { return nil }`). Without it, a nil
// or empty GPOPolicies map still falls through to the final wrapFinding call
// and emits a finding ("0 parsed GPO(s)") even though nothing was actually
// collected - a false positive for an unreachable SYSVOL rather than silence.
func TestM29_NoGPOPoliciesAtAll_NoFinding(t *testing.T) {
	d := NewM29LocalAdminNotRestrictedDetector()

	nilCase := &audit.DetectorData{GPOPolicies: nil}
	if findings := d.Detect(context.Background(), nilCase); len(findings) != 0 {
		t.Fatalf("nil GPOPolicies: expected no finding, got %+v", findings)
	}

	emptyCase := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{}}
	if findings := d.Detect(context.Background(), emptyCase); len(findings) != 0 {
		t.Fatalf("empty GPOPolicies: expected no finding, got %+v", findings)
	}
}

// TestM29_NilGPOEntry_SkippedWithoutPanic kills the mutation removing the
// :87 guard (`if p == nil { continue }`). Without it, a nil *GPOPolicy entry
// in the map (a plausible shape for a partially-parsed SYSVOL) dereferences
// p.RestrictedGroups and panics instead of being skipped.
func TestM29_NilGPOEntry_SkippedWithoutPanic(t *testing.T) {
	d := NewM29LocalAdminNotRestrictedDetector()

	// A nil entry followed by a GPO that genuinely restricts local Admins:
	// must not panic, and the restricting GPO still satisfies M29.
	mixed := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{nil-gpo}": nil,
			"{real-gpo}": {
				RestrictedGroups: []audit.RestrictedGroupSpec{
					{GroupSID: builtinAdministratorsSID, MembersSIDs: []string{"S-1-5-21-1-2-3-500"}},
				},
			},
		},
	}
	findings := d.Detect(context.Background(), mixed)
	if len(findings) != 0 {
		t.Fatalf("expected no finding (a non-nil GPO restricts local Administrators), got %+v", findings)
	}

	// A nil entry alone: must not panic, and must still be flagged (no GPO
	// actually restricts local Admins).
	nilOnly := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{nil-gpo}": nil,
		},
	}
	findings = d.Detect(context.Background(), nilOnly)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected exactly 1 finding with Count=1, got %+v", findings)
	}
}

// TestM29_FindingSeverity_IsMedium kills the mutation changing the finding's
// severity from types.SeverityMedium to types.SeverityHigh.
func TestM29_FindingSeverity_IsMedium(t *testing.T) {
	d := NewM29LocalAdminNotRestrictedDetector()
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{gpo}": {RestrictedGroups: nil},
		},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %+v", findings)
	}
	if findings[0].Severity != types.SeverityMedium {
		t.Fatalf("expected severity %v, got %v", types.SeverityMedium, findings[0].Severity)
	}
}

// TestM29_Description_ReportsParsedGPOCount kills the mutation replacing
// len(data.GPOPolicies) with 0 in the finding's Description text (mutation
// #16): with 2 unrestricted GPOs parsed, the Description must say "2 parsed
// GPO(s)", not "0 parsed GPO(s)".
func TestM29_Description_ReportsParsedGPOCount(t *testing.T) {
	d := NewM29LocalAdminNotRestrictedDetector()
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{gpo-1}": {RestrictedGroups: nil},
			"{gpo-2}": {RestrictedGroups: nil},
		},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %+v", findings)
	}
	if want := "2 parsed GPO(s)"; !strings.Contains(findings[0].Description, want) {
		t.Fatalf("Description = %q, want it to contain %q", findings[0].Description, want)
	}
}
