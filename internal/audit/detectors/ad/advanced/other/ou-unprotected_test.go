package other

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// acl_parser.go's aceTypeToString only ever emits "ACCESS_DENIED" or
// "ACCESS_DENIED_OBJECT" for a deny ACE - never "ACCESS_DENIED_ACE". The
// old comparison against "ACCESS_DENIED_ACE" therefore never matched
// anything, so protectedOUs stayed empty and every OU was reported
// unprotected regardless of a real Deny-Delete ACE for Everyone. This test
// fails against the old string (the protected OU is still reported as
// unprotected) and passes once the comparison targets "ACCESS_DENIED".
func TestOUUnprotected_RecognizesRealDenyDeleteACE(t *testing.T) {
	const deleteRight = 0x10000
	data := &audit.DetectorData{
		OUs: []types.OU{
			{DN: "OU=Protected,DC=test,DC=local"},
			{DN: "OU=Unprotected,DC=test,DC=local"},
		},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   "OU=Protected,DC=test,DC=local",
				Trustee:    "S-1-1-0",
				AccessMask: deleteRight,
				AceType:    "ACCESS_DENIED",
			},
		},
	}

	findings := NewOUUnprotectedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (only OU=Unprotected should be reported)", findings[0].Count)
	}
}

// Branch E (ANALYSE.md §2.E / §4): a Deny-DELETE ACE for a trustee other than
// S-1-1-0 (Everyone) does not recognize protection - acl.Trustee == "S-1-1-0"
// (ou-unprotected.go:42) is false, so the OU is reported as unprotected. This
// is the intended behavior: only the "Everyone" deny posed by "Protect object
// from accidental deletion" counts.
func TestOUUnprotected_OtherTrusteeDenyDeleteIsNotProtection(t *testing.T) {
	const deleteRight = 0x10000
	data := &audit.DetectorData{
		OUs: []types.OU{
			{DN: "OU=Finance,DC=test,DC=local"},
		},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   "OU=Finance,DC=test,DC=local",
				Trustee:    "S-1-5-21-111111111-222222222-333333333-5001",
				AccessMask: deleteRight,
				AceType:    "ACCESS_DENIED",
			},
		},
	}

	findings := NewOUUnprotectedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (the OU must be reported: the deny ACE does not target Everyone)", findings[0].Count)
	}
}

// Branch F (ANALYSE.md §2.F / §4): an OU named "Domain Controllers" carries no
// special-case exclusion in the detector (no name or system-flag check) - its
// report depends only on its real ACL, exactly like any other OU.
func TestOUUnprotected_DomainControllersOUHasNoExclusion(t *testing.T) {
	data := &audit.DetectorData{
		OUs: []types.OU{
			{DN: "OU=Domain Controllers,DC=test,DC=local"},
		},
		ACLEntries: []types.ACLEntry{},
	}

	findings := NewOUUnprotectedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (the Domain Controllers OU gets no exclusion, it is reported like any unprotected OU)", findings[0].Count)
	}
}

// Branch H (ANALYSE.md §1.5 / §2.H): an OU with no security descriptor read
// at all (no ACLEntry for its DN) is reported as unprotected even though its
// real protection state is unknown. This is a documented structural false
// positive (bias toward over-reporting, never silently hidden) - not a defect
// fixed by this ticket, but the detector's current, intentional behavior
// given absent data.
func TestOUUnprotected_NoACLEntryAtAllIsReportedUnprotected(t *testing.T) {
	data := &audit.DetectorData{
		OUs: []types.OU{
			{DN: "OU=NoSD,DC=test,DC=local"},
		},
		ACLEntries: nil,
	}

	findings := NewOUUnprotectedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (absent ACL data is a structural FP: the OU is reported unprotected)", findings[0].Count)
	}
}

// Allow-DELETE (not Deny) for S-1-1-0: AceType "ACCESS_ALLOWED" never matches
// strings.EqualFold(acl.AceType, "ACCESS_DENIED") (ou-unprotected.go:41), so
// the OU is reported as unprotected regardless of the access mask. An Allow
// ACE grants deletion, it does not protect against it - this is correct.
func TestOUUnprotected_AllowDeleteIsNotProtection(t *testing.T) {
	const deleteRight = 0x10000
	data := &audit.DetectorData{
		OUs: []types.OU{
			{DN: "OU=Sales,DC=test,DC=local"},
		},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   "OU=Sales,DC=test,DC=local",
				Trustee:    "S-1-1-0",
				AccessMask: deleteRight,
				AceType:    "ACCESS_ALLOWED",
			},
		},
	}

	findings := NewOUUnprotectedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (an Allow-DELETE ACE for Everyone is not protection)", findings[0].Count)
	}
}

// The mask sub-term is load-bearing on its own: a Deny ACE for S-1-1-0 whose
// AccessMask carries no DELETE bit at all (an unrelated right, not the
// DELETE_TREE case reserved as a known defect) must not be treated as
// protection (ou-unprotected.go:43, (acl.AccessMask&deleteRight) != 0).
func TestOUUnprotected_DenyACEWithUnrelatedRightIsNotProtection(t *testing.T) {
	const genericRead = 0x1
	data := &audit.DetectorData{
		OUs: []types.OU{
			{DN: "OU=Marketing,DC=test,DC=local"},
		},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   "OU=Marketing,DC=test,DC=local",
				Trustee:    "S-1-1-0",
				AccessMask: genericRead,
				AceType:    "ACCESS_DENIED",
			},
		},
	}

	findings := NewOUUnprotectedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (a deny ACE unrelated to DELETE must not count as protection)", findings[0].Count)
	}
}

// Counting: several OUs, some protected and some not, must produce an exact
// Count (ou-unprotected.go:61, Count = len(unprotected)) - not the total
// number of OUs, not a fixed value.
func TestOUUnprotected_CountIsExactAcrossMultipleOUs(t *testing.T) {
	const deleteRight = 0x10000
	data := &audit.DetectorData{
		OUs: []types.OU{
			{DN: "OU=Protected1,DC=test,DC=local"},
			{DN: "OU=Protected2,DC=test,DC=local"},
			{DN: "OU=Unprotected1,DC=test,DC=local"},
			{DN: "OU=Unprotected2,DC=test,DC=local"},
			{DN: "OU=Unprotected3,DC=test,DC=local"},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "OU=Protected1,DC=test,DC=local", Trustee: "S-1-1-0", AccessMask: deleteRight, AceType: "ACCESS_DENIED"},
			{ObjectDN: "OU=Protected2,DC=test,DC=local", Trustee: "S-1-1-0", AccessMask: deleteRight, AceType: "ACCESS_DENIED"},
		},
	}

	findings := NewOUUnprotectedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 3 {
		t.Fatalf("Count = %d, want 3 (2 of 5 OUs are protected, 3 remain unprotected)", findings[0].Count)
	}
}

// Deduplication: two protecting ACEs on the same OU (e.g. one explicit, one
// inherited, or simply duplicated) must count that OU once. protectedOUs is a
// map keyed by ObjectDN (ou-unprotected.go:44), so a second matching ACE for
// the same DN is a no-op, not a second entry.
func TestOUUnprotected_TwoProtectingACEsOnSameOUCountOnce(t *testing.T) {
	const deleteRight = 0x10000
	data := &audit.DetectorData{
		OUs: []types.OU{
			{DN: "OU=DoubleProtected,DC=test,DC=local"},
			{DN: "OU=Unprotected,DC=test,DC=local"},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "OU=DoubleProtected,DC=test,DC=local", Trustee: "S-1-1-0", AccessMask: deleteRight, AceType: "ACCESS_DENIED"},
			{ObjectDN: "OU=DoubleProtected,DC=test,DC=local", Trustee: "S-1-1-0", AccessMask: deleteRight, AceType: "access_denied"},
		},
	}

	findings := NewOUUnprotectedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (OU=DoubleProtected has two protecting ACEs but must count once; only OU=Unprotected is reported)", findings[0].Count)
	}
}

// IncludeDetails=false must keep AffectedEntities nil even though there are
// unprotected OUs (ou-unprotected.go:64 guards on data.IncludeDetails).
func TestOUUnprotected_IncludeDetailsFalseKeepsEntitiesNil(t *testing.T) {
	data := &audit.DetectorData{
		OUs: []types.OU{
			{DN: "OU=Unprotected,DC=test,DC=local"},
		},
		ACLEntries:     []types.ACLEntry{},
		IncludeDetails: false,
	}

	findings := NewOUUnprotectedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
	if findings[0].AffectedEntities != nil {
		t.Fatalf("AffectedEntities = %#v, want nil when IncludeDetails is false", findings[0].AffectedEntities)
	}
}

// IncludeDetails=true must produce exactly one AffectedEntity per unprotected
// OU, of Type "ou", carrying its DN (ou-unprotected.go:64-73).
func TestOUUnprotected_IncludeDetailsTrueProducesOneEntityPerUnprotectedOU(t *testing.T) {
	const deleteRight = 0x10000
	data := &audit.DetectorData{
		OUs: []types.OU{
			{DN: "OU=Protected,DC=test,DC=local"},
			{DN: "OU=Unprotected1,DC=test,DC=local"},
			{DN: "OU=Unprotected2,DC=test,DC=local"},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "OU=Protected,DC=test,DC=local", Trustee: "S-1-1-0", AccessMask: deleteRight, AceType: "ACCESS_DENIED"},
		},
		IncludeDetails: true,
	}

	findings := NewOUUnprotectedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 2 {
		t.Fatalf("Count = %d, want 2", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 2 {
		t.Fatalf("len(AffectedEntities) = %d, want 2 (one per unprotected OU)", len(findings[0].AffectedEntities))
	}
	wantDNs := map[string]bool{
		"OU=Unprotected1,DC=test,DC=local": false,
		"OU=Unprotected2,DC=test,DC=local": false,
	}
	for _, e := range findings[0].AffectedEntities {
		if e.Type != "ou" {
			t.Fatalf("AffectedEntity.Type = %q, want %q", e.Type, "ou")
		}
		if _, ok := wantDNs[e.DN]; !ok {
			t.Fatalf("unexpected AffectedEntity.DN %q", e.DN)
		}
		wantDNs[e.DN] = true
	}
	for dn, seen := range wantDNs {
		if !seen {
			t.Fatalf("expected an AffectedEntity for %q, none found", dn)
		}
	}
}

// IncludeDetails=true with no unprotected OU (Count=0) must keep
// AffectedEntities nil, not an empty non-nil slice - the guard at
// ou-unprotected.go:64 tests len(unprotected) > 0 as well as IncludeDetails,
// specifically to avoid entities := make([]types.AffectedEntity, 0, 0) ever
// being assigned when there is nothing to report.
func TestOUUnprotected_IncludeDetailsTrueNoUnprotectedOUsEntitiesStayNil(t *testing.T) {
	const deleteRight = 0x10000
	data := &audit.DetectorData{
		OUs: []types.OU{
			{DN: "OU=Protected,DC=test,DC=local"},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "OU=Protected,DC=test,DC=local", Trustee: "S-1-1-0", AccessMask: deleteRight, AceType: "ACCESS_DENIED"},
		},
		IncludeDetails: true,
	}

	findings := NewOUUnprotectedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
	if findings[0].AffectedEntities != nil {
		t.Fatalf("AffectedEntities = %#v, want nil when there are no unprotected OUs", findings[0].AffectedEntities)
	}
}

// Severity is always Low (ou-unprotected.go:57), regardless of how many OUs
// are unprotected.
func TestOUUnprotected_SeverityIsAlwaysLow(t *testing.T) {
	data := &audit.DetectorData{
		OUs: []types.OU{
			{DN: "OU=Unprotected,DC=test,DC=local"},
		},
		ACLEntries: []types.ACLEntry{},
	}

	findings := NewOUUnprotectedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityLow {
		t.Fatalf("Severity = %q, want %q", findings[0].Severity, types.SeverityLow)
	}
}
