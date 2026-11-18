package dangerous

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

const dcsyncDomainDN = "DC=contoso,DC=com"
const dcsyncOtherObjectDN = "CN=LabPlants,DC=contoso,DC=com"

// TestDCSync_SingleRightNotCounted: holding only DS-Replication-Get-Changes
// (without -All) on the domain root cannot perform DCSync, but the old code
// counted a single right as sufficient.
func TestDCSync_SingleRightNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: dcsyncDomainDN},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   dcsyncDomainDN,
				Trustee:    "S-1-5-21-1-2-3-9999",
				ObjectType: types.GUIDDSReplicationGetChanges,
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_ALLOWED",
			},
		},
	}

	findings := NewDCSyncDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 (only one of the two required rights is held), got %d", findings[0].Count)
	}
}

// TestDCSync_BothRightsOffDomainRootNotCounted: the old code never checked
// ace.ObjectDN against the domain root, so both rights granted on an
// arbitrary object (not a domain-DNS NC head) were counted as DCSync, even
// though the rights are documented Applies-To Domain-DNS only.
func TestDCSync_BothRightsOffDomainRootNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: dcsyncDomainDN},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   dcsyncOtherObjectDN,
				Trustee:    "S-1-5-21-1-2-3-9999",
				ObjectType: types.GUIDDSReplicationGetChanges,
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_ALLOWED",
			},
			{
				ObjectDN:   dcsyncOtherObjectDN,
				Trustee:    "S-1-5-21-1-2-3-9999",
				ObjectType: types.GUIDDSReplicationGetChangesAll,
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_ALLOWED",
			},
		},
	}

	findings := NewDCSyncDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 (both rights held, but not on the domain root), got %d", findings[0].Count)
	}
}

// TestDCSync_BothRightsOnDomainRootCounted is the true-positive case: a
// trustee holding BOTH DS-Replication-Get-Changes and
// DS-Replication-Get-Changes-All on the domain root can perform DCSync.
// The two rights arrive on two separate ACEs for the SAME trustee: the old
// code (no per-trustee aggregation) stored both raw ACEs in `affected` and
// surfaced TotalInstances=2 for what is really a single logical capability;
// the fix aggregates per trustee first, so exactly one representative ACE is
// kept and TotalInstances stays unset (equal to Count, not reported
// separately) - this is what actually distinguishes old and new code here,
// since either implementation already fires (Count=1) on this fixture.
func TestDCSync_BothRightsOnDomainRootCounted(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: dcsyncDomainDN},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   dcsyncDomainDN,
				Trustee:    "S-1-5-21-1-2-3-9999",
				ObjectType: types.GUIDDSReplicationGetChanges,
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_ALLOWED",
			},
			{
				ObjectDN:   dcsyncDomainDN,
				Trustee:    "S-1-5-21-1-2-3-9999",
				ObjectType: types.GUIDDSReplicationGetChangesAll,
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_ALLOWED",
			},
		},
	}

	findings := NewDCSyncDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 (both rights held on the domain root), got %d", findings[0].Count)
	}
	if findings[0].TotalInstances != 0 {
		t.Fatalf("expected TotalInstances=0 (one trustee, aggregated to a single representative ACE, not two raw ACE matches), got %d", findings[0].TotalInstances)
	}
}

// TestDCSync_NonBuiltinGroupWithControlAccessEquivalentCounted covers the
// equivalent grant form: a single CONTROL_ACCESS ACE with an EMPTY
// ObjectType grants every extended right at once (MS-ADTS convention,
// mirrored from replicaRootHolders in
// accounts/advanced/replica-directory-changes.go), including both
// replication rights. The population here is any non-builtin-admin trustee
// (not just data.Users), so this also exercises a non-user trustee such as a
// domain group.
func TestDCSync_NonBuiltinGroupWithControlAccessEquivalentCounted(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: dcsyncDomainDN},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   dcsyncDomainDN,
				Trustee:    "S-1-5-21-1-2-3-5000", // non-builtin group SID, not resolved against data.Users
				ObjectType: "",
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_ALLOWED",
			},
		},
	}

	findings := NewDCSyncDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 (CONTROL_ACCESS with empty ObjectType grants both rights at once), got %d", findings[0].Count)
	}
}

// TestDCSync_GenericAllOnDomainRootCounted covers the second equivalent
// grant form: GenericAll subsumes every other right including both
// replication rights.
func TestDCSync_GenericAllOnDomainRootCounted(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: dcsyncDomainDN},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   dcsyncDomainDN,
				Trustee:    "S-1-5-21-1-2-3-9999",
				AccessMask: types.MaskGenericAll,
				AceType:    "ACCESS_ALLOWED",
			},
		},
	}

	findings := NewDCSyncDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 (GenericAll subsumes both replication rights), got %d", findings[0].Count)
	}
}

// TestDCSync_InheritOnlyOnDomainRootNotCounted: an INHERIT_ONLY ACE (MS-ADTS
// 3.1) does not apply to the object it is set on, only to descendants that
// inherit it. Both rights are granted to a non-privileged trustee on the
// domain root itself, but both ACEs carry InheritOnly: true, so neither
// right actually applies to the domain root and the trustee must not be
// counted.
func TestDCSync_InheritOnlyOnDomainRootNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: dcsyncDomainDN},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:    dcsyncDomainDN,
				Trustee:     "S-1-5-21-1-2-3-9999",
				ObjectType:  types.GUIDDSReplicationGetChanges,
				AccessMask:  types.MaskControlAccess,
				AceType:     "ACCESS_ALLOWED",
				InheritOnly: true,
			},
			{
				ObjectDN:    dcsyncDomainDN,
				Trustee:     "S-1-5-21-1-2-3-9999",
				ObjectType:  types.GUIDDSReplicationGetChangesAll,
				AccessMask:  types.MaskControlAccess,
				AceType:     "ACCESS_ALLOWED",
				InheritOnly: true,
			},
		},
	}

	findings := NewDCSyncDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 (both ACEs are InheritOnly, so neither applies to the domain root itself), got %d", findings[0].Count)
	}
}

// TestDCSync_DenyACEsNotCounted: a DENY ace grants nothing (DET_10). Both
// rights appear on the domain root for a non-privileged trustee, but both
// ACEs are ACCESS_DENIED, so the trustee holds neither right and must not be
// counted.
func TestDCSync_DenyACEsNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: dcsyncDomainDN},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   dcsyncDomainDN,
				Trustee:    "S-1-5-21-1-2-3-9999",
				ObjectType: types.GUIDDSReplicationGetChanges,
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_DENIED",
			},
			{
				ObjectDN:   dcsyncDomainDN,
				Trustee:    "S-1-5-21-1-2-3-9999",
				ObjectType: types.GUIDDSReplicationGetChangesAll,
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_DENIED",
			},
		},
	}

	findings := NewDCSyncDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 (DENY ACEs grant nothing), got %d", findings[0].Count)
	}
}

// TestDCSync_BuiltinAdminTrusteeNotCounted: SYSTEM (S-1-5-18) holds
// replication rights on every domain by construction - a DC cannot
// replicate without them. Reporting it describes AD's design, not a
// misconfiguration, so it must not be counted even though it holds both
// rights on the domain root.
func TestDCSync_BuiltinAdminTrusteeNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: dcsyncDomainDN},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   dcsyncDomainDN,
				Trustee:    "S-1-5-18",
				ObjectType: types.GUIDDSReplicationGetChanges,
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_ALLOWED",
			},
			{
				ObjectDN:   dcsyncDomainDN,
				Trustee:    "S-1-5-18",
				ObjectType: types.GUIDDSReplicationGetChangesAll,
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_ALLOWED",
			},
		},
	}

	findings := NewDCSyncDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 (SYSTEM is a built-in admin trustee, expected to hold replication rights by design), got %d", findings[0].Count)
	}
}

// TestDCSync_DomainRootDNCaseInsensitive: the domain-root comparison in
// Detect lowercases both ace.ObjectDN and the domain DN before comparing, so
// an ACE whose ObjectDN is written in a different case than
// DomainInfo.DomainDN must still match the domain root and be counted for a
// non-privileged trustee holding both rights.
func TestDCSync_DomainRootDNCaseInsensitive(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: dcsyncDomainDN},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   "dc=CONTOSO,dc=COM",
				Trustee:    "S-1-5-21-1-2-3-9999",
				ObjectType: types.GUIDDSReplicationGetChanges,
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_ALLOWED",
			},
			{
				ObjectDN:   "dc=CONTOSO,dc=COM",
				Trustee:    "S-1-5-21-1-2-3-9999",
				ObjectType: types.GUIDDSReplicationGetChangesAll,
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_ALLOWED",
			},
		},
	}

	findings := NewDCSyncDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 (ObjectDN case must not prevent matching the domain root), got %d", findings[0].Count)
	}
}

// TestDCSync_M12_EmptyDomainDNEarlyReturnLocksOriginalBehavior locks that
// when DomainInfo resolves to an empty domain root (both DomainDN and DN
// are empty), the detector returns the zero finding without ever
// inspecting ACLEntries - an ACE at ObjectDN="" that would otherwise
// qualify is never reached.
func TestDCSync_M12_EmptyDomainDNEarlyReturnLocksOriginalBehavior(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: "", DN: ""},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   "",
				Trustee:    "S-1-5-21-1-2-3-9999",
				AccessMask: types.MaskGenericAll,
				AceType:    "ACCESS_ALLOWED",
			},
		},
	}

	findings := NewDCSyncDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 (an empty domain root short-circuits before any ACE is examined), got %d", findings[0].Count)
	}
}

// TestDCSync_M15_NilDomainInfoNoPanic locks that a nil DomainInfo does not
// panic and leaves the detector with no domain root to match against, so no
// trustee is ever counted.
func TestDCSync_M15_NilDomainInfoNoPanic(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: nil,
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   dcsyncDomainDN,
				Trustee:    "S-1-5-21-1-2-3-9999",
				AccessMask: types.MaskGenericAll,
				AceType:    "ACCESS_ALLOWED",
			},
		},
	}

	findings := NewDCSyncDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 (nil DomainInfo leaves no domain root to match against), got %d", findings[0].Count)
	}
}

// TestDCSync_M16_DomainDNFallsBackToDN locks the fallback: when
// DomainInfo.DomainDN is empty but DomainInfo.DN carries the root DN, the
// detector must still use DN as the domain root and count a qualifying ACE
// placed there.
func TestDCSync_M16_DomainDNFallsBackToDN(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: "", DN: dcsyncDomainDN},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   dcsyncDomainDN,
				Trustee:    "S-1-5-21-1-2-3-9999",
				AccessMask: types.MaskGenericAll,
				AceType:    "ACCESS_ALLOWED",
			},
		},
	}

	findings := NewDCSyncDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 (an empty DomainDN must fall back to DN as the domain root), got %d", findings[0].Count)
	}
}

// TestDCSync_M24_TwoTrusteesOnRootReportsTotalInstances locks TotalInstances:
// two distinct trustees each qualifying on the same domain-root object
// collapse to a single unique object (Count=1, deduplicated by ObjectDN),
// but the raw per-trustee match count must still be reported separately.
func TestDCSync_M24_TwoTrusteesOnRootReportsTotalInstances(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: dcsyncDomainDN},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   dcsyncDomainDN,
				Trustee:    "S-1-5-21-1-2-3-9999",
				AccessMask: types.MaskGenericAll,
				AceType:    "ACCESS_ALLOWED",
			},
			{
				ObjectDN:   dcsyncDomainDN,
				Trustee:    "S-1-5-21-1-2-3-8888",
				AccessMask: types.MaskGenericAll,
				AceType:    "ACCESS_ALLOWED",
			},
		},
	}

	findings := NewDCSyncDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 (both trustees qualify on the same domain-root object, deduplicated by ObjectDN), got %d", findings[0].Count)
	}
	if findings[0].TotalInstances != 2 {
		t.Fatalf("expected TotalInstances=2 (two distinct trustees collapsed into one unique object), got %d", findings[0].TotalInstances)
	}
}

// TestDCSync_M27_IncludeDetailsFalseAffectedEntitiesNil locks that
// AffectedEntities stays empty for a positive finding when the caller does
// not request IncludeDetails.
func TestDCSync_M27_IncludeDetailsFalseAffectedEntitiesNil(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo:     &types.DomainInfo{DomainDN: dcsyncDomainDN},
		IncludeDetails: false,
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   dcsyncDomainDN,
				Trustee:    "S-1-5-21-1-2-3-9999",
				AccessMask: types.MaskGenericAll,
				AceType:    "ACCESS_ALLOWED",
			},
		},
	}

	findings := NewDCSyncDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 (precondition for a positive finding), got %d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 0 {
		t.Fatalf("AffectedEntities = %v, want empty when IncludeDetails=false", findings[0].AffectedEntities)
	}
}
