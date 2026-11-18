package moderate

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// The detector never checked AceType, so a DENY ACE carrying the
// GenericAll/GenericWrite/WriteDACL bits was counted the same as an ALLOW
// grant - the bug signature (a DENY ACE grants nothing). This test
// fails against the old code (the DENY ACE is wrongly counted, Count=1) and
// passes once AceType is checked via audit.IsGrantACE (Count=0).
func TestGPOLinkPoisoning_DenyACEDoesNotCount(t *testing.T) {
	const writeDACL = 0x00040000
	containerDN := "CN=Policies,CN=System,DC=test,DC=local"

	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: containerDN, Trustee: "S-1-5-21-1-2-3-1234", AccessMask: writeDACL, AceType: "ACCESS_DENIED"},
		},
	}

	findings := NewGPOLinkPoisoningDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (a DENY ACE must not count as a dangerous grant)", findings[0].Count)
	}
}

// An ALLOW grant with a dangerous bit on the Policies container is still
// caught - the fix must not silence real positives.
func TestGPOLinkPoisoning_AllowACEStillCounts(t *testing.T) {
	const writeDACL = 0x00040000
	containerDN := "CN=Policies,CN=System,DC=test,DC=local"

	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: containerDN, Trustee: "S-1-5-21-1-2-3-1234", AccessMask: writeDACL, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewGPOLinkPoisoningDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (a real ALLOW grant must still be caught)", findings[0].Count)
	}
}

// The default ACEs on CN=Policies,CN=System grant SYSTEM, Domain Admins,
// Enterprise Admins and BUILTIN\Administrators the dangerous bits this
// detector looks for - on every standard domain, with no delegation
// anomaly. Without filtering these built-in/privileged trustees out, the
// detector false-positives domain-wide (Count=1, TotalInstances=4). This
// test fails against the old code (Count=0 expected, Count=1 observed
// because none of the 4 ACEs were excluded) and passes once
// audit.IsBuiltinAdminTrustee filters them.
func TestGPOLinkPoisoning_BuiltinAdminTrusteesNotCounted(t *testing.T) {
	const genericAll = 0x10000000
	containerDN := "CN=Policies,CN=System,DC=example,DC=com"

	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: containerDN, Trustee: "S-1-5-18", AccessMask: genericAll, AceType: "ACCESS_ALLOWED"},           // SYSTEM
			{ObjectDN: containerDN, Trustee: "S-1-5-21-1-2-3-512", AccessMask: genericAll, AceType: "ACCESS_ALLOWED"}, // Domain Admins
			{ObjectDN: containerDN, Trustee: "S-1-5-21-1-2-3-519", AccessMask: genericAll, AceType: "ACCESS_ALLOWED"}, // Enterprise Admins
			{ObjectDN: containerDN, Trustee: "S-1-5-32-544", AccessMask: genericAll, AceType: "ACCESS_ALLOWED"},       // BUILTIN\Administrators
		},
	}

	findings := NewGPOLinkPoisoningDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (SYSTEM/Domain Admins/Enterprise Admins/BUILTIN\\Administrators default ACEs must not count)", findings[0].Count)
	}
}

// A dangerous grant to an ordinary domain user on the same container is a
// real anomaly and must still be caught after the built-in/privileged
// trustee exclusion is added.
func TestGPOLinkPoisoning_OrdinaryUserStillCounts(t *testing.T) {
	const genericAll = 0x10000000
	containerDN := "CN=Policies,CN=System,DC=example,DC=com"

	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: containerDN, Trustee: "S-1-5-21-1-2-3-1234", AccessMask: genericAll, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewGPOLinkPoisoningDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (a dangerous grant to an ordinary user must still be caught)", findings[0].Count)
	}
}

// The dangerous-permission mask includes GenericWrite (0x40000000). An ACE
// that carries only this bit, with no GenericAll or WriteDACL, must still be
// counted.
func TestGPOLinkPoisoning_GenericWriteCounts(t *testing.T) {
	const genericWrite = 0x40000000
	containerDN := "CN=Policies,CN=System,DC=test,DC=local"

	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: containerDN, Trustee: "S-1-5-21-1-2-3-1234", AccessMask: genericWrite, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewGPOLinkPoisoningDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (a GenericWrite-only grant must still be caught)", findings[0].Count)
	}
}

// An ALLOW grant to an ordinary trustee on the container, but carrying none
// of the three dangerous bits, must not be counted. Combined with
// OtherObjectNotCounted below, this also kills a mutation that drops the
// container-AND-mask guard entirely and appends every grant ACE
// unconditionally.
func TestGPOLinkPoisoning_NonDangerousMaskNotCounted(t *testing.T) {
	const readOnlyMask = 0x00020094
	containerDN := "CN=Policies,CN=System,DC=test,DC=local"

	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: containerDN, Trustee: "S-1-5-21-1-2-3-1234", AccessMask: readOnlyMask, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewGPOLinkPoisoningDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (a non-dangerous mask must not be counted)", findings[0].Count)
	}
}

// A dangerous ALLOW grant on an object outside the GPO container must not be
// counted. Combined with NonDangerousMaskNotCounted above, this kills the
// mutation that drops the container-AND-mask guard entirely: without the
// guard, this ACE would be appended unconditionally.
func TestGPOLinkPoisoning_OtherObjectNotCounted(t *testing.T) {
	const genericAll = 0x10000000
	otherDN := "CN=SomeOtherObject,DC=test,DC=local"

	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: otherDN, Trustee: "S-1-5-21-1-2-3-1234", AccessMask: genericAll, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewGPOLinkPoisoningDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (an object outside the GPO container must not be counted)", findings[0].Count)
	}
}

// TotalInstances reports the raw ACE count only when it differs from the
// deduplicated object count. Two dangerous ACEs on the same container (two
// distinct trustees) must set TotalInstances=2 against Count=1; a single ACE
// must leave TotalInstances unset (0).
func TestGPOLinkPoisoning_TotalInstances(t *testing.T) {
	const genericAll = 0x10000000
	containerDN := "CN=Policies,CN=System,DC=test,DC=local"

	multi := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: containerDN, Trustee: "S-1-5-21-1-2-3-1234", AccessMask: genericAll, AceType: "ACCESS_ALLOWED"},
			{ObjectDN: containerDN, Trustee: "S-1-5-21-1-2-3-5678", AccessMask: genericAll, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewGPOLinkPoisoningDetector().Detect(context.Background(), multi)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (two trustees on the same container dedupe to one object)", findings[0].Count)
	}
	if findings[0].TotalInstances != 2 {
		t.Fatalf("TotalInstances = %d, want 2 (two distinct trustees on the same container)", findings[0].TotalInstances)
	}

	single := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: containerDN, Trustee: "S-1-5-21-1-2-3-1234", AccessMask: genericAll, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings = NewGPOLinkPoisoningDetector().Detect(context.Background(), single)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].TotalInstances != 0 {
		t.Fatalf("TotalInstances = %d, want 0 (not set when it equals the unique object count)", findings[0].TotalInstances)
	}
}

// AffectedEntities is populated only when IncludeDetails is requested, and
// only then.
func TestGPOLinkPoisoning_AffectedEntitiesOnlyWithDetails(t *testing.T) {
	const genericAll = 0x10000000
	containerDN := "CN=Policies,CN=System,DC=test,DC=local"
	aces := []types.ACLEntry{
		{ObjectDN: containerDN, Trustee: "S-1-5-21-1-2-3-1234", AccessMask: genericAll, AceType: "ACCESS_ALLOWED"},
	}

	withDetails := &audit.DetectorData{ACLEntries: aces, IncludeDetails: true}
	findings := NewGPOLinkPoisoningDetector().Detect(context.Background(), withDetails)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if len(findings[0].AffectedEntities) != 1 {
		t.Fatalf("AffectedEntities count = %d, want 1 when IncludeDetails is true", len(findings[0].AffectedEntities))
	}
	if findings[0].AffectedEntities[0].Type != "gpo" {
		t.Fatalf("AffectedEntities[0].Type = %q, want %q", findings[0].AffectedEntities[0].Type, "gpo")
	}
	if findings[0].AffectedEntities[0].DN != containerDN {
		t.Fatalf("AffectedEntities[0].DN = %q, want %q", findings[0].AffectedEntities[0].DN, containerDN)
	}

	withoutDetails := &audit.DetectorData{ACLEntries: aces, IncludeDetails: false}
	findings = NewGPOLinkPoisoningDetector().Detect(context.Background(), withoutDetails)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if len(findings[0].AffectedEntities) != 0 {
		t.Fatalf("AffectedEntities count = %d, want 0 when IncludeDetails is false", len(findings[0].AffectedEntities))
	}
}
