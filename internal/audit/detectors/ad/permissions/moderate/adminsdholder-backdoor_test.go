package moderate

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

const adminSDHolderDN = "CN=AdminSDHolder,CN=System,DC=contoso,DC=com"

// TestAdminSDHolderBackdoor_FiltersBaselineACEs covers a bug where the
// detector counted every ACE on AdminSDHolder as a "backdoor", including the
// baseline SDProp grants (Domain Admins, deny-ACEs) that exist on every AD
// domain by construction. Sibling detectors (writeowner.go, genericall.go,
// and others) already filter grant-only + non-admin trustees - this detector
// never received those two filters.
func TestAdminSDHolderBackdoor_FiltersBaselineACEs(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			// Baseline: Domain Admins grant - expected, not a finding.
			{ObjectDN: adminSDHolderDN, Trustee: "S-1-5-21-1-2-3-512", AccessMask: 0x000F01FF, AceType: "ACCESS_ALLOWED"},
			// Baseline: a DENY ace grants nothing.
			{ObjectDN: adminSDHolderDN, Trustee: "S-1-5-21-1-2-3-9999", AccessMask: 0x000F01FF, AceType: "ACCESS_DENIED"},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 (baseline SDProp ACEs must not count as a backdoor), got %d", findings[0].Count)
	}
}

// TestAdminSDHolderBackdoor_FiresOnNonAdminGrant guards against
// over-filtering: a real grant to a non-admin trustee must still fire.
func TestAdminSDHolderBackdoor_FiresOnNonAdminGrant(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: adminSDHolderDN, Trustee: "S-1-5-21-1-2-3-9999", AccessMask: 0x000F01FF, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 for a real non-admin grant, got %d", findings[0].Count)
	}
}

// TestAdminSDHolderBackdoor_ExcludesReadOnlyGrant: the detector never read
// ace.AccessMask, so a read-only ACE (ReadProperty) to a non-admin trustee -
// Authenticated Users holds exactly this by default on AdminSDHolder
// (Appendix K) - was counted identically to a GenericAll grant. A read-only
// right is not a persistence backdoor.
func TestAdminSDHolderBackdoor_ExcludesReadOnlyGrant(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: adminSDHolderDN, Trustee: "S-1-5-11", AccessMask: types.MaskReadProperty, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 (ReadProperty-only grant is not a backdoor), got %d", findings[0].Count)
	}
}

// TestAdminSDHolderBackdoor_ExcludesDocumentedDefaultACE: the detector
// counted AdminSDHolder's own documented default security descriptor
// (Microsoft Learn, Appendix K) as a backdoor on any unmodified domain. Cert
// Publishers (well-known RID 517) carries a default WriteProperty grant on
// userCert (bf967a7f-0de6-11d0-a285-00aa003049e2) for certificate enrollment
// - legitimate baseline, not an attacker-added ACE.
func TestAdminSDHolderBackdoor_ExcludesDocumentedDefaultACE(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   adminSDHolderDN,
				Trustee:    "S-1-5-21-1-2-3-517",
				ObjectType: "bf967a7f-0de6-11d0-a285-00aa003049e2",
				AccessMask: types.MaskWriteProperty,
				AceType:    "ACCESS_ALLOWED",
			},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 (Cert Publishers' default userCert ACE is baseline, not a backdoor), got %d", findings[0].Count)
	}
}

// TestAdminSDHolderBackdoor_CountsGenericAllForOrdinaryUser guards against
// over-filtering: a GenericAll grant to an ordinary (non-baseline, non-admin)
// user must still fire at full severity.
func TestAdminSDHolderBackdoor_CountsGenericAllForOrdinaryUser(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: adminSDHolderDN, Trustee: "S-1-5-21-1-2-3-9999", AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 for a GenericAll grant to an ordinary user, got %d", findings[0].Count)
	}
}

// TestAdminSDHolderBackdoor_RecognizesLowercaseDN: the DN comparison was
// case-sensitive (strings.Contains), so a collector that normalized
// AdminSDHolder's DN to lowercase would let a real backdoor ACE escape
// detection silently.
func TestAdminSDHolderBackdoor_RecognizesLowercaseDN(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "cn=adminsdholder,cn=system,dc=contoso,dc=com", Trustee: "S-1-5-21-1-2-3-9999", AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 for a lowercase AdminSDHolder DN, got %d", findings[0].Count)
	}
}

// TestAdminSDHolderBackdoor_IgnoresWriteGrantOnOtherObject guards the DN
// filter itself: a write grant to an ordinary (non-admin) trustee on an
// object OTHER than AdminSDHolder must never be reported by this detector -
// that is some other object's ACL, not an AdminSDHolder backdoor.
func TestAdminSDHolderBackdoor_IgnoresWriteGrantOnOtherObject(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=OtherObject,CN=System,DC=contoso,DC=com", Trustee: "S-1-5-21-1-2-3-9999", AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 (ACE targets a different object than AdminSDHolder), got %d", findings[0].Count)
	}
}

// TestAdminSDHolderBackdoor_ExcludesEveryoneChangePasswordRight covers the
// exact-SID baseline branch: Everyone (S-1-1-0) holds the Change Password
// CONTROL_ACCESS extended right (ab721a53-1e2f-11d0-9819-00aa0040529b) by
// default on AdminSDHolder (Appendix K). This must be filtered as baseline,
// not reported as a backdoor.
func TestAdminSDHolderBackdoor_ExcludesEveryoneChangePasswordRight(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   adminSDHolderDN,
				Trustee:    "S-1-1-0",
				ObjectType: "ab721a53-1e2f-11d0-9819-00aa0040529b",
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_ALLOWED",
			},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 (Everyone's default Change Password right is baseline, not a backdoor), got %d", findings[0].Count)
	}
}

// TestAdminSDHolderBackdoor_CountsNonCertPublishersWriteProperty covers the
// RID-suffix baseline branch: the WriteProperty grant on userCert
// (bf967a7f-0de6-11d0-a285-00aa003049e2) is only baseline for Cert
// Publishers (RID -517). The identical grant to a trustee that does NOT end
// in -517 is not that documented default and must still be reported.
func TestAdminSDHolderBackdoor_CountsNonCertPublishersWriteProperty(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   adminSDHolderDN,
				Trustee:    "S-1-5-21-1-2-3-9999",
				ObjectType: "bf967a7f-0de6-11d0-a285-00aa003049e2",
				AccessMask: types.MaskWriteProperty,
				AceType:    "ACCESS_ALLOWED",
			},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 (trustee does not end in -517, so this is not Cert Publishers' baseline), got %d", findings[0].Count)
	}
}

// TestAdminSDHolderBackdoor_CountsCertPublishersSuffixWithDifferentObjectType
// covers the ObjectType comparison of the baseline match: a trustee that DOES
// end in -517 (matching Cert Publishers' RID suffix) but whose ACE carries a
// DIFFERENT ObjectType than the documented userCert property
// (bf967a7f-0de6-11d0-a285-00aa003049e2) is not that baseline grant and must
// still be reported.
func TestAdminSDHolderBackdoor_CountsCertPublishersSuffixWithDifferentObjectType(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   adminSDHolderDN,
				Trustee:    "S-1-5-21-1-2-3-517",
				ObjectType: "99999999-0000-0000-0000-000000000000",
				AccessMask: types.MaskWriteProperty,
				AceType:    "ACCESS_ALLOWED",
			},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 (ObjectType differs from Cert Publishers' documented userCert baseline), got %d", findings[0].Count)
	}
}

// TestAdminSDHolderBackdoor_CountsBaselineTrusteeWithOutOfMaskBit covers the
// access-mask comparison of the baseline match: Terminal Server License
// Servers (S-1-5-32-561) has a default WriteProperty grant, not scoped to any
// ObjectType. The SAME trustee granted a DIFFERENT write/control bit
// (WriteDACL, outside the documented baseline mask) is not that default ACE
// and must still be reported.
func TestAdminSDHolderBackdoor_CountsBaselineTrusteeWithOutOfMaskBit(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   adminSDHolderDN,
				Trustee:    "S-1-5-32-561",
				AccessMask: types.MaskWriteDACL,
				AceType:    "ACCESS_ALLOWED",
			},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 (WriteDACL is outside the documented baseline mask for this trustee), got %d", findings[0].Count)
	}
}

// TestAdminSDHolderBackdoor_SetsTotalInstancesWhenDuplicated covers
// TotalInstances: two distinct backdoor ACEs on the SAME AdminSDHolder object
// must collapse to one unique object (Count=1) while still reporting the raw
// instance count (TotalInstances=2).
func TestAdminSDHolderBackdoor_SetsTotalInstancesWhenDuplicated(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: adminSDHolderDN, Trustee: "S-1-5-21-1-2-3-9001", AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED"},
			{ObjectDN: adminSDHolderDN, Trustee: "S-1-5-21-1-2-3-9002", AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 (single unique object), got %d", findings[0].Count)
	}
	if findings[0].TotalInstances != 2 {
		t.Fatalf("expected TotalInstances=2 (two distinct backdoor ACEs on the same object), got %d", findings[0].TotalInstances)
	}
}

// TestAdminSDHolderBackdoor_OmitsTotalInstancesWhenNoDuplicates covers the
// complementary case: with exactly one backdoor ACE, TotalInstances equals
// Count and must be left unset (zero value), not redundantly populated.
func TestAdminSDHolderBackdoor_OmitsTotalInstancesWhenNoDuplicates(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: adminSDHolderDN, Trustee: "S-1-5-21-1-2-3-9001", AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].TotalInstances != 0 {
		t.Fatalf("expected TotalInstances=0 (equals Count, must stay unset), got %d", findings[0].TotalInstances)
	}
}

// TestAdminSDHolderBackdoor_PopulatesAffectedEntitiesWhenIncludeDetails
// covers IncludeDetails=true: with a real backdoor ACE present,
// AffectedEntities must be populated.
func TestAdminSDHolderBackdoor_PopulatesAffectedEntitiesWhenIncludeDetails(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: adminSDHolderDN, Trustee: "S-1-5-21-1-2-3-9001", AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED"},
		},
		IncludeDetails: true,
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if len(findings[0].AffectedEntities) == 0 {
		t.Fatalf("expected AffectedEntities to be populated when IncludeDetails=true, got empty")
	}
}

// TestAdminSDHolderBackdoor_OmitsAffectedEntitiesWhenDetailsDisabled covers
// the complementary case: with the SAME real backdoor ACE (Count=1) but
// IncludeDetails=false, AffectedEntities must stay empty.
func TestAdminSDHolderBackdoor_OmitsAffectedEntitiesWhenDetailsDisabled(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: adminSDHolderDN, Trustee: "S-1-5-21-1-2-3-9001", AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED"},
		},
		IncludeDetails: false,
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count == 0 {
		t.Fatalf("expected Count>0 for this test to be meaningful, got 0")
	}
	if len(findings[0].AffectedEntities) != 0 {
		t.Fatalf("expected AffectedEntities empty when IncludeDetails=false, got %d entries", len(findings[0].AffectedEntities))
	}
}

// TestAdminSDHolderBackdoor_CountsGenericWriteOnlyGrant guards the
// MaskGenericWrite bit of adminSDHolderWriteOrControlMask: an ALLOW ACE to a
// non-admin, non-baseline trustee carrying ONLY GenericWrite on AdminSDHolder
// must still fire. Without this bit in the mask, such a grant (write access
// to most non-protected attributes) would silently stop being detected.
func TestAdminSDHolderBackdoor_CountsGenericWriteOnlyGrant(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: adminSDHolderDN, Trustee: "S-1-5-21-1-2-3-9999", AccessMask: types.MaskGenericWrite, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 for a GenericWrite-only grant to a non-admin trustee (MaskGenericWrite must be part of the write/control mask), got %d", findings[0].Count)
	}
}

// TestAdminSDHolderBackdoor_CountsWriteOwnerOnlyGrant guards the
// MaskWriteOwner bit: an ALLOW ACE to a non-admin, non-baseline trustee
// carrying ONLY WriteOwner on AdminSDHolder must still fire - taking
// ownership is a classic full-control backdoor even without any other bit.
func TestAdminSDHolderBackdoor_CountsWriteOwnerOnlyGrant(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: adminSDHolderDN, Trustee: "S-1-5-21-1-2-3-9999", AccessMask: types.MaskWriteOwner, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 for a WriteOwner-only grant to a non-admin trustee (MaskWriteOwner must be part of the write/control mask), got %d", findings[0].Count)
	}
}

// TestAdminSDHolderBackdoor_CountsSelfOnlyGrant guards the MaskSelf bit: an
// ALLOW ACE to a non-admin, non-baseline trustee carrying ONLY Self
// (validated write / self-membership) on AdminSDHolder must still fire.
func TestAdminSDHolderBackdoor_CountsSelfOnlyGrant(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: adminSDHolderDN, Trustee: "S-1-5-21-1-2-3-9999", AccessMask: types.MaskSelf, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 for a Self-only grant to a non-admin trustee (MaskSelf must be part of the write/control mask), got %d", findings[0].Count)
	}
}

// TestAdminSDHolderBackdoor_CountsControlAccessOnlyGrant guards the
// MaskControlAccess bit: an ALLOW ACE to a non-admin, non-baseline trustee
// carrying ONLY ControlAccess, on an ObjectType outside the baseline table
// (so the Everyone/Change-Password default entry cannot be what excludes
// it), must still fire.
func TestAdminSDHolderBackdoor_CountsControlAccessOnlyGrant(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   adminSDHolderDN,
				Trustee:    "S-1-5-21-1-2-3-9999",
				ObjectType: "11111111-1111-1111-1111-111111111111",
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_ALLOWED",
			},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 for a ControlAccess-only grant to a non-admin trustee on a non-baseline extended right (MaskControlAccess must be part of the write/control mask), got %d", findings[0].Count)
	}
}

// TestAdminSDHolderBackdoor_ExcludesTerminalServerLicenseServersWriteProperty
// covers the adminSDHolderDefaultACEs entry for Terminal Server License
// Servers (S-1-5-32-561): its documented default WriteProperty grant, not
// scoped to any ObjectType, must be filtered as baseline, not reported as a
// backdoor. Without this entry, the real default ACE on every unmodified
// domain would be falsely counted.
func TestAdminSDHolderBackdoor_ExcludesTerminalServerLicenseServersWriteProperty(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   adminSDHolderDN,
				Trustee:    "S-1-5-32-561",
				AccessMask: types.MaskWriteProperty,
				AceType:    "ACCESS_ALLOWED",
			},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 (Terminal Server License Servers' default WriteProperty ACE is baseline, not a backdoor), got %d", findings[0].Count)
	}
}

// TestAdminSDHolderBackdoor_ExcludesBaselineTrusteeRegardlessOfObjectType
// covers the wildcard branch of the ObjectType comparison: Terminal Server
// License Servers' default grant (S-1-5-32-561) is not scoped to any
// ObjectType, so an empty baseline ObjectType must act as a wildcard and
// still match even when the actual ACE DOES carry a (non-empty) ObjectType.
func TestAdminSDHolderBackdoor_ExcludesBaselineTrusteeRegardlessOfObjectType(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   adminSDHolderDN,
				Trustee:    "S-1-5-32-561",
				ObjectType: "22222222-2222-2222-2222-222222222222",
				AccessMask: types.MaskWriteProperty,
				AceType:    "ACCESS_ALLOWED",
			},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 (Terminal Server License Servers' default grant is not ObjectType-scoped, so it still matches baseline even with an ObjectType set on the ACE), got %d", findings[0].Count)
	}
}

// TestAdminSDHolderBackdoor_SeverityIsMedium covers the Severity field itself:
// a real backdoor ACE (write/control grant to a non-admin, non-baseline
// trustee) must produce a finding at exactly SeverityMedium, neither escalated
// nor downgraded.
func TestAdminSDHolderBackdoor_SeverityIsMedium(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{ObjectDN: adminSDHolderDN, Trustee: "S-1-5-21-1-2-3-9999", AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count == 0 {
		t.Fatalf("expected Count>0 for this test to be meaningful, got 0")
	}
	if findings[0].Severity != types.SeverityMedium {
		t.Fatalf("expected Severity=%s, got %s", types.SeverityMedium, findings[0].Severity)
	}
}

// TestAdminSDHolderBackdoor_CountsEveryoneControlAccessOnDifferentExtendedRight
// covers the ObjectType scoping of Everyone's baseline entry: Everyone's
// documented default grant is the Change Password extended right
// (ab721a53-1e2f-11d0-9819-00aa0040529b) specifically, not every
// CONTROL_ACCESS right. The identical AccessMask on a DIFFERENT extended
// right (ObjectType) is not that documented default and must still be
// reported.
func TestAdminSDHolderBackdoor_CountsEveryoneControlAccessOnDifferentExtendedRight(t *testing.T) {
	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   adminSDHolderDN,
				Trustee:    "S-1-1-0",
				ObjectType: "33333333-3333-3333-3333-333333333333",
				AccessMask: types.MaskControlAccess,
				AceType:    "ACCESS_ALLOWED",
			},
		},
	}

	findings := NewAdminSDHolderBackdoorDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 (ObjectType differs from Everyone's documented Change Password extended right), got %d", findings[0].Count)
	}
}
