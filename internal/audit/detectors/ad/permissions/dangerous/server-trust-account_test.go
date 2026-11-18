package dangerous

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

const uacTargetDN = "CN=srv01,OU=Servers,DC=contoso,DC=com"

// TestServerTrustAccount_PropertySetGrantFlagged pins the missing scope:
// the AD delegation wizard commonly grants "write account restrictions" at
// the User-Account-Restrictions property-set level
// (4c164200-20c0-11d0-a768-00aa006e0529), which per Microsoft's AD schema
// reference includes User-Account-Control as a member attribute. The
// detector used to check only the individual attribute's schemaIDGUID and
// missed every ACE written at the property-set level.
func TestServerTrustAccount_PropertySetGrantFlagged(t *testing.T) {
	nonAdminSID := "S-1-5-21-1-2-3-9001"

	data := &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   uacTargetDN,
				Trustee:    nonAdminSID,
				AceType:    "ACCESS_ALLOWED_OBJECT",
				AccessMask: types.MaskWriteProperty,
				ObjectType: "4c164200-20c0-11d0-a768-00aa006e0529",
			},
		},
	}

	findings := NewServerTrustAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: a WriteProperty grant on the User-Account-Restrictions property set covers userAccountControl", findings[0].Count)
	}
}

// TestServerTrustAccount_AttributeGrantStillFlagged guards the pre-existing
// path: a direct grant on the userAccountControl attribute's own GUID must
// still fire.
func TestServerTrustAccount_AttributeGrantStillFlagged(t *testing.T) {
	nonAdminSID := "S-1-5-21-1-2-3-9002"

	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   uacTargetDN,
				Trustee:    nonAdminSID,
				AceType:    "ACCESS_ALLOWED_OBJECT",
				AccessMask: types.MaskWriteProperty,
				ObjectType: "bf967a68-0de6-11d0-a285-00aa003049e2",
			},
		},
	}

	findings := NewServerTrustAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: direct userAccountControl attribute grant must still fire", findings[0].Count)
	}
}

// TestServerTrustAccount_PrivilegedDomainSIDExcluded pins the exclusion of
// a domain-relative privileged SID (e.g. Domain Admins, <DomainSID>-512)
// from the finding: a grant already held by a privileged principal is not
// an attack path. This exercises both the construction of the privileged
// SID set from DomainInfo and the trustee check against that set.
func TestServerTrustAccount_PrivilegedDomainSIDExcluded(t *testing.T) {
	domainSID := "S-1-5-21-1-2-3"

	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainSID: domainSID},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   uacTargetDN,
				Trustee:    domainSID + "-512", // Domain Admins
				AceType:    "ACCESS_ALLOWED_OBJECT",
				AccessMask: types.MaskWriteProperty,
				ObjectType: "bf967a68-0de6-11d0-a285-00aa003049e2",
			},
		},
	}

	findings := NewServerTrustAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a grant to the domain-relative Domain Admins SID is privileged and must not be counted", findings[0].Count)
	}
}

// TestServerTrustAccount_DeniedACENotCounted pins the ACE type check: an
// ACCESS_DENIED ACE grants nothing and must never be counted even when
// every other field looks like a qualifying grant.
func TestServerTrustAccount_DeniedACENotCounted(t *testing.T) {
	nonAdminSID := "S-1-5-21-1-2-3-9010"

	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   uacTargetDN,
				Trustee:    nonAdminSID,
				AceType:    "ACCESS_DENIED_OBJECT_ACE_TYPE",
				AccessMask: types.MaskWriteProperty,
				ObjectType: "bf967a68-0de6-11d0-a285-00aa003049e2",
			},
		},
	}

	findings := NewServerTrustAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: an ACCESS_DENIED ACE must not be counted as a qualifying grant", findings[0].Count)
	}
}

// TestServerTrustAccount_ReadOnlyAccessNotCounted pins the access mask
// check: a ReadProperty-only grant (no WriteProperty bit) does not allow
// setting SERVER_TRUST_ACCOUNT and must not be counted.
func TestServerTrustAccount_ReadOnlyAccessNotCounted(t *testing.T) {
	nonAdminSID := "S-1-5-21-1-2-3-9011"

	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   uacTargetDN,
				Trustee:    nonAdminSID,
				AceType:    "ACCESS_ALLOWED_OBJECT",
				AccessMask: types.MaskReadProperty,
				ObjectType: "bf967a68-0de6-11d0-a285-00aa003049e2",
			},
		},
	}

	findings := NewServerTrustAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a ReadProperty-only grant (no WriteProperty bit) must not be counted", findings[0].Count)
	}
}

// TestServerTrustAccount_UnrelatedObjectTypeNotCounted pins the object
// type check: a WriteProperty grant on an attribute other than
// userAccountControl (or its containing property set) is unrelated and
// must not be counted.
func TestServerTrustAccount_UnrelatedObjectTypeNotCounted(t *testing.T) {
	nonAdminSID := "S-1-5-21-1-2-3-9012"

	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   uacTargetDN,
				Trustee:    nonAdminSID,
				AceType:    "ACCESS_ALLOWED_OBJECT",
				AccessMask: types.MaskWriteProperty,
				ObjectType: "11111111-1111-1111-1111-111111111111",
			},
		},
	}

	findings := NewServerTrustAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a WriteProperty grant on an unrelated attribute GUID must not be counted", findings[0].Count)
	}
}

// TestServerTrustAccount_TotalInstancesSetWhenDuplicated pins the
// TotalInstances field: when more than one qualifying ACE targets the same
// object, TotalInstances must report the raw instance count while Count
// reports the deduplicated object count.
func TestServerTrustAccount_TotalInstancesSetWhenDuplicated(t *testing.T) {
	nonAdminSID := "S-1-5-21-1-2-3-9013"

	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   uacTargetDN,
				Trustee:    nonAdminSID,
				AceType:    "ACCESS_ALLOWED_OBJECT",
				AccessMask: types.MaskWriteProperty,
				ObjectType: "bf967a68-0de6-11d0-a285-00aa003049e2",
			},
			{
				ObjectDN:   uacTargetDN,
				Trustee:    nonAdminSID,
				AceType:    "ACCESS_ALLOWED_OBJECT",
				AccessMask: types.MaskWriteProperty,
				ObjectType: "4c164200-20c0-11d0-a768-00aa006e0529",
			},
		},
	}

	findings := NewServerTrustAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: both ACEs target the same object", findings[0].Count)
	}
	if findings[0].TotalInstances != 2 {
		t.Fatalf("TotalInstances = %d, want 2: two qualifying ACEs on the same object", findings[0].TotalInstances)
	}
}

// TestServerTrustAccount_TotalInstancesOmittedWhenNoDuplicates pins the
// opposite side of the TotalInstances guard: when there is exactly one
// qualifying ACE, TotalInstances must stay at its zero value (omitted from
// the JSON output) rather than being set to a redundant value equal to Count.
func TestServerTrustAccount_TotalInstancesOmittedWhenNoDuplicates(t *testing.T) {
	nonAdminSID := "S-1-5-21-1-2-3-9014"

	data := &audit.DetectorData{
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   uacTargetDN,
				Trustee:    nonAdminSID,
				AceType:    "ACCESS_ALLOWED_OBJECT",
				AccessMask: types.MaskWriteProperty,
				ObjectType: "bf967a68-0de6-11d0-a285-00aa003049e2",
			},
		},
	}

	findings := NewServerTrustAccountDetector().Detect(context.Background(), data)
	if findings[0].TotalInstances != 0 {
		t.Fatalf("TotalInstances = %d, want 0 (omitted): a single qualifying ACE must not set a redundant TotalInstances", findings[0].TotalInstances)
	}
}

// TestServerTrustAccount_AffectedEntitiesPopulatedWhenIncludeDetails pins
// the IncludeDetails guard: when the caller asked for details and there is
// at least one qualifying object, AffectedEntities must be populated.
func TestServerTrustAccount_AffectedEntitiesPopulatedWhenIncludeDetails(t *testing.T) {
	nonAdminSID := "S-1-5-21-1-2-3-9015"

	data := &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   uacTargetDN,
				Trustee:    nonAdminSID,
				AceType:    "ACCESS_ALLOWED_OBJECT",
				AccessMask: types.MaskWriteProperty,
				ObjectType: "bf967a68-0de6-11d0-a285-00aa003049e2",
			},
		},
	}

	findings := NewServerTrustAccountDetector().Detect(context.Background(), data)
	if len(findings[0].AffectedEntities) == 0 {
		t.Fatalf("AffectedEntities is empty, want at least one entity when IncludeDetails is true and a qualifying object exists")
	}
}

// TestServerTrustAccount_AffectedEntitiesNilWhenDetailsExcluded pins the
// opposite side of the IncludeDetails guard: when the caller did not ask
// for details, AffectedEntities must stay nil even though a qualifying
// object exists.
func TestServerTrustAccount_AffectedEntitiesNilWhenDetailsExcluded(t *testing.T) {
	nonAdminSID := "S-1-5-21-1-2-3-9016"

	data := &audit.DetectorData{
		IncludeDetails: false,
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   uacTargetDN,
				Trustee:    nonAdminSID,
				AceType:    "ACCESS_ALLOWED_OBJECT",
				AccessMask: types.MaskWriteProperty,
				ObjectType: "bf967a68-0de6-11d0-a285-00aa003049e2",
			},
		},
	}

	findings := NewServerTrustAccountDetector().Detect(context.Background(), data)
	if findings[0].AffectedEntities != nil {
		t.Fatalf("AffectedEntities = %v, want nil: IncludeDetails is false", findings[0].AffectedEntities)
	}
}
