package dangerous

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// Mask values are literals matching the real Windows ACE access-mask bits,
// never the detector's own types.Mask* constants: a drift in those constants
// would otherwise be invisible to these tests (the LAPS GUID lesson).
const (
	schemaPermDomainSID = "S-1-5-21-4444444444-5555555555-6666666666"

	schemaPermMaskWriteProperty = 0x00000020
	schemaPermMaskWriteDACL     = 0x00040000
	schemaPermMaskWriteOwner    = 0x00080000
	schemaPermMaskGenericAll    = 0x10000000
	schemaPermMaskControlAccess = 0x00000100 // extended right, not a dangerous bit

	schemaPermSchemaDN          = "CN=Schema,CN=Configuration,DC=example,DC=com"
	schemaPermSchemaDNUppercase = "CN=SCHEMA,CN=CONFIGURATION,DC=EXAMPLE,DC=COM"
	schemaPermOutsideSchemaDN   = "CN=Users,DC=example,DC=com"

	schemaPermOrdinaryTrustee = schemaPermDomainSID + "-1105"
	schemaPermOtherTrustee    = schemaPermDomainSID + "-1106"
)

func schemaPermData(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		DomainInfo: &types.DomainInfo{
			DomainDN:  "DC=example,DC=com",
			DomainSID: schemaPermDomainSID,
		},
	}
}

func schemaPermDetect(aces ...types.ACLEntry) types.Finding {
	data := schemaPermData(aces...)
	d := NewSchemaPermissionsDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		panic("expected exactly 1 finding from SchemaPermissionsDetector")
	}
	return findings[0]
}

// TestSchemaPermissions_WritePropertyNonPrivilegedCounted covers the
// WriteProperty bit of the dangerous mask (kills mutation e: MaskWriteProperty
// removed from dangerousMask).
func TestSchemaPermissions_WritePropertyNonPrivilegedCounted(t *testing.T) {
	ace := types.ACLEntry{
		ObjectDN:   schemaPermSchemaDN,
		Trustee:    schemaPermOrdinaryTrustee,
		AceType:    "ACCESS_ALLOWED_OBJECT",
		AccessMask: schemaPermMaskWriteProperty,
	}
	finding := schemaPermDetect(ace)
	if finding.Count != 1 {
		t.Fatalf("Count = %d, want 1 (WriteProperty from a non-privileged trustee on the schema container)", finding.Count)
	}
}

// TestSchemaPermissions_WriteDACLOnlyCounted covers the WriteDACL bit alone
// (kills mutation f: MaskWriteDACL removed from dangerousMask).
func TestSchemaPermissions_WriteDACLOnlyCounted(t *testing.T) {
	ace := types.ACLEntry{
		ObjectDN:   schemaPermSchemaDN,
		Trustee:    schemaPermOrdinaryTrustee,
		AceType:    "ACCESS_ALLOWED_OBJECT",
		AccessMask: schemaPermMaskWriteDACL,
	}
	finding := schemaPermDetect(ace)
	if finding.Count != 1 {
		t.Fatalf("Count = %d, want 1 (WriteDACL alone must fire)", finding.Count)
	}
}

// TestSchemaPermissions_WriteOwnerOnlyCounted covers the WriteOwner bit alone.
func TestSchemaPermissions_WriteOwnerOnlyCounted(t *testing.T) {
	ace := types.ACLEntry{
		ObjectDN:   schemaPermSchemaDN,
		Trustee:    schemaPermOrdinaryTrustee,
		AceType:    "ACCESS_ALLOWED_OBJECT",
		AccessMask: schemaPermMaskWriteOwner,
	}
	finding := schemaPermDetect(ace)
	if finding.Count != 1 {
		t.Fatalf("Count = %d, want 1 (WriteOwner alone must fire)", finding.Count)
	}
}

// TestSchemaPermissions_GenericAllOnlyCounted covers the GenericAll bit alone.
func TestSchemaPermissions_GenericAllOnlyCounted(t *testing.T) {
	ace := types.ACLEntry{
		ObjectDN:   schemaPermSchemaDN,
		Trustee:    schemaPermOrdinaryTrustee,
		AceType:    "ACCESS_ALLOWED_OBJECT",
		AccessMask: schemaPermMaskGenericAll,
	}
	finding := schemaPermDetect(ace)
	if finding.Count != 1 {
		t.Fatalf("Count = %d, want 1 (GenericAll alone must fire)", finding.Count)
	}
}

// TestSchemaPermissions_OutsideSchemaNotCounted covers the DN guard (kills
// mutation a: the "cn=schema,cn=configuration," Contains check removed).
func TestSchemaPermissions_OutsideSchemaNotCounted(t *testing.T) {
	ace := types.ACLEntry{
		ObjectDN:   schemaPermOutsideSchemaDN,
		Trustee:    schemaPermOrdinaryTrustee,
		AceType:    "ACCESS_ALLOWED_OBJECT",
		AccessMask: schemaPermMaskWriteProperty,
	}
	finding := schemaPermDetect(ace)
	if finding.Count != 0 {
		t.Fatalf("Count = %d, want 0 (%s is not under the schema container)", finding.Count, schemaPermOutsideSchemaDN)
	}
}

// TestSchemaPermissions_DeniedNotCounted covers the ALLOWED guard (kills
// mutation b: the "ALLOWED" Contains check on AceType removed).
func TestSchemaPermissions_DeniedNotCounted(t *testing.T) {
	ace := types.ACLEntry{
		ObjectDN:   schemaPermSchemaDN,
		Trustee:    schemaPermOrdinaryTrustee,
		AceType:    "ACCESS_DENIED_OBJECT",
		AccessMask: schemaPermMaskWriteProperty,
	}
	finding := schemaPermDetect(ace)
	if finding.Count != 0 {
		t.Fatalf("Count = %d, want 0 (ACCESS_DENIED_OBJECT does not contain ALLOWED)", finding.Count)
	}
}

// TestSchemaPermissions_SystemTrusteeNotCounted covers the hardcoded SYSTEM
// entry of the privileged-trustee exclusion (kills mutation c: the exclusion
// check removed).
func TestSchemaPermissions_SystemTrusteeNotCounted(t *testing.T) {
	ace := types.ACLEntry{
		ObjectDN:   schemaPermSchemaDN,
		Trustee:    "S-1-5-18",
		AceType:    "ACCESS_ALLOWED_OBJECT",
		AccessMask: schemaPermMaskWriteProperty,
	}
	finding := schemaPermDetect(ace)
	if finding.Count != 0 {
		t.Fatalf("Count = %d, want 0 (SYSTEM is a hardcoded privileged trustee)", finding.Count)
	}
}

// TestSchemaPermissions_DomainSchemaAdminsNotCounted covers the dynamic half
// of privilegedSIDs, built from DomainInfo.DomainSID + types.PrivilegedSIDSuffixes
// (kills mutation h: the suffix loop removed; also killed by mutation c).
func TestSchemaPermissions_DomainSchemaAdminsNotCounted(t *testing.T) {
	ace := types.ACLEntry{
		ObjectDN:   schemaPermSchemaDN,
		Trustee:    schemaPermDomainSID + "-518", // Schema Admins
		AceType:    "ACCESS_ALLOWED_OBJECT",
		AccessMask: schemaPermMaskWriteProperty,
	}
	finding := schemaPermDetect(ace)
	if finding.Count != 0 {
		t.Fatalf("Count = %d, want 0 (domain Schema Admins is a domainSID-suffix privileged trustee)", finding.Count)
	}
}

// TestSchemaPermissions_ExtendedRightOnlyNotCounted covers the dangerous-mask
// guard (kills mutation d: the mask-intersection check removed). A
// ControlAccess bit alone (an extended right) is not one of GenericAll /
// WriteDACL / WriteOwner / WriteProperty.
func TestSchemaPermissions_ExtendedRightOnlyNotCounted(t *testing.T) {
	ace := types.ACLEntry{
		ObjectDN:   schemaPermSchemaDN,
		Trustee:    schemaPermOrdinaryTrustee,
		AceType:    "ACCESS_ALLOWED_OBJECT",
		AccessMask: schemaPermMaskControlAccess,
	}
	finding := schemaPermDetect(ace)
	if finding.Count != 0 {
		t.Fatalf("Count = %d, want 0 (a ControlAccess bit alone carries no dangerous right)", finding.Count)
	}
}

// TestSchemaPermissions_TwoACEsOneObjectCountsOnce covers the Count/TotalInstances
// dedup split (kills mutation g: Count set to totalInstances instead of
// len(uniqueObjects)).
func TestSchemaPermissions_TwoACEsOneObjectCountsOnce(t *testing.T) {
	first := types.ACLEntry{
		ObjectDN:   schemaPermSchemaDN,
		Trustee:    schemaPermOrdinaryTrustee,
		AceType:    "ACCESS_ALLOWED_OBJECT",
		AccessMask: schemaPermMaskWriteProperty,
	}
	second := types.ACLEntry{
		ObjectDN:   schemaPermSchemaDN,
		Trustee:    schemaPermOtherTrustee,
		AceType:    "ACCESS_ALLOWED_OBJECT",
		AccessMask: schemaPermMaskWriteDACL,
	}
	finding := schemaPermDetect(first, second)
	if finding.Count != 1 {
		t.Fatalf("Count = %d, want 1 (two dangerous ACEs on the same object dedup to one object)", finding.Count)
	}
	if finding.TotalInstances != 2 {
		t.Fatalf("TotalInstances = %d, want 2 (two distinct ACE instances behind the single counted object)", finding.TotalInstances)
	}
}

// TestSchemaPermissions_UppercaseDNCounted covers the lowercasing of the DN
// before the Contains check.
func TestSchemaPermissions_UppercaseDNCounted(t *testing.T) {
	ace := types.ACLEntry{
		ObjectDN:   schemaPermSchemaDNUppercase,
		Trustee:    schemaPermOrdinaryTrustee,
		AceType:    "ACCESS_ALLOWED_OBJECT",
		AccessMask: schemaPermMaskWriteProperty,
	}
	finding := schemaPermDetect(ace)
	if finding.Count != 1 {
		t.Fatalf("Count = %d, want 1 (an uppercase DN must still match the schema container)", finding.Count)
	}
}
