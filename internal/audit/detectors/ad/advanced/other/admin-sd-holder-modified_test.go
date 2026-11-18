package other

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// This detector never read AccessMask at all before this fix (motif(b),
// same signature as the bugs the dangerous_acl_test.go suite covers): ANY
// ACCESS_ALLOWED ACE on AdminSDHolder from a non-default SID was flagged HIGH
// severity regardless of what right it actually granted. Live proof against
// DC01 confirms the fix behaves correctly against real
// AD data; this table-driven test pins the exact boundary deterministically -
// AccessMaskToRight (aclentry.go) never renders a plain read-only right as a
// named entity, so a live-only demonstration cannot show the negative case by
// entity name alone.

const (
	asdhDomainDN = "DC=example,DC=com"
	asdhDomain   = "S-1-5-21-1234567890-1111111111-2222222222"
	asdhObjectDN = "CN=AdminSDHolder,CN=System," + asdhDomainDN

	// An ordinary domain principal, not one of adminSDHolderWhitelist's SIDs.
	asdhOrdinarySID = asdhDomain + "-93801"

	maskReadProperty = 0x00000010 // ADS_RIGHT_DS_READ_PROP - not in dangerousMask
	maskWriteDACL    = 0x00040000

	// Fictional GUID that is neither the Private-Information property set
	// nor the terminalServer attribute/property set - used to prove the
	// whitelist is scoped to the specific ObjectType, not to the trustee SID
	// alone.
	asdhUnrelatedObjectType = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	// The Private-Information property set GUID added for SELF by adprep
	// /domainprep operation 59 (Windows Server 2008).
	asdhPrivateInformationObjectType = "91e647de-d96f-4b70-9557-d63ff4f3ccd8"
	// The terminalServer attribute GUID added for Terminal Server License
	// Servers by adprep /domainprep operation 61.
	asdhTerminalServerObjectType = "5805bc62-bdc9-4428-a5e2-856a0f4c185e"
	// The userCertificate attribute GUID, the only ObjectType Appendix K
	// documents a default Cert Publishers grant against.
	asdhUserCertificateObjectType = "bf967a7f-0de6-11d0-a285-00aa003049e2"

	maskReadWriteProperty = 0x00000030 // ADS_RIGHT_DS_READ_PROP | ADS_RIGHT_DS_WRITE_PROP

	// Two real-world "full control" AccessMask encodings seen on
	// AdminSDHolder's whole-object default ACEs (Domain Admins, Enterprise
	// Admins, Administrators, SYSTEM per Appendix K): both carry the
	// dangerousMask bits (WriteProperty, WriteDACL, WriteOwner) and must
	// still be whitelisted because objectTypes is empty for these SIDs.
	maskFullControlV1 = 0x000F01FF
	maskFullControlV2 = 0x000E01BF
)

func asdhData(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		DomainInfo:     &types.DomainInfo{DomainSID: asdhDomain, DomainDN: asdhDomainDN},
	}
}

func TestAdminSDHolderModified_RequiresDangerousRight(t *testing.T) {
	t.Run("read-only grant from a non-default SID does NOT fire", func(t *testing.T) {
		d := NewAdminSdHolderModifiedDetector()
		findings := d.Detect(context.Background(), asdhData(
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: asdhOrdinarySID, AccessMask: maskReadProperty, AceType: "ACCESS_ALLOWED"},
		))
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 0 {
			t.Fatalf("a read-only ACE must not be flagged as a modification, got count=%d", findings[0].Count)
		}
	})

	t.Run("WriteDACL grant from a non-default SID DOES fire", func(t *testing.T) {
		d := NewAdminSdHolderModifiedDetector()
		findings := d.Detect(context.Background(), asdhData(
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: asdhOrdinarySID, AccessMask: maskWriteDACL, AceType: "ACCESS_ALLOWED"},
		))
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 1 {
			t.Fatalf("a WriteDACL grant to a non-default principal must fire, got count=%d", findings[0].Count)
		}
		if len(findings[0].AffectedEntities) != 1 {
			t.Fatalf("finding must be actionable, got %d entities", len(findings[0].AffectedEntities))
		}
	})

	t.Run("deny ACE with a dangerous mask still does not fire", func(t *testing.T) {
		d := NewAdminSdHolderModifiedDetector()
		findings := d.Detect(context.Background(), asdhData(
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: asdhOrdinarySID, AccessMask: maskWriteDACL, AceType: "ACCESS_DENIED"},
		))
		if findings[0].Count != 0 {
			t.Fatalf("a DENY ACE must never be counted as a grant, got count=%d", findings[0].Count)
		}
	})
}

// A pristine, never-touched AdminSDHolder still carries two default
// attribute-scoped WriteProperty ACEs documented by Microsoft ("Appendix K:
// Default Settings in the Master Security Descriptor of the AdminSDHolder
// Object"): Cert Publishers (RP;WP on userCert) and Terminal Server License
// Servers (RP;WP on terminalServer). Before isDefaultAdminSDHolderSID knew
// about them, both were indistinguishable from an attacker-granted
// WriteProperty right and a virgin object was reported "Modified".
func TestAdminSDHolderModified_DefaultAttributeScopedACEsDoNotFire(t *testing.T) {
	t.Run("Cert Publishers default WriteProperty-on-userCert ACE does NOT fire", func(t *testing.T) {
		d := NewAdminSdHolderModifiedDetector()
		findings := d.Detect(context.Background(), asdhData(
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: asdhDomain + "-517", ObjectType: asdhUserCertificateObjectType, AccessMask: maskReadWriteProperty, AceType: "ACCESS_ALLOWED"},
		))
		if findings[0].Count != 0 {
			t.Fatalf("Cert Publishers' default userCert ACE must not be reported as a modification, got count=%d", findings[0].Count)
		}
	})

	t.Run("Terminal Server License Servers default WriteProperty-on-terminalServer ACE does NOT fire", func(t *testing.T) {
		d := NewAdminSdHolderModifiedDetector()
		findings := d.Detect(context.Background(), asdhData(
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: "S-1-5-32-561", ObjectType: asdhTerminalServerObjectType, AccessMask: types.MaskWriteProperty, AceType: "ACCESS_ALLOWED"},
		))
		if findings[0].Count != 0 {
			t.Fatalf("Terminal Server License Servers' default terminalServer ACE must not be reported as a modification, got count=%d", findings[0].Count)
		}
	})
}

// Operation 59 (adprep /domainprep, Windows Server 2008) adds
// "(OA;CI;CRRPWP;91e647de-...;;PS)" on AdminSDHolder: SELF gets
// ControlAccess+ReadProperty+WriteProperty (mask 0x130) scoped to the
// Private-Information property set only. This is exactly the ACE observed
// at rest on a real DC, and the detector must not flag it.
func TestAdminSDHolder_DefaultSelfPrivateInformationNotFlagged(t *testing.T) {
	d := NewAdminSdHolderModifiedDetector()
	findings := d.Detect(context.Background(), asdhData(
		types.ACLEntry{
			ObjectDN:   asdhObjectDN,
			Trustee:    "S-1-5-10",
			ObjectType: asdhPrivateInformationObjectType,
			AccessMask: types.MaskControlAccess | types.MaskReadProperty | types.MaskWriteProperty,
			AceType:    "ACCESS_ALLOWED",
		},
	))
	if findings[0].Count != 0 {
		t.Fatalf("the default operation-59 SELF/Private-Information ACE must not be reported as a modification, got count=%d", findings[0].Count)
	}
}

// SELF is only whitelisted for the Private-Information property set. Given
// both the legitimate default op59 ACE and a WriteProperty grant to SELF
// scoped to an unrelated attribute/property set, the detector must still
// single out the unrelated one as the modification - treating SELF as
// blanket-whitelisted (ignoring ObjectType) would instead flag the default
// ACE as evidence, or dedupe it away and report nothing specific to the real
// offender, since both ACEs share the same trustee and target DN.
func TestAdminSDHolder_SelfOtherObjectTypeFlagged(t *testing.T) {
	d := NewAdminSdHolderModifiedDetector()
	findings := d.Detect(context.Background(), asdhData(
		types.ACLEntry{
			ObjectDN:   asdhObjectDN,
			Trustee:    "S-1-5-10",
			ObjectType: asdhPrivateInformationObjectType,
			AccessMask: types.MaskControlAccess | types.MaskReadProperty | types.MaskWriteProperty,
			AceType:    "ACCESS_ALLOWED",
		},
		types.ACLEntry{
			ObjectDN:   asdhObjectDN,
			Trustee:    "S-1-5-10",
			ObjectType: asdhUnrelatedObjectType,
			AccessMask: types.MaskWriteProperty,
			AceType:    "ACCESS_ALLOWED",
		},
	))
	if findings[0].Count != 1 {
		t.Fatalf("a SELF WriteProperty grant outside the Private-Information property set must be flagged, got count=%d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 {
		t.Fatalf("expected exactly 1 affected entity, got %d", len(findings[0].AffectedEntities))
	}
	wantRight := "WriteProperty:" + asdhUnrelatedObjectType
	if got := findings[0].AffectedEntities[0].Right; got != wantRight {
		t.Fatalf("the flagged entity must be the unrelated-ObjectType ACE, not the default op59 one: got right=%q, want %q", got, wantRight)
	}
}

// Terminal Server License Servers is only whitelisted for the terminalServer
// attribute/property set (operation 61). A WriteProperty grant to it scoped
// to any other attribute has no documented default and must be flagged.
func TestAdminSDHolder_TSLSOtherObjectTypeFlagged(t *testing.T) {
	d := NewAdminSdHolderModifiedDetector()
	findings := d.Detect(context.Background(), asdhData(
		types.ACLEntry{
			ObjectDN:   asdhObjectDN,
			Trustee:    "S-1-5-32-561",
			ObjectType: asdhUnrelatedObjectType,
			AccessMask: types.MaskWriteProperty,
			AceType:    "ACCESS_ALLOWED",
		},
	))
	if findings[0].Count != 1 {
		t.Fatalf("a Terminal Server License Servers WriteProperty grant outside the terminalServer attribute/property set must be flagged, got count=%d", findings[0].Count)
	}
}

// Neither Appendix K nor any adprep /domainprep operation (2008 through the
// current Server Annual Channel) grants Schema Admins (-518) or Account
// Operators (S-1-5-32-548) any right on AdminSDHolder. Both must be flagged.
func TestAdminSDHolder_SchemaAdminsAndAccountOperatorsFlagged(t *testing.T) {
	t.Run("Schema Admins WriteDACL grant is flagged", func(t *testing.T) {
		d := NewAdminSdHolderModifiedDetector()
		findings := d.Detect(context.Background(), asdhData(
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: asdhDomain + "-518", AccessMask: maskWriteDACL, AceType: "ACCESS_ALLOWED"},
		))
		if findings[0].Count != 1 {
			t.Fatalf("Schema Admins has no sourced default grant on AdminSDHolder and must be flagged, got count=%d", findings[0].Count)
		}
	})

	t.Run("Account Operators GenericAll grant is flagged", func(t *testing.T) {
		d := NewAdminSdHolderModifiedDetector()
		findings := d.Detect(context.Background(), asdhData(
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: "S-1-5-32-548", AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED"},
		))
		if findings[0].Count != 1 {
			t.Fatalf("Account Operators has no sourced default grant on AdminSDHolder and must be flagged, got count=%d", findings[0].Count)
		}
	})
}

// Cert Publishers is only whitelisted for the userCertificate attribute
// (Appendix K's RP;WP grant, mask 0x30). A wider grant to the same trustee -
// whether GenericAll or WriteDACL - has no documented default and must be
// flagged; the default attribute-scoped ACE itself must still not fire.
func TestAdminSDHolder_CertPublishersWiderGrantFlagged(t *testing.T) {
	t.Run("Cert Publishers GenericAll grant is flagged", func(t *testing.T) {
		d := NewAdminSdHolderModifiedDetector()
		findings := d.Detect(context.Background(), asdhData(
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: asdhDomain + "-517", AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED"},
		))
		if findings[0].Count != 1 {
			t.Fatalf("Cert Publishers GenericAll on AdminSDHolder has no sourced default and must be flagged, got count=%d", findings[0].Count)
		}
	})

	t.Run("Cert Publishers WriteDACL grant is flagged", func(t *testing.T) {
		d := NewAdminSdHolderModifiedDetector()
		findings := d.Detect(context.Background(), asdhData(
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: asdhDomain + "-517", AccessMask: maskWriteDACL, AceType: "ACCESS_ALLOWED"},
		))
		if findings[0].Count != 1 {
			t.Fatalf("Cert Publishers WriteDACL on AdminSDHolder has no sourced default and must be flagged, got count=%d", findings[0].Count)
		}
	})

	t.Run("Cert Publishers default ReadProperty+WriteProperty-on-userCertificate ACE does NOT fire", func(t *testing.T) {
		d := NewAdminSdHolderModifiedDetector()
		findings := d.Detect(context.Background(), asdhData(
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: asdhDomain + "-517", ObjectType: asdhUserCertificateObjectType, AccessMask: maskReadWriteProperty, AceType: "ACCESS_ALLOWED"},
		))
		if findings[0].Count != 0 {
			t.Fatalf("Cert Publishers' default userCertificate ACE must not be reported as a modification, got count=%d", findings[0].Count)
		}
	})
}

// A scoped default ACE only earns the whitelist because of its ObjectType;
// the sourced mask (0x130 for SELF/Private-Information, 0x30 for the
// attribute-scoped grants) bounds exactly what that default actually grants.
// An ACE that matches the ObjectType but carries a wider right than the
// source documents is not the default - it must still be flagged.
func TestAdminSDHolder_ScopedDefaultWithWiderMaskFlagged(t *testing.T) {
	t.Run("SELF Private-Information ACE with an extra WriteDACL bit is flagged", func(t *testing.T) {
		d := NewAdminSdHolderModifiedDetector()
		findings := d.Detect(context.Background(), asdhData(
			types.ACLEntry{
				ObjectDN:   asdhObjectDN,
				Trustee:    "S-1-5-10",
				ObjectType: asdhPrivateInformationObjectType,
				AccessMask: types.MaskControlAccess | types.MaskReadProperty | types.MaskWriteProperty | types.MaskWriteDACL,
				AceType:    "ACCESS_ALLOWED",
			},
		))
		if findings[0].Count != 1 {
			t.Fatalf("a SELF Private-Information ACE carrying WriteDACL beyond the sourced 0x130 mask must be flagged, got count=%d", findings[0].Count)
		}
	})

	t.Run("Terminal Server License Servers ACE with GenericAll instead of the sourced mask is flagged", func(t *testing.T) {
		d := NewAdminSdHolderModifiedDetector()
		findings := d.Detect(context.Background(), asdhData(
			types.ACLEntry{
				ObjectDN:   asdhObjectDN,
				Trustee:    "S-1-5-32-561",
				ObjectType: asdhTerminalServerObjectType,
				AccessMask: types.MaskGenericAll,
				AceType:    "ACCESS_ALLOWED",
			},
		))
		if findings[0].Count != 1 {
			t.Fatalf("a Terminal Server License Servers ACE scoped to terminalServer but granting GenericAll instead of the sourced 0x30 mask must be flagged, got count=%d", findings[0].Count)
		}
	})

	t.Run("Cert Publishers userCertificate ACE with WriteOwner instead of the sourced mask is flagged", func(t *testing.T) {
		d := NewAdminSdHolderModifiedDetector()
		findings := d.Detect(context.Background(), asdhData(
			types.ACLEntry{
				ObjectDN:   asdhObjectDN,
				Trustee:    asdhDomain + "-517",
				ObjectType: asdhUserCertificateObjectType,
				AccessMask: types.MaskWriteOwner,
				AceType:    "ACCESS_ALLOWED",
			},
		))
		if findings[0].Count != 1 {
			t.Fatalf("a Cert Publishers userCertificate ACE carrying WriteOwner instead of the sourced 0x30 mask must be flagged, got count=%d", findings[0].Count)
		}
	})
}

// AdminSDHolder's whole-object default ACEs (Appendix K: Domain Admins,
// Enterprise Admins, Administrators, SYSTEM get full control with no
// ObjectType restriction) carry dangerousMask bits and must not be flagged.
// These SIDs are whitelisted via an empty objectTypes (isWhitelistedAdminSDHolderACE,
// admin-sd-holder-modified.go:120): removing that branch would make every one
// of these default ACEs fire, since each full-control mask also sets
// WriteProperty/WriteDACL/WriteOwner.
func TestAdminSDHolder_DefaultWholeObjectACEsNotFlagged(t *testing.T) {
	t.Run("full control mask 0x000F01FF", func(t *testing.T) {
		d := NewAdminSdHolderModifiedDetector()
		findings := d.Detect(context.Background(), asdhData(
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: asdhDomain + "-512", AccessMask: maskFullControlV1, AceType: "ACCESS_ALLOWED"},
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: asdhDomain + "-519", AccessMask: maskFullControlV1, AceType: "ACCESS_ALLOWED"},
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: "S-1-5-32-544", AccessMask: maskFullControlV1, AceType: "ACCESS_ALLOWED"},
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: "S-1-5-18", AccessMask: maskFullControlV1, AceType: "ACCESS_ALLOWED"},
		))
		if findings[0].Count != 0 {
			t.Fatalf("the four whole-object default ACEs (mask 0x000F01FF) must not be reported as a modification, got count=%d", findings[0].Count)
		}
	})

	t.Run("full control mask 0x000E01BF", func(t *testing.T) {
		d := NewAdminSdHolderModifiedDetector()
		findings := d.Detect(context.Background(), asdhData(
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: asdhDomain + "-512", AccessMask: maskFullControlV2, AceType: "ACCESS_ALLOWED"},
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: asdhDomain + "-519", AccessMask: maskFullControlV2, AceType: "ACCESS_ALLOWED"},
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: "S-1-5-32-544", AccessMask: maskFullControlV2, AceType: "ACCESS_ALLOWED"},
			types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: "S-1-5-18", AccessMask: maskFullControlV2, AceType: "ACCESS_ALLOWED"},
		))
		if findings[0].Count != 0 {
			t.Fatalf("the four whole-object default ACEs (mask 0x000E01BF) must not be reported as a modification, got count=%d", findings[0].Count)
		}
	})
}

// data.DomainInfo can be nil (domain info unavailable to the collector run).
// The nil-guard at admin-sd-holder-modified.go:152 must return a non-panicking
// "review required" finding instead of dereferencing DomainInfo.DomainSID /
// DomainDN below it.
func TestAdminSDHolder_NilDomainInfoReturnsReviewRequired(t *testing.T) {
	d := NewAdminSdHolderModifiedDetector()
	data := &audit.DetectorData{IncludeDetails: true, DomainInfo: nil}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("a nil DomainInfo must not be reported as a modification, got count=%d", findings[0].Count)
	}
	if findings[0].Title != "AdminSDHolder Review Required" {
		t.Fatalf("expected title %q, got %q", "AdminSDHolder Review Required", findings[0].Title)
	}
}

// A look-alike object merely named AdminSDHolder outside CN=System (e.g.
// under an OU) is not the real, SDProp-propagated AdminSDHolder object and
// must not be analyzed as one, even though its DN contains the substring
// "cn=adminsdholder".
func TestAdminSDHolder_LookalikeDNNotTreatedAsAdminSDHolder(t *testing.T) {
	d := NewAdminSdHolderModifiedDetector()
	lookalikeDN := "CN=AdminSDHolder,OU=X," + asdhDomainDN
	findings := d.Detect(context.Background(), asdhData(
		types.ACLEntry{ObjectDN: lookalikeDN, Trustee: asdhOrdinarySID, AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED"},
	))
	if findings[0].Count != 0 {
		t.Fatalf("a look-alike object outside CN=System must not be treated as the real AdminSDHolder, got count=%d", findings[0].Count)
	}
}

// isAdminSDHolderObject's domainDN=="" guard (admin-sd-holder-modified.go:137)
// must reject every DN outright, including the exact string its own
// concatenation ("CN=AdminSDHolder,CN=System,"+domainDN) would produce when
// domainDN is empty - without the guard, strings.EqualFold would match that
// degenerate DN.
func TestIsAdminSDHolderObject_EmptyDomainDNReturnsFalse(t *testing.T) {
	t.Run("the DN the guard's own concatenation would produce does not match", func(t *testing.T) {
		if isAdminSDHolderObject("CN=AdminSDHolder,CN=System,", "") {
			t.Fatal("an empty domainDN must never match, even against CN=AdminSDHolder,CN=System, with nothing appended")
		}
	})
	t.Run("a real AdminSDHolder DN with an empty domainDN also does not match", func(t *testing.T) {
		if isAdminSDHolderObject(asdhObjectDN, "") {
			t.Fatal("a real AdminSDHolder DN must not match when domainDN is empty")
		}
	})
}

// Two ACEs sharing the same trustee and the same target DN (seen[key],
// admin-sd-holder-modified.go:200) must collapse to a single affected
// entity - without the dedup, a repeated ACE (a common ldap artifact of a
// multi-valued attribute re-read) would double-count the same modification.
func TestAdminSDHolder_DuplicateACEDedupedToSingleAffectedEntity(t *testing.T) {
	d := NewAdminSdHolderModifiedDetector()
	duplicatedACE := types.ACLEntry{ObjectDN: asdhObjectDN, Trustee: asdhOrdinarySID, AccessMask: maskWriteDACL, AceType: "ACCESS_ALLOWED"}
	findings := d.Detect(context.Background(), asdhData(duplicatedACE, duplicatedACE))
	if findings[0].Count != 1 {
		t.Fatalf("two identical dangerous ACEs from the same trustee on the same object must still report a single modification, got count=%d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 {
		t.Fatalf("the duplicate ACE must be deduplicated to exactly 1 affected entity, got %d", len(findings[0].AffectedEntities))
	}
}

// When IncludeDetails is false, the finding must still count the real
// modification but must carry neither AffectedEntities nor Details - the
// guard at admin-sd-holder-modified.go:222 is what keeps detail-building
// conditional on IncludeDetails, not just on there being a modification.
func TestAdminSDHolder_DetailsOmittedWhenIncludeDetailsFalse(t *testing.T) {
	d := NewAdminSdHolderModifiedDetector()
	data := &audit.DetectorData{
		IncludeDetails: false,
		ACLEntries: []types.ACLEntry{
			{ObjectDN: asdhObjectDN, Trustee: asdhOrdinarySID, AccessMask: maskWriteDACL, AceType: "ACCESS_ALLOWED"},
		},
		DomainInfo: &types.DomainInfo{DomainSID: asdhDomain, DomainDN: asdhDomainDN},
	}
	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("a real modification must still be counted even when IncludeDetails is false, got count=%d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 0 {
		t.Fatalf("AffectedEntities must stay empty when IncludeDetails is false, got %d entries", len(findings[0].AffectedEntities))
	}
	if findings[0].Details != nil {
		t.Fatalf("Details must stay nil when IncludeDetails is false, got %v", findings[0].Details)
	}
}

// strings.EqualFold at admin-sd-holder-modified.go:140 makes the AdminSDHolder
// DN match case-insensitively; a strict "==" would miss any DN that arrives in
// a different case than DomainInfo.DN (the detector never canonicalizes it
// before comparing). MUTATION E1 target: admin-sd-holder-modified.go:140.
func TestAdminSDHolder_ObjectDNDifferentCaseStillMatches(t *testing.T) {
	differentCaseDN := "cn=adminsdholder,cn=system,dc=example,dc=com" // same object as asdhObjectDN, all lowercase
	d := NewAdminSdHolderModifiedDetector()
	findings := d.Detect(context.Background(), asdhData(
		types.ACLEntry{ObjectDN: differentCaseDN, Trustee: asdhOrdinarySID, AccessMask: maskWriteDACL, AceType: "ACCESS_ALLOWED"},
	))
	if findings[0].Count != 1 {
		t.Fatalf("an AdminSDHolder DN written in a different case than DomainInfo.DN must still be recognized and flagged, got count=%d", findings[0].Count)
	}
}

// Direct unit test on isAdminSDHolderObject with a mixed-case DN, independent
// of any other Detect logic. MUTATION E1 target: admin-sd-holder-modified.go:140.
func TestIsAdminSDHolderObject_MixedCaseDNMatches(t *testing.T) {
	mixedCaseDN := "Cn=AdMinSDHolder,CN=system,DC=EXAMPLE,dc=com" // same object as asdhObjectDN, mixed case
	if !isAdminSDHolderObject(mixedCaseDN, asdhDomainDN) {
		t.Fatal("a mixed-case AdminSDHolder DN must still match the real object, case-insensitively")
	}
}

// strings.EqualFold at admin-sd-holder-modified.go:124 makes the whitelist's
// ObjectType comparison case-insensitive; a strict "==" would reject a
// whitelisted scoped grant whose ObjectType GUID arrives in a different case
// than the hardcoded constant, misclassifying a legitimate default as a
// modification. MUTATION E2 target: admin-sd-holder-modified.go:124.
func TestAdminSDHolder_WhitelistObjectTypeDifferentCaseStillWhitelisted(t *testing.T) {
	differentCaseObjectType := "91E647DE-D96F-4B70-9557-D63FF4F3CCD8" // uppercase form of asdhPrivateInformationObjectType
	d := NewAdminSdHolderModifiedDetector()
	findings := d.Detect(context.Background(), asdhData(
		types.ACLEntry{
			ObjectDN:   asdhObjectDN,
			Trustee:    "S-1-5-10",
			ObjectType: differentCaseObjectType,
			AccessMask: types.MaskControlAccess | types.MaskReadProperty | types.MaskWriteProperty,
			AceType:    "ACCESS_ALLOWED",
		},
	))
	if findings[0].Count != 0 {
		t.Fatalf("the default SELF/Private-Information ACE must stay whitelisted when its ObjectType GUID arrives in a different case, got count=%d", findings[0].Count)
	}
}
