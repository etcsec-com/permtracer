package dangerous

import (
	"testing"

	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestEnterpriseKeyAdmins_DenyACENotCounted pins the fix for this reader:
// ENTERPRISE_KEY_ADMINS_FULL_ACCESS tested Trustee/ObjectType/
// AccessMask but never AceType, so once acl_parser.go starts collecting deny
// ACEs this detector would count a Deny GenericAll on Enterprise Key Admins
// as if it were a grant. Before the fix (no audit.IsGrantACE guard), this ACE
// counted; after, it must not.
func TestEnterpriseKeyAdmins_DenyACENotCounted(t *testing.T) {
	enterpriseKeyAdminsSID := aclDomain + "-527"

	f := detectOne(t, NewEnterpriseKeyAdminsDetector(), aclData(
		types.ACLEntry{ObjectDN: aclDomainDN, Trustee: enterpriseKeyAdminsSID, AccessMask: maskFullControl, AceType: "ACCESS_DENIED"},
	))
	if f.Count != 0 {
		t.Fatalf("a Deny ACE granting full control to Enterprise Key Admins must not be counted as a grant, got count=%d", f.Count)
	}
}

// TestEnterpriseKeyAdmins_WritePropertyOtherAttributeNotCounted pins that
// WriteProperty alone is not enough: it must land on msDS-KeyCredentialLink
// specifically. A WriteProperty grant on an unrelated attribute (here
// servicePrincipalName) carries none of the Shadow Credentials risk this
// detector exists for and must not be counted.
func TestEnterpriseKeyAdmins_WritePropertyOtherAttributeNotCounted(t *testing.T) {
	enterpriseKeyAdminsSID := aclDomain + "-527"
	const servicePrincipalNameGUID = "f3a64788-5306-11d1-a9c5-0000f80367c1"

	f := detectOne(t, NewEnterpriseKeyAdminsDetector(), aclData(
		types.ACLEntry{ObjectDN: aclDomainDN, Trustee: enterpriseKeyAdminsSID, AccessMask: types.MaskWriteProperty, AceType: "ACCESS_ALLOWED_OBJECT", ObjectType: servicePrincipalNameGUID},
	))
	if f.Count != 0 {
		t.Fatalf("WriteProperty on an attribute other than msDS-KeyCredentialLink must not be counted, got count=%d", f.Count)
	}
}

// TestEnterpriseKeyAdmins_TwoACEsOneObjectCountsOnce pins that Count reports
// unique affected objects, not raw ACE instances: two separate grant ACEs to
// Enterprise Key Admins on the same object must still report Count 1.
func TestEnterpriseKeyAdmins_TwoACEsOneObjectCountsOnce(t *testing.T) {
	enterpriseKeyAdminsSID := aclDomain + "-527"
	const keyCredentialLinkGUID = "5b47d60f-6090-40b2-9f37-2a4de88f3063"

	f := detectOne(t, NewEnterpriseKeyAdminsDetector(), aclData(
		types.ACLEntry{ObjectDN: aclDomainDN, Trustee: enterpriseKeyAdminsSID, AccessMask: types.MaskWriteProperty, AceType: "ACCESS_ALLOWED_OBJECT", ObjectType: keyCredentialLinkGUID},
		types.ACLEntry{ObjectDN: aclDomainDN, Trustee: enterpriseKeyAdminsSID, AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 1 {
		t.Fatalf("two grant ACEs to Enterprise Key Admins on the same object must count the object once, got count=%d", f.Count)
	}
	if f.TotalInstances != 2 {
		t.Fatalf("TotalInstances must report both ACE instances, got %d", f.TotalInstances)
	}
}
