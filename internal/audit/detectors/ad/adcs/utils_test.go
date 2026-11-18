package adcs

import (
	"testing"

	"github.com/etcsec-com/permtracer/pkg/types"
)

const (
	utilsTemplateDN = "CN=Vuln,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com"
	utilsUnprivSID  = "S-1-5-21-1111111111-2222222222-3333333333-1105"
	utilsAdminSID   = "S-1-5-21-1111111111-2222222222-3333333333-512" // Domain Admins
)

func TestTemplateEnrollableByUnprivileged_GUIDGrant(t *testing.T) {
	acls := []types.ACLEntry{
		{ObjectDN: utilsTemplateDN, Trustee: utilsUnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateEnrollment},
	}
	if !templateEnrollableByUnprivileged(utilsTemplateDN, acls) {
		t.Fatal("a Certificate-Enrollment GUID grant to a non-privileged trustee must count as enrollable")
	}
}

func TestTemplateEnrollableByUnprivileged_AutoenrollGUIDGrant(t *testing.T) {
	acls := []types.ACLEntry{
		{ObjectDN: utilsTemplateDN, Trustee: utilsUnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateAutoenrollment},
	}
	if !templateEnrollableByUnprivileged(utilsTemplateDN, acls) {
		t.Fatal("a Certificate-AutoEnrollment GUID grant to a non-privileged trustee must count as enrollable")
	}
}

func TestTemplateEnrollableByUnprivileged_GenericAllGrant(t *testing.T) {
	acls := []types.ACLEntry{
		{ObjectDN: utilsTemplateDN, Trustee: utilsUnprivSID, AceType: "ACCESS_ALLOWED", AccessMask: GenericAll},
	}
	if !templateEnrollableByUnprivileged(utilsTemplateDN, acls) {
		t.Fatal("a full-control (GenericAll) grant to a non-privileged trustee must count as enrollable")
	}
}

func TestTemplateEnrollableByUnprivileged_AdminOnlyIsNotEnrollable(t *testing.T) {
	acls := []types.ACLEntry{
		{ObjectDN: utilsTemplateDN, Trustee: utilsAdminSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateEnrollment},
	}
	if templateEnrollableByUnprivileged(utilsTemplateDN, acls) {
		t.Fatal("a grant restricted to a privileged trustee (Domain Admins) must not count as unprivileged-enrollable")
	}
}

func TestTemplateEnrollableByUnprivileged_DenyIgnored(t *testing.T) {
	acls := []types.ACLEntry{
		{ObjectDN: utilsTemplateDN, Trustee: utilsUnprivSID, AceType: "deny", ObjectType: types.GUIDCertificateEnrollment},
	}
	if templateEnrollableByUnprivileged(utilsTemplateDN, acls) {
		t.Fatal("a deny ACE must not grant enrollment")
	}
}

// TestTemplateEnrollableByUnprivileged_RealDenyACEIgnored pins the fix for
// this shared helper (ESC1/ESC2/ESC3): the previous guard
// compared AceType to the literal "deny", a string acl_parser.go's
// aceTypeToString never actually produces (it emits ACCESS_DENIED /
// ACCESS_DENIED_OBJECT) - the guard never ran. Now that acl_parser.go
// collects deny ACEs under their real AceType, a real ACCESS_DENIED_OBJECT
// ACE granting Certificate-Enrollment must still not count as enrollable.
func TestTemplateEnrollableByUnprivileged_RealDenyACEIgnored(t *testing.T) {
	acls := []types.ACLEntry{
		{ObjectDN: utilsTemplateDN, Trustee: utilsUnprivSID, AceType: "ACCESS_DENIED_OBJECT", ObjectType: types.GUIDCertificateEnrollment},
	}
	if templateEnrollableByUnprivileged(utilsTemplateDN, acls) {
		t.Fatal("a real ACCESS_DENIED_OBJECT ACE (the AceType the parser actually produces) must not grant enrollment")
	}
}

func TestTemplateEnrollableByUnprivileged_UnrelatedRightIgnored(t *testing.T) {
	acls := []types.ACLEntry{
		{ObjectDN: utilsTemplateDN, Trustee: utilsUnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDLAPSPassword},
	}
	if templateEnrollableByUnprivileged(utilsTemplateDN, acls) {
		t.Fatal("an ACE unrelated to enrollment rights must not count as enrollable")
	}
}

func TestTemplateEnrollableByUnprivileged_OtherDNIgnored(t *testing.T) {
	acls := []types.ACLEntry{
		{ObjectDN: "CN=Other," + utilsTemplateDN, Trustee: utilsUnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateEnrollment},
	}
	if templateEnrollableByUnprivileged(utilsTemplateDN, acls) {
		t.Fatal("an ACE on a different object DN must not apply to this template")
	}
}

func TestTemplateEnrollableByUnprivileged_NoACLs(t *testing.T) {
	if templateEnrollableByUnprivileged(utilsTemplateDN, nil) {
		t.Fatal("no ACL entries means no one can be shown to enroll")
	}
}

// TestTemplatePublishedOnAnyCA_MatchesCaseInsensitive covers the V8 ecart a:
// data.CertAuthorities[].PublishedTemplates holds template names from the
// certificateTemplates attribute, which is case-insensitive in AD. A template
// whose Name differs only by case from the published entry must still be
// considered published.
func TestTemplatePublishedOnAnyCA_MatchesCaseInsensitive(t *testing.T) {
	cas := []types.CertAuthority{
		{Name: "CorpCA", PublishedTemplates: []string{"VulnTemplate"}},
	}
	if !templatePublishedOnAnyCA("vulntemplate", cas) {
		t.Fatalf("expected case-insensitive match against PublishedTemplates")
	}
}

// TestTemplatePublishedOnAnyCA_NoMatch covers the ecart: a template name not
// present on any CA's PublishedTemplates must not be reported as published.
func TestTemplatePublishedOnAnyCA_NoMatch(t *testing.T) {
	cas := []types.CertAuthority{
		{Name: "CorpCA", PublishedTemplates: []string{"OtherTemplate"}},
	}
	if templatePublishedOnAnyCA("VulnTemplate", cas) {
		t.Fatalf("template not listed in any CA's PublishedTemplates must not be reported as published")
	}
}

// TestTemplatePublishedOnAnyCA_NoCertAuthorities covers the ecart: with no
// CertAuthorities collected at all, no template can be requestable, so the
// helper must report false regardless of the template name.
func TestTemplatePublishedOnAnyCA_NoCertAuthorities(t *testing.T) {
	if templatePublishedOnAnyCA("VulnTemplate", nil) {
		t.Fatalf("with no CertAuthorities collected, no template is published")
	}
}

// TestTemplatePublishedOnAnyCA_SecondCAPublishes covers the ecart: a template
// must be considered published as soon as ANY one of several collected CAs
// lists it, not only the first.
func TestTemplatePublishedOnAnyCA_SecondCAPublishes(t *testing.T) {
	cas := []types.CertAuthority{
		{Name: "CA1", PublishedTemplates: []string{"OtherTemplate"}},
		{Name: "CA2", PublishedTemplates: []string{"VulnTemplate"}},
	}
	if !templatePublishedOnAnyCA("VulnTemplate", cas) {
		t.Fatalf("expected a match from the second CA's PublishedTemplates")
	}
}
