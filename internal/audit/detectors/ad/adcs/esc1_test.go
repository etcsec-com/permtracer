package adcs

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

const (
	esc1TemplateDN = "CN=Vuln,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com"
	esc1UnprivSID  = "S-1-5-21-1111111111-2222222222-3333333333-1105"
	esc1AdminSID   = "S-1-5-21-1111111111-2222222222-3333333333-512" // Domain Admins
	esc1CADN       = "CN=CorpCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com"
)

// esc1PublishingCA returns a single enterprise CA that publishes templateName
// - the baseline every pre-existing test now needs since ESC1 only counts a
// template that is actually requestable (published on an enterprise CA).
func esc1PublishingCA(templateName string) []types.CertAuthority {
	return []types.CertAuthority{
		{DN: esc1CADN, Name: "CorpCA", PublishedTemplates: []string{templateName}},
	}
}

// esc1Detect runs the detector against arbitrary data and returns the
// reported count.
func esc1Detect(t *testing.T, data *audit.DetectorData) int {
	t.Helper()
	findings := NewESC1Detector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0].Count
}

// esc1Count runs the detector against a single template plus its enrollment
// ACEs, publishing tmpl on a CA so the publication requirement doesn't
// interfere with what these tests prove, and returns the reported count.
func esc1Count(t *testing.T, tmpl types.CertTemplate, acls []types.ACLEntry) int {
	t.Helper()
	data := &audit.DetectorData{
		CertTemplates:   []types.CertTemplate{tmpl},
		ACLEntries:      acls,
		CertAuthorities: esc1PublishingCA(tmpl.Name),
	}
	return esc1Detect(t, data)
}

// esc1BaseVulnerable meets the pre-existing ESC1 conditions (enrollee supplies
// subject, client auth EKU, no manager approval) - the old predicate flagged
// this regardless of RA-signature requirement or who can actually enroll.
func esc1BaseVulnerable() types.CertTemplate {
	return types.CertTemplate{
		DN:               esc1TemplateDN,
		Name:             "Vuln",
		SubjectNameFlag:  CTFlagEnrolleeSuppliesSubject,
		ExtendedKeyUsage: []string{EKUClientAuth},
		EnrollmentFlag:   0,
	}
}

func TestESC1_FiresWhenFullyExploitable(t *testing.T) {
	tmpl := esc1BaseVulnerable()
	tmpl.AuthorizedSignatures = 0
	acls := []types.ACLEntry{
		{ObjectDN: esc1TemplateDN, Trustee: esc1UnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateEnrollment},
	}
	if got := esc1Count(t, tmpl, acls); got != 1 {
		t.Fatalf("fully exploitable template (no RA-signature, enrollable by unprivileged) must fire: want 1, got %d", got)
	}
}

func TestESC1_SilentWhenRASignatureRequired(t *testing.T) {
	// Old predicate flagged this; msPKI-RA-Signature >= 1 means an enrollment
	// agent signature is required, which is NOT directly exploitable (SpecterOps).
	tmpl := esc1BaseVulnerable()
	tmpl.AuthorizedSignatures = 1
	acls := []types.ACLEntry{
		{ObjectDN: esc1TemplateDN, Trustee: esc1UnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateEnrollment},
	}
	if got := esc1Count(t, tmpl, acls); got != 0 {
		t.Fatalf("template requiring an RA signature is not directly exploitable: want 0, got %d", got)
	}
}

func TestESC1_SilentWhenOnlyAdminsCanEnroll(t *testing.T) {
	// Old predicate flagged this; only a privileged principal (Domain Admins)
	// can enroll, so this is not a privilege escalation path.
	tmpl := esc1BaseVulnerable()
	tmpl.AuthorizedSignatures = 0
	acls := []types.ACLEntry{
		{ObjectDN: esc1TemplateDN, Trustee: esc1AdminSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateEnrollment},
	}
	if got := esc1Count(t, tmpl, acls); got != 0 {
		t.Fatalf("template enrollable only by a privileged principal must not fire: want 0, got %d", got)
	}
}

// TestESC1_SilentWhenTemplateNotPublished covers the V8 ecart a: a
// template not published on ANY enterprise CA is not requestable by anyone,
// so it must not fire even though every other ESC1 condition is met. Before
// the fix, ESC1 never checked data.CertAuthorities at all and would have
// counted this.
func TestESC1_SilentWhenTemplateNotPublished(t *testing.T) {
	tmpl := esc1BaseVulnerable()
	tmpl.AuthorizedSignatures = 0
	data := &audit.DetectorData{
		CertTemplates: []types.CertTemplate{tmpl},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: esc1TemplateDN, Trustee: esc1UnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateEnrollment},
		},
		CertAuthorities: []types.CertAuthority{
			{DN: esc1CADN, Name: "CorpCA", PublishedTemplates: []string{"SomeOtherTemplate"}},
		},
	}
	if got := esc1Detect(t, data); got != 0 {
		t.Fatalf("a template not published on any CA is not requestable and must not fire: want 0, got %d", got)
	}
}

// TestESC1_SilentWhenNoCertAuthorities covers the V8 ecart a: with no
// CertAuthorities collected at all, no template can be considered published,
// so ESC1 must not fire regardless of how exploitable the template otherwise
// looks.
func TestESC1_SilentWhenNoCertAuthorities(t *testing.T) {
	tmpl := esc1BaseVulnerable()
	tmpl.AuthorizedSignatures = 0
	data := &audit.DetectorData{
		CertTemplates: []types.CertTemplate{tmpl},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: esc1TemplateDN, Trustee: esc1UnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateEnrollment},
		},
	}
	if got := esc1Detect(t, data); got != 0 {
		t.Fatalf("with no CertAuthorities collected, no template is requestable: want 0, got %d", got)
	}
}

// TestESC1_FiresWithAnyPurposeEKU covers the V8 ecart b: HasAuthenticationEKU
// only recognizes 3 explicit authentication EKUs, but a template with the Any
// Purpose EKU (2.5.29.37.0) also permits client authentication and must fire
// just like a template with an explicit authentication EKU.
func TestESC1_FiresWithAnyPurposeEKU(t *testing.T) {
	tmpl := esc1BaseVulnerable()
	tmpl.ExtendedKeyUsage = []string{EKUAnyPurpose}
	tmpl.AuthorizedSignatures = 0
	acls := []types.ACLEntry{
		{ObjectDN: esc1TemplateDN, Trustee: esc1UnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateEnrollment},
	}
	if got := esc1Count(t, tmpl, acls); got != 1 {
		t.Fatalf("Any Purpose EKU permits authentication just like an explicit authentication EKU: want 1, got %d", got)
	}
}

// TestESC1_FiresWithNoEKUConstraint covers the V8 ecart b: a template
// with no EKU constraint at all also permits client authentication and must
// fire just like a template with an explicit authentication EKU.
func TestESC1_FiresWithNoEKUConstraint(t *testing.T) {
	tmpl := esc1BaseVulnerable()
	tmpl.ExtendedKeyUsage = nil
	tmpl.AuthorizedSignatures = 0
	acls := []types.ACLEntry{
		{ObjectDN: esc1TemplateDN, Trustee: esc1UnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateEnrollment},
	}
	if got := esc1Count(t, tmpl, acls); got != 1 {
		t.Fatalf("no EKU constraint permits authentication just like an explicit authentication EKU: want 1, got %d", got)
	}
}
