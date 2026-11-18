package adcs

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

const (
	esc2TemplateDN = "CN=AnyPurpose,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com"
	esc2UnprivSID  = "S-1-5-21-1111111111-2222222222-3333333333-1106"
	esc2AdminSID   = "S-1-5-21-1111111111-2222222222-3333333333-519" // Enterprise Admins
	esc2CADN       = "CN=CorpCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com"
)

// esc2PublishingCA returns a single enterprise CA that publishes templateName
// - the baseline every pre-existing test now needs since ESC2 only counts a
// template that is actually requestable (published on an enterprise CA).
func esc2PublishingCA(templateName string) []types.CertAuthority {
	return []types.CertAuthority{
		{DN: esc2CADN, Name: "CorpCA", PublishedTemplates: []string{templateName}},
	}
}

// esc2Detect runs the detector against arbitrary data and returns the
// reported count.
func esc2Detect(t *testing.T, data *audit.DetectorData) int {
	t.Helper()
	findings := NewESC2Detector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0].Count
}

// esc2Count runs the detector against a single template plus its enrollment
// ACEs, publishing tmpl on a CA so the publication requirement doesn't
// interfere with what these tests prove, and returns the reported count.
func esc2Count(t *testing.T, tmpl types.CertTemplate, acls []types.ACLEntry) int {
	t.Helper()
	data := &audit.DetectorData{
		CertTemplates:   []types.CertTemplate{tmpl},
		ACLEntries:      acls,
		CertAuthorities: esc2PublishingCA(tmpl.Name),
	}
	return esc2Detect(t, data)
}

// esc2BaseVulnerable meets the pre-existing ESC2 conditions (no EKU
// constraint, no manager approval) - the old predicate flagged this
// regardless of RA-signature requirement or who can actually enroll.
func esc2BaseVulnerable() types.CertTemplate {
	return types.CertTemplate{
		DN:               esc2TemplateDN,
		Name:             "AnyPurpose",
		ExtendedKeyUsage: nil,
		EnrollmentFlag:   0,
	}
}

func TestESC2_FiresWhenFullyExploitable(t *testing.T) {
	tmpl := esc2BaseVulnerable()
	tmpl.AuthorizedSignatures = 0
	acls := []types.ACLEntry{
		{ObjectDN: esc2TemplateDN, Trustee: esc2UnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateAutoenrollment},
	}
	if got := esc2Count(t, tmpl, acls); got != 1 {
		t.Fatalf("fully exploitable template (no RA-signature, enrollable by unprivileged) must fire: want 1, got %d", got)
	}
}

func TestESC2_SilentWhenRASignatureRequired(t *testing.T) {
	// Old predicate flagged this via the CrossCA path; msPKI-RA-Signature >= 1
	// means an enrollment agent signature is required first.
	tmpl := esc2BaseVulnerable()
	tmpl.AuthorizedSignatures = 1
	acls := []types.ACLEntry{
		{ObjectDN: esc2TemplateDN, Trustee: esc2UnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateAutoenrollment},
	}
	if got := esc2Count(t, tmpl, acls); got != 0 {
		t.Fatalf("template requiring an RA signature is not directly exploitable: want 0, got %d", got)
	}
}

func TestESC2_SilentWhenOnlyAdminsCanEnroll(t *testing.T) {
	// Old predicate flagged this; only a privileged principal (Enterprise
	// Admins) can enroll, so this is not a privilege escalation path.
	tmpl := esc2BaseVulnerable()
	tmpl.AuthorizedSignatures = 0
	acls := []types.ACLEntry{
		{ObjectDN: esc2TemplateDN, Trustee: esc2AdminSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateAutoenrollment},
	}
	if got := esc2Count(t, tmpl, acls); got != 0 {
		t.Fatalf("template enrollable only by a privileged principal must not fire: want 0, got %d", got)
	}
}

// TestESC2_SilentWhenTemplateNotPublished covers the V8 ecart a: a
// template not published on ANY enterprise CA is not requestable by anyone,
// so it must not fire even though every other ESC2 condition is met. Before
// the fix, ESC2 never checked data.CertAuthorities at all and would have
// counted this.
func TestESC2_SilentWhenTemplateNotPublished(t *testing.T) {
	tmpl := esc2BaseVulnerable()
	tmpl.AuthorizedSignatures = 0
	data := &audit.DetectorData{
		CertTemplates: []types.CertTemplate{tmpl},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: esc2TemplateDN, Trustee: esc2UnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateAutoenrollment},
		},
		CertAuthorities: []types.CertAuthority{
			{DN: esc2CADN, Name: "CorpCA", PublishedTemplates: []string{"SomeOtherTemplate"}},
		},
	}
	if got := esc2Detect(t, data); got != 0 {
		t.Fatalf("a template not published on any CA is not requestable and must not fire: want 0, got %d", got)
	}
}

// TestESC2_SilentWhenNoCertAuthorities covers the V8 ecart a: with no
// CertAuthorities collected at all, no template can be considered published,
// so ESC2 must not fire regardless of how exploitable the template otherwise
// looks.
func TestESC2_SilentWhenNoCertAuthorities(t *testing.T) {
	tmpl := esc2BaseVulnerable()
	tmpl.AuthorizedSignatures = 0
	data := &audit.DetectorData{
		CertTemplates: []types.CertTemplate{tmpl},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: esc2TemplateDN, Trustee: esc2UnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateAutoenrollment},
		},
	}
	if got := esc2Detect(t, data); got != 0 {
		t.Fatalf("with no CertAuthorities collected, no template is requestable: want 0, got %d", got)
	}
}
