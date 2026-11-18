package adcs

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// ESC1Detector detects ESC1: Misconfigured Certificate Template
type ESC1Detector struct {
	audit.BaseDetector
}

// NewESC1Detector creates a new detector
func NewESC1Detector() *ESC1Detector {
	return &ESC1Detector{
		BaseDetector: audit.NewBaseDetector("ESC1_VULNERABLE_TEMPLATE", audit.CategoryADCS),
	}
}

// Detect executes the detection
func (d *ESC1Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedTemplates []types.CertTemplate

	for _, t := range data.CertTemplates {
		// Enrollee can supply subject
		enrolleeSuppliesSubject := (t.SubjectNameFlag & CTFlagEnrolleeSuppliesSubject) != 0

		// Has authentication capability. Beyond the three explicit
		// authentication EKUs, a template with the Any Purpose EKU
		// (2.5.29.37.0) or with no EKU constraint at all also permits
		// client authentication. HasAuthenticationEKU itself stays
		// unchanged since other callers rely on its narrower check.
		canAuthenticate := HasAuthenticationEKU(t.ExtendedKeyUsage) ||
			len(t.ExtendedKeyUsage) == 0 ||
			ContainsEKU(t.ExtendedKeyUsage, EKUAnyPurpose)

		// Doesn't require manager approval
		noApprovalRequired := (t.EnrollmentFlag & CTFlagPendAllRequests) == 0

		// No enrollment agent signature required (msPKI-RA-Signature); a
		// template requiring one is not directly exploitable (SpecterOps ESC1).
		noRASignatureRequired := t.AuthorizedSignatures == 0

		// A non-privileged principal can enroll in this template
		enrollableByUnprivileged := templateEnrollableByUnprivileged(t.DN, data.ACLEntries)

		// Only a template published on at least one enterprise CA is
		// actually requestable.
		published := templatePublishedOnAnyCA(t.Name, data.CertAuthorities)

		if enrolleeSuppliesSubject && canAuthenticate && noApprovalRequired &&
			noRASignatureRequired && enrollableByUnprivileged && published {
			affectedTemplates = append(affectedTemplates, t)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "ESC1 - Misconfigured Certificate Template",
		Description: "Certificate template allows enrollee to specify Subject Alternative Name (SAN), has client authentication EKU, and is published on an enterprise CA, enabling privilege escalation to any user/computer.",
		Count:       len(affectedTemplates),
	}

	if data.IncludeDetails && len(affectedTemplates) > 0 {
		finding.AffectedEntities = helpers.ToAffectedCertTemplateEntities(affectedTemplates)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewESC1Detector())
}
