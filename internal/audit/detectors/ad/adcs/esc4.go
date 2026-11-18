package adcs

import (
	"context"
	"sort"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// ESC4Detector detects ESC4: Vulnerable Certificate Template ACL
type ESC4Detector struct {
	audit.BaseDetector
}

// NewESC4Detector creates a new detector
func NewESC4Detector() *ESC4Detector {
	return &ESC4Detector{
		BaseDetector: audit.NewBaseDetector("ESC4_VULNERABLE_TEMPLATE_ACL", audit.CategoryADCS),
	}
}

// Access mask constants
const (
	GenericAll    = 0x10000000
	GenericWrite  = 0x40000000
	WriteDACL     = 0x00040000
	WriteOwner    = 0x00080000
	WriteProperty = 0x00000020
)

// isDangerousAccessMask reports whether mask+objectType together grant a
// dangerous, ESC4-relevant right on a certificate template.
//
// GenericAll, WriteOwner and WriteDacl are object-wide rights: they are never
// scoped by ObjectType, so they are always dangerous when granted.
//
// WriteProperty is different: on an ACCESS_ALLOWED_OBJECT ACE, an ObjectType
// GUID restricts the grant to a single attribute (or property set); only an
// ACE with no ObjectType (empty string here) grants write access to every
// property of the object. SpecterOps, "Certified Pre-Owned" / Certify wiki,
// ESC4 ("Vulnerable Certificate Template Access Control") describes exactly
// this right as "the principal has generic write on the object and can edit
// any property" - i.e. it is the all-properties case that lets an attacker
// rewrite msPKI-Certificate-Name-Flag/pKIExtendedKeyUsage/etc. into an ESC1
// shape. A WriteProperty ACE scoped to one unrelated attribute cannot do that
// and was previously flagged regardless of ObjectType, which is exactly the
// "default ACL noise" over-reporting this detector was producing.
//
// GenericWrite was declared as a constant and named in this detector's own
// remediation text but was never actually checked against the mask - a real
// under-reporting bug, fixed here.
func isDangerousAccessMask(mask int, objectType string) bool {
	if (mask&GenericAll) != 0 ||
		(mask&GenericWrite) != 0 ||
		(mask&WriteDACL) != 0 ||
		(mask&WriteOwner) != 0 {
		return true
	}
	return (mask&WriteProperty) != 0 && objectType == ""
}

// Detect executes the detection
func (d *ESC4Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if data.DomainInfo == nil {
		finding := types.Finding{
			Type:        d.ID(),
			Severity:    types.SeverityCritical,
			Category:    string(d.Category()),
			Title:       "ESC4 - Certificate Template ACL Review Required",
			Description: "Certificate templates with authentication capability should be reviewed for overly permissive ACLs that allow non-admins to modify template properties.",
			Count:       0,
			Details: map[string]interface{}{
				"note": "Domain information not available for analysis.",
			},
		}
		return []types.Finding{finding}
	}

	// Build map of template DNs for quick lookup
	templateDNs := make(map[string]*types.CertTemplate)
	for i := range data.CertTemplates {
		templateDNs[data.CertTemplates[i].DN] = &data.CertTemplates[i]
	}

	affectedTemplates := make(map[string]*types.CertTemplate)
	dangerousACEsMap := make(map[string][]types.ACLEntry)
	detailsMap := make(map[string][]map[string]interface{})

	// Check ACL entries for certificate templates
	for _, acl := range data.ACLEntries {
		// Check if this ACL is for a certificate template
		template, isTemplate := templateDNs[acl.ObjectDN]
		if !isTemplate {
			continue
		}

		// Only a template published on at least one enterprise CA is
		// actually requestable.
		if !templatePublishedOnAnyCA(template.Name, data.CertAuthorities) {
			continue
		}

		// Skip if trustee is a built-in administrative principal expected to
		// hold broad rights by AD's own design (SYSTEM, SELF, CREATOR OWNER,
		// Enterprise Domain Controllers, and privileged group RID suffixes).
		trusteeSID := acl.Trustee
		if audit.IsBuiltinAdminTrustee(trusteeSID) {
			continue
		}

		// Skip ACEs that don't grant access (e.g. ACCESS_DENIED): a deny ACE
		// restricts, it never extends, what a trustee can do.
		if !audit.IsGrantACE(acl.AceType) {
			continue
		}

		// Check for dangerous permissions
		if isDangerousAccessMask(acl.AccessMask, acl.ObjectType) {
			affectedTemplates[template.DN] = template
			dangerousACEsMap[template.DN] = append(dangerousACEsMap[template.DN], acl)

			if data.IncludeDetails {
				templateName := template.Name
				if templateName == "" {
					templateName = template.DisplayName
				}

				detailsMap[templateName] = append(detailsMap[templateName], map[string]interface{}{
					"dn":         template.DN,
					"trustee":    acl.Trustee,
					"accessMask": acl.AccessMask,
					"aceType":    acl.AceType,
				})
			}
		}
	}

	// A template owned by a non-administrative principal is Owner-equivalent
	// on it (owners implicitly hold WRITE_DAC/WRITE_OWNER) regardless of what
	// its ACEs grant, which the finding's own Description names explicitly.
	// Count it once even when no ACE above already flagged it.
	for i := range data.CertTemplates {
		template := &data.CertTemplates[i]
		if _, already := affectedTemplates[template.DN]; already {
			continue
		}
		if !templatePublishedOnAnyCA(template.Name, data.CertAuthorities) {
			continue
		}
		if data.ObjectOwners == nil {
			continue
		}
		ownerSID, hasOwner := data.ObjectOwners[template.DN]
		if !hasOwner || ownerSID == "" || audit.IsBuiltinAdminTrustee(ownerSID) {
			continue
		}
		affectedTemplates[template.DN] = template
	}

	// Severity/scope per SpecterOps "Certified Pre-Owned" / Certify wiki, ESC4
	// ("Vulnerable Certificate Template Access Control": Owner, Full Control,
	// generic Write Property, Write Owner and Write Dacl held by a
	// non-administrative principal let that principal reconfigure the template
	// into an ESC1/ESC2/ESC3/ESC9/ESC13/ESC15 shape) and Microsoft Learn,
	// Defender for Identity - "Edit misconfigured certificate templates ACL
	// (ESC4)" (security-posture-assessments/certificates.md), which likewise
	// flags an ACE granting a built-in unprivileged group (Authenticated
	// Users/Domain Users/Everyone) Full Control or Write DACL on a template.
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "ESC4 - Vulnerable Certificate Template ACL",
		Description: "Certificate templates published on an enterprise CA with dangerous permissions (Owner-equivalent, GenericAll/GenericWrite, WriteDACL, WriteOwner, or an unscoped WriteProperty granting write to every attribute) granted to non-administrator principals. This allows unauthorized modification of template properties, potentially enabling certificate-based attacks.",
		Count:       len(affectedTemplates),
	}

	if data.IncludeDetails && len(affectedTemplates) > 0 {
		// Sorted by DN: affectedTemplates is a map, so ranging
		// it directly gives a randomized order per process - same input,
		// different JSON, different sha256 across runs.
		dns := make([]string, 0, len(affectedTemplates))
		for dn := range affectedTemplates {
			dns = append(dns, dn)
		}
		sort.Strings(dns)

		entities := make([]types.AffectedEntity, 0, len(affectedTemplates))
		for _, dn := range dns {
			t := affectedTemplates[dn]
			ownerSID := ""
			if data.ObjectOwners != nil {
				ownerSID = data.ObjectOwners[t.DN]
			}
			entities = append(entities, helpers.CertTemplateToAffectedEntityWithACL(t, ownerSID, dangerousACEsMap[t.DN]))
		}
		finding.AffectedEntities = entities
	}

	if data.IncludeDetails && len(detailsMap) > 0 {
		finding.Details = map[string]interface{}{
			"recommendation":    "Remove GenericAll, GenericWrite, WriteDACL, WriteOwner, and WriteProperty permissions for non-admin principals on certificate templates.",
			"affectedTemplates": detailsMap,
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewESC4Detector())
}
