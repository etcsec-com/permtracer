package moderate

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// WriteValidatedDNSDetector detects Validated-Write-DNS rights on computers
type WriteValidatedDNSDetector struct {
	audit.BaseDetector
}

// NewWriteValidatedDNSDetector creates a new detector
func NewWriteValidatedDNSDetector() *WriteValidatedDNSDetector {
	return &WriteValidatedDNSDetector{
		BaseDetector: audit.NewBaseDetector("ACL_COMPUTER_WRITE_VALIDATED_DNS", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *WriteValidatedDNSDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Validated-Write to DNS-Host-Name: 72e39547-7b18-11d1-adef-00c04fd8d5cd
	const validatedDNSGUID = "72e39547-7b18-11d1-adef-00c04fd8d5cd"

	// Computers routinely live outside the default CN=Computers container
	// (custom OUs), so membership is decided by the collected computer
	// objects themselves, not by where the object happens to sit.
	computerDNs := make(map[string]bool, len(data.Computers))
	for _, c := range data.Computers {
		computerDNs[strings.ToLower(c.DN)] = true
	}

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		if !audit.IsGrantACE(ace.AceType) {
			continue
		}
		if strings.ToLower(ace.ObjectType) != validatedDNSGUID {
			continue
		}
		if !computerDNs[strings.ToLower(ace.ObjectDN)] {
			continue
		}
		// The Computer class's own Default-Security-Descriptor grants this
		// same GUID to SELF (S-1-5-10) and CREATOR OWNER (S-1-3-0) on every
		// computer object (Microsoft Learn, "Computer class"); reporting
		// that baseline ACE would describe AD's own schema, not a
		// misconfiguration.
		if audit.IsBuiltinAdminTrustee(ace.Trustee) {
			continue
		}
		// The GUID only names the property; the mask must actually grant
		// writing it (validated write or direct WriteProperty), or a
		// read-only ACE on the same ObjectType would count as a write.
		if (ace.AccessMask & (types.MaskSelf | types.MaskWriteProperty)) == 0 {
			continue
		}
		affected = append(affected, ace)
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Validated-Write-DNS on Computers",
		Description: "Principals with rights to modify DNS host names on computer objects. Can be used for DNS spoofing and MITM attacks.",
		Count:       len(uniqueObjects),
	}

	if totalInstances != len(uniqueObjects) {
		finding.TotalInstances = totalInstances
	}

	if data.IncludeDetails && len(uniqueObjects) > 0 {
		finding.AffectedEntities = audit.GetUniqueObjectEntities(affected, data.ObjectByDN)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWriteValidatedDNSDetector())
}
