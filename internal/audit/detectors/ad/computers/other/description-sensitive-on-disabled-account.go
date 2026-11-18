package other

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// DescriptionSensitiveOnDisabledAccountDetector checks for disabled
// computer accounts with sensitive data in the description field. Split
// out of DescriptionSensitiveDetector: UF_ACCOUNTDISABLE blocks
// authentication for this account across every protocol, but it does not
// close read access to the object's attributes - the description field
// stays fully readable to any identity with ordinary directory-read
// access, independent of the disabled state. A password, internal IP, or
// privileged identifier sitting in the description of a disabled computer
// is exploitable today exactly as it would be on an active one (for
// example, a reused password), which is why this twin keeps the same
// Medium severity as the active detector rather than being downgraded.
//
// Named COMPUTER_DESCRIPTION_SENSITIVE_ON_DISABLED_ACCOUNT, not
// COMPUTER_DESCRIPTION_SENSITIVE_DISABLED: the _DISABLED suffix is
// reserved elsewhere in this catalog for "a protection was turned off",
// which reads as bad news. Naming the population instead of a mechanism
// state avoids an auditor misreading this as the risk itself being off.
type DescriptionSensitiveOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewDescriptionSensitiveOnDisabledAccountDetector creates a new detector
func NewDescriptionSensitiveOnDisabledAccountDetector() *DescriptionSensitiveOnDisabledAccountDetector {
	return &DescriptionSensitiveOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_DESCRIPTION_SENSITIVE_ON_DISABLED_ACCOUNT", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *DescriptionSensitiveOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if !c.Disabled {
			continue
		}
		if c.Description == "" {
			continue
		}
		for _, pattern := range sensitivePatterns {
			if pattern.MatchString(c.Description) {
				affected = append(affected, c)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Computer Description Sensitive (Disabled Account)",
		Description: "Disabled computer account with sensitive data (passwords, IPs, etc.) in its description. The account cannot authenticate, but the description field remains readable by anyone with ordinary directory-read access regardless of the disabled state. Information disclosure.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDescriptionSensitiveOnDisabledAccountDetector())
}
