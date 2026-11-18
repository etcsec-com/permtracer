package credentials

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// RBCDAbuseDetector detects RBCD abuse configurations
type RBCDAbuseDetector struct {
	audit.BaseDetector
}

// NewRBCDAbuseDetector creates a new detector
func NewRBCDAbuseDetector() *RBCDAbuseDetector {
	return &RBCDAbuseDetector{
		BaseDetector: audit.NewBaseDetector("RBCD_ABUSE", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
//
// Disabled target computers are excluded here on purpose: exploiting this
// attribute requires the KDC to issue a Kerberos service ticket
// (S4U2Proxy) for an SPN belonging to the computer that carries it, and the
// KDC refuses to issue a service ticket for a disabled account's SPN - the
// same target-side refusal measured directly against a real KDC for the
// sibling UNCONSTRAINED_DELEGATION_ON_DISABLED_ACCOUNT split (see
// docs/security-validation/results/unconstrained-delegation-disabled-v2/VERDICT.md).
// The attribute itself is not removed by this state - it persists on the
// object and reasserts full exploitability the instant the computer is
// re-enabled, which is why it is not dropped from the audit: it is
// reported separately, at Medium, by RBCDAbuseOnDisabledAccountDetector -
// the same computer-identity-takeover class of risk as SHADOW_CREDENTIALS,
// not a hygiene finding.
func (d *RBCDAbuseDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedComputers []types.Computer

	// Check computers for RBCD configuration
	for _, c := range data.Computers {
		if c.Disabled {
			continue
		}
		// Check msDS-AllowedToActOnBehalfOfOtherIdentity attribute
		if len(c.AllowedToActOnBehalfOfOtherIdentity) > 0 {
			affectedComputers = append(affectedComputers, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "RBCD Abuse",
		Description: "Computers with msDS-AllowedToActOnBehalfOfOtherIdentity configured. This enables privilege escalation via resource-based constrained delegation attacks. Disabled computers are reported separately by RBCD_ABUSE_ON_DISABLED_ACCOUNT.",
		Count:       len(affectedComputers),
	}

	if data.IncludeDetails && len(affectedComputers) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affectedComputers)
		finding.Details = map[string]interface{}{
			"recommendation": "Review and remove unnecessary RBCD configurations. This attribute should only be set when resource-based constrained delegation is intentionally configured.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewRBCDAbuseDetector())
}
