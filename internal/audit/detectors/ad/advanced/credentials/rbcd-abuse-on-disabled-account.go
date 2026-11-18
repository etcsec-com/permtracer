package credentials

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// RBCDAbuseOnDisabledAccountDetector checks for disabled computers carrying
// a resource-based constrained delegation (RBCD) configuration
// (msDS-AllowedToActOnBehalfOfOtherIdentity). Split out of
// RBCDAbuseDetector: exploiting RBCD requires the KDC to issue a Kerberos
// service ticket (S4U2Proxy) for an SPN belonging to the computer that
// carries the attribute, and the KDC refuses to issue a service ticket for
// a disabled account's SPN - the same target-side refusal measured
// directly against a real KDC for the sibling
// UNCONSTRAINED_DELEGATION_ON_DISABLED_ACCOUNT split (see
// docs/security-validation/results/unconstrained-delegation-disabled-v2/VERDICT.md).
// The attribute itself is not removed by this state - it persists on the
// object and reasserts full exploitability the instant the computer is
// re-enabled, which is the residual risk this detector keeps reporting.
//
// Severity Medium, not Low: this is a full computer-identity takeover
// primitive (the attribute lets the listed principal impersonate ANY
// domain user to every service hosted on the target), the same class of
// risk as SHADOW_CREDENTIALS, per the split severity grid (D1) - not a
// hygiene finding.
//
// Named RBCD_ABUSE_ON_DISABLED_ACCOUNT, not RBCD_ABUSE_DISABLED: the
// _DISABLED suffix is reserved elsewhere in this catalog for "a protection
// was turned off" (LDAP_SIGNING_DISABLED, TRUST_AES_DISABLED, ...), which
// reads as bad news. Naming the population instead of a mechanism state
// avoids an auditor misreading this as the risk itself being off.
type RBCDAbuseOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewRBCDAbuseOnDisabledAccountDetector creates a new detector
func NewRBCDAbuseOnDisabledAccountDetector() *RBCDAbuseOnDisabledAccountDetector {
	return &RBCDAbuseOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("RBCD_ABUSE_ON_DISABLED_ACCOUNT", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *RBCDAbuseOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedComputers []types.Computer

	for _, c := range data.Computers {
		if !c.Disabled {
			continue
		}
		if len(c.AllowedToActOnBehalfOfOtherIdentity) > 0 {
			affectedComputers = append(affectedComputers, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "RBCD Abuse (Disabled Account)",
		Description: "Disabled computers with msDS-AllowedToActOnBehalfOfOtherIdentity configured. Not exploitable today - the KDC refuses to issue a service ticket for a disabled computer's SPN, which closes the S4U2Proxy step this configuration relies on - but the attribute remains set and would re-enable full resource-based constrained delegation abuse the instant the computer is re-enabled.",
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
	audit.MustRegister(NewRBCDAbuseOnDisabledAccountDetector())
}
