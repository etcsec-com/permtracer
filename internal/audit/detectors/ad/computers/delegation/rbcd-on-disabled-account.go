package delegation

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// RbcdOnDisabledAccountDetector checks for disabled computer accounts with
// Resource-Based Constrained Delegation configured. Split out of
// RbcdDetector, on the same model as RBCDAbuseOnDisabledAccountDetector
// (advanced/credentials), which tests the exact same
// msDS-AllowedToActOnBehalfOfOtherIdentity condition: exploiting this
// configuration requires the KDC to issue a Kerberos service ticket
// (S4U2Proxy) for an SPN belonging to the computer that carries the
// attribute, and the KDC refuses to issue a service ticket for a disabled
// account's SPN. The security descriptor itself is not removed by this
// state - it persists and reasserts full exploitability the instant the
// account is re-enabled, which is the residual risk this detector keeps
// reporting.
type RbcdOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewRbcdOnDisabledAccountDetector creates a new detector
func NewRbcdOnDisabledAccountDetector() *RbcdOnDisabledAccountDetector {
	return &RbcdOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_RBCD_ON_DISABLED_ACCOUNT", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *RbcdOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if !c.Disabled {
			continue
		}
		if len(c.AllowedToActOnBehalfOfOtherIdentity) > 0 {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Computer RBCD (Disabled Account)",
		Description: "Disabled computer account has Resource-Based Constrained Delegation configured (msDS-AllowedToActOnBehalfOfOtherIdentity). Not exploitable today: the KDC refuses to issue a Kerberos service ticket (S4U2Proxy) for a disabled account's SPN, which blocks the step this configuration relies on. The security descriptor lets the listed principal(s) impersonate any domain user to every service hosted by this computer - a domain-level delegation privilege that the disabled account retains and that returns to full effect the instant the account is re-enabled. Remediation: remove the RBCD configuration or delete the account.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewRbcdOnDisabledAccountDetector())
}
