package delegation

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// ConstrainedDelegationOnDisabledAccountDetector checks for disabled
// computer accounts configured for constrained Kerberos delegation. Split
// out of ConstrainedDelegationDetector, on the same model as the computer
// delegation pair in this same package (UnconstrainedDelegationDetector /
// UnconstrainedDelegationOnDisabledAccountDetector): a disabled computer
// account cannot obtain a TGT of its own, so it cannot exercise the
// delegation it is configured for. The configuration itself is not removed
// by this state - it persists and reasserts full exploitability the instant
// the account is re-enabled, which is the residual risk this detector keeps
// reporting.
type ConstrainedDelegationOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewConstrainedDelegationOnDisabledAccountDetector creates a new detector
func NewConstrainedDelegationOnDisabledAccountDetector() *ConstrainedDelegationOnDisabledAccountDetector {
	return &ConstrainedDelegationOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_CONSTRAINED_DELEGATION_ON_DISABLED_ACCOUNT", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *ConstrainedDelegationOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if !c.Disabled {
			continue
		}
		if len(c.AllowedToDelegateTo) > 0 {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Computer Constrained Delegation (Disabled Account)",
		Description: "Disabled computer account is configured for constrained Kerberos delegation (msDS-AllowedToDelegateTo). It cannot obtain a ticket-granting ticket while disabled, so it cannot exercise the delegation today. The configuration persists on the object and becomes exploitable again the instant the account is re-enabled; by itself it does not carry a privileged group membership, a replication right, or an exposed secret. Remediation: remove the delegation configuration or delete the account.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewConstrainedDelegationOnDisabledAccountDetector())
}
