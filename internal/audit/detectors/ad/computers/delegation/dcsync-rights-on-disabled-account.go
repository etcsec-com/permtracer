package delegation

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// DCSyncRightsOnDisabledAccountDetector checks for disabled computer
// accounts holding DCSync replication rights. Split out of
// DCSyncRightsDetector, on the same model as the computer delegation pair
// in this same package (UnconstrainedDelegationDetector /
// UnconstrainedDelegationOnDisabledAccountDetector): a disabled computer
// account cannot authenticate, so it cannot mount the DRSUAPI session its
// replication rights would require. The rights themselves are not removed
// by this state - they persist and reassert full exploitability the instant
// the account is re-enabled, which is the residual risk this detector keeps
// reporting.
type DCSyncRightsOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewDCSyncRightsOnDisabledAccountDetector creates a new detector
func NewDCSyncRightsOnDisabledAccountDetector() *DCSyncRightsOnDisabledAccountDetector {
	return &DCSyncRightsOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_DCSYNC_RIGHTS_ON_DISABLED_ACCOUNT", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *DCSyncRightsOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if !c.Disabled {
			continue
		}
		if c.ReplicationRights {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Computer DCSync Rights (Disabled Account)",
		Description: "Disabled computer account holds DCSync replication rights (DS-Replication-Get-Changes / DS-Replication-Get-Changes-All) on the domain root. It cannot authenticate while disabled, so it cannot mount the DRSUAPI session those rights would require today. Replication rights are a domain-level privilege that the disabled account retains: they remain granted on the object and become exploitable again the instant the account is re-enabled. Remediation: remove the replication rights or delete the account.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDCSyncRightsOnDisabledAccountDetector())
}
