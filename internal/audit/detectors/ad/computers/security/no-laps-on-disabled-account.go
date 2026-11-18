package security

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// NoLapsOnDisabledAccountDetector checks for disabled computer accounts
// without LAPS deployed. Split out of NoLapsDetector, on the same model as
// AdminCountOnDisabledAccountDetector in computers/status: an unmanaged
// local administrator password on a disabled computer account is a
// dormant configuration residue, not a live administrative surface - the
// account cannot authenticate while disabled - but the local admin
// password stays static/potentially shared and becomes fully relevant
// again the instant the account is re-enabled, without any remediation
// having happened in the meantime. Does not reproduce the active
// detector's schema-extended severity escalation: that logic recategorizes
// the active population's own severity and title, and has no precedent of
// being replicated on a disabled-account twin in this catalog.
type NoLapsOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewNoLapsOnDisabledAccountDetector creates a new detector
func NewNoLapsOnDisabledAccountDetector() *NoLapsOnDisabledAccountDetector {
	return &NoLapsOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_NO_LAPS_ON_DISABLED_ACCOUNT", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *NoLapsOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// SERVER_TRUST_ACCOUNT flag for Domain Controllers
	const serverTrustAccount = 0x2000

	var affected []types.Computer

	for _, c := range data.Computers {
		// Only check disabled computers
		if !c.Disabled {
			continue
		}

		// Skip Domain Controllers (they don't use LAPS)
		if (c.UserAccountControl & serverTrustAccount) != 0 {
			continue
		}

		// No LAPS if neither legacy nor Windows LAPS is configured
		if !c.HasLegacyLAPS && !c.HasWindowsLAPS {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Computer No LAPS (Disabled Account)",
		Description: "Disabled computer account without LAPS deployed. The local administrator password stays unmanaged and potentially shared, but the account cannot authenticate while disabled, so this is a dormant configuration residue rather than a live administrative surface. It becomes fully relevant again the instant the account is re-enabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoLapsOnDisabledAccountDetector())
}
