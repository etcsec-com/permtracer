package security

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// NoLapsDetector checks for computers without LAPS deployed
type NoLapsDetector struct {
	audit.BaseDetector
}

// NewNoLapsDetector creates a new detector
func NewNoLapsDetector() *NoLapsDetector {
	return &NoLapsDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_NO_LAPS", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *NoLapsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// SERVER_TRUST_ACCOUNT flag for Domain Controllers
	const serverTrustAccount = 0x2000

	// Track whether any active computer actually uses LAPS (indicates usage, not schema extension)
	var anyActiveLegacyLAPS, anyActiveWindowsLAPS bool
	var withLegacyLaps, withWindowsLaps int

	var affected []types.Computer

	for _, c := range data.Computers {
		// Only check enabled computers
		if c.Disabled {
			continue
		}

		// Skip Domain Controllers (they don't use LAPS)
		if (c.UserAccountControl & serverTrustAccount) != 0 {
			continue
		}

		// Track LAPS usage on the active fleet
		if c.HasLegacyLAPS {
			anyActiveLegacyLAPS = true
			withLegacyLaps++
		}
		if c.HasWindowsLAPS {
			anyActiveWindowsLAPS = true
			withWindowsLaps++
		}

		// No LAPS if neither legacy nor Windows LAPS is configured
		if !c.HasLegacyLAPS && !c.HasWindowsLAPS {
			affected = append(affected, c)
		}
	}

	// Measures usage on the active fleet, not whether the schema is extended
	lapsInUseOnActiveFleet := anyActiveLegacyLAPS || anyActiveWindowsLAPS

	severity := types.SeverityHigh
	title := "Computer No LAPS"
	description := "Computer without LAPS deployed. Shared/static local admin passwords across workstations."

	if !lapsInUseOnActiveFleet && len(affected) > 0 {
		severity = types.SeverityCritical
		title = "LAPS Not Deployed (No Active Computer Uses LAPS)"
		description = "No enabled non-DC computer carries a LAPS password attribute: LAPS is not deployed on the active fleet, so local administrator passwords are unmanaged and likely shared across computers."
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    severity,
		Category:    string(d.Category()),
		Title:       title,
		Description: description,
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoLapsDetector())
}
