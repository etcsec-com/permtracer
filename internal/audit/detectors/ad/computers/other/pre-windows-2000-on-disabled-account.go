package other

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// PreWindows2000OnDisabledAccountDetector checks for disabled computer
// accounts running Windows 95/98. Split out of PreWindows2000Detector: a
// disabled computer account cannot authenticate against the domain, so the
// finding is a directory cleanup signal rather than an active exploitation
// risk - the machine itself may still be powered on and reachable on the
// network, so the signal is kept, at Low, rather than dropped.
//
// Named COMPUTER_PRE_WINDOWS_2000_ON_DISABLED_ACCOUNT, not
// COMPUTER_PRE_WINDOWS_2000_DISABLED: the _DISABLED suffix is reserved
// elsewhere in this catalog for "a protection was turned off", which reads
// as bad news. Naming the population instead of a mechanism state avoids an
// auditor misreading this as the risk itself being off.
type PreWindows2000OnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewPreWindows2000OnDisabledAccountDetector creates a new detector
func NewPreWindows2000OnDisabledAccountDetector() *PreWindows2000OnDisabledAccountDetector {
	return &PreWindows2000OnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_PRE_WINDOWS_2000_ON_DISABLED_ACCOUNT", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *PreWindows2000OnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if !c.Disabled {
			continue
		}
		if c.OperatingSystem == "" {
			continue
		}
		if preWin2000Pattern.MatchString(c.OperatingSystem) {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Windows 95/98 Computer (Disabled Account)",
		Description: "Disabled Windows 95/98 compatible computer account. The account cannot authenticate, but the object remains an obsolete OS record to clean up or re-verify. Windows NT/2000 is reported separately by COMPUTER_OS_OBSOLETE_NT_ON_DISABLED_ACCOUNT.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPreWindows2000OnDisabledAccountDetector())
}
