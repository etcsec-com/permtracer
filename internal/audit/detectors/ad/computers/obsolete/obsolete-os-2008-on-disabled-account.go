package obsolete

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// ObsoleteOS2008OnDisabledAccountDetector checks for disabled computer
// accounts running Windows Server 2008 (not R2). Split out of
// ObsoleteOS2008Detector: a disabled computer account cannot authenticate
// against the domain, so the finding is a directory cleanup signal rather
// than an active exploitation risk - the machine itself may still be
// powered on and reachable on the network, so the signal is kept, at Low,
// rather than dropped.
//
// Named COMPUTER_OS_OBSOLETE_2008_ON_DISABLED_ACCOUNT, not
// COMPUTER_OS_OBSOLETE_2008_DISABLED: the _DISABLED suffix is reserved
// elsewhere in this catalog for "a protection was turned off", which reads
// as bad news. Naming the population instead of a mechanism state avoids an
// auditor misreading this as the risk itself being off.
type ObsoleteOS2008OnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewObsoleteOS2008OnDisabledAccountDetector creates a new detector
func NewObsoleteOS2008OnDisabledAccountDetector() *ObsoleteOS2008OnDisabledAccountDetector {
	return &ObsoleteOS2008OnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_OS_OBSOLETE_2008_ON_DISABLED_ACCOUNT", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *ObsoleteOS2008OnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if !c.Disabled {
			continue
		}
		osLower := strings.ToLower(c.OperatingSystem)
		// Check for Server 2008 but exclude R2
		if osLower != "" && strings.Contains(osLower, "server 2008") && !strings.Contains(osLower, "r2") {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Obsolete OS: Windows Server 2008 (Disabled Account)",
		Description: "Disabled computer accounts running Windows Server 2008, an unsupported operating system. The account cannot authenticate, but the object remains an obsolete OS record to clean up or re-verify.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewObsoleteOS2008OnDisabledAccountDetector())
}
