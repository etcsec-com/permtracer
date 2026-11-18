package obsolete

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// ObsoleteOSNTOnDisabledAccountDetector checks for disabled computer
// accounts running Windows NT 4.0 or Windows 2000. Split out of
// ObsoleteOSNTDetector: a disabled computer account cannot authenticate
// against the domain, so the finding is a directory cleanup signal rather
// than an active exploitation risk - the machine itself may still be
// powered on and reachable on the network, so the signal is kept, at Low,
// rather than dropped.
//
// Named COMPUTER_OS_OBSOLETE_NT_ON_DISABLED_ACCOUNT, not
// COMPUTER_OS_OBSOLETE_NT_DISABLED: the _DISABLED suffix is reserved
// elsewhere in this catalog for "a protection was turned off", which reads
// as bad news. Naming the population instead of a mechanism state avoids an
// auditor misreading this as the risk itself being off.
type ObsoleteOSNTOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewObsoleteOSNTOnDisabledAccountDetector creates a new detector
func NewObsoleteOSNTOnDisabledAccountDetector() *ObsoleteOSNTOnDisabledAccountDetector {
	return &ObsoleteOSNTOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_OS_OBSOLETE_NT_ON_DISABLED_ACCOUNT", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *ObsoleteOSNTOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if !c.Disabled {
			continue
		}
		osLower := strings.ToLower(c.OperatingSystem)
		if osLower != "" && (strings.Contains(osLower, "windows nt") || strings.Contains(osLower, "windows 2000")) {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Obsolete OS: Windows NT/2000 (Disabled Account)",
		Description: "Disabled computer accounts running Windows NT 4.0 or Windows 2000, extremely outdated and unsupported operating systems. The account cannot authenticate, but the object remains an obsolete OS record to clean up or re-verify.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewObsoleteOSNTOnDisabledAccountDetector())
}
