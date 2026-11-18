package obsolete

import (
	"context"
	"regexp"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// ObsoleteOSVistaOnDisabledAccountDetector checks for disabled computer
// accounts running Windows Vista. Split out of ObsoleteOSVistaDetector: a
// disabled computer account cannot authenticate against the domain, so the
// finding is a directory cleanup signal rather than an active exploitation
// risk - the machine itself may still be powered on and reachable on the
// network, so the signal is kept, at Low, rather than dropped.
//
// Named COMPUTER_OS_OBSOLETE_VISTA_ON_DISABLED_ACCOUNT, not
// COMPUTER_OS_OBSOLETE_VISTA_DISABLED: the _DISABLED suffix is reserved
// elsewhere in this catalog for "a protection was turned off", which reads
// as bad news. Naming the population instead of a mechanism state avoids an
// auditor misreading this as the risk itself being off.
type ObsoleteOSVistaOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewObsoleteOSVistaOnDisabledAccountDetector creates a new detector
func NewObsoleteOSVistaOnDisabledAccountDetector() *ObsoleteOSVistaOnDisabledAccountDetector {
	return &ObsoleteOSVistaOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_OS_OBSOLETE_VISTA_ON_DISABLED_ACCOUNT", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *ObsoleteOSVistaOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	pattern := regexp.MustCompile(`(?i)Windows Vista`)
	var affected []types.Computer

	for _, c := range data.Computers {
		if !c.Disabled {
			continue
		}
		os := strings.ToLower(c.OperatingSystem)
		if os != "" && pattern.MatchString(c.OperatingSystem) {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Obsolete OS: Windows Vista (Disabled Account)",
		Description: "Disabled computer accounts running Windows Vista, an unsupported operating system. The account cannot authenticate, but the object remains an obsolete OS record to clean up or re-verify.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewObsoleteOSVistaOnDisabledAccountDetector())
}
