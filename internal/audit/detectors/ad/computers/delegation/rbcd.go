package delegation

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// RbcdDetector checks for computers with RBCD configured
type RbcdDetector struct {
	audit.BaseDetector
}

// NewRbcdDetector creates a new detector
func NewRbcdDetector() *RbcdDetector {
	return &RbcdDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_RBCD", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *RbcdDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		// Exploiting resource-based constrained delegation requires the KDC
		// to issue a Kerberos service ticket (S4U2Proxy) for an SPN
		// belonging to this computer, the target resource that carries the
		// attribute, and the KDC refuses to issue a service ticket for a
		// disabled account's SPN. Reported separately by
		// RbcdOnDisabledAccountDetector in this same package.
		if c.Disabled {
			continue
		}
		// Check that msDS-AllowedToActOnBehalfOfOtherIdentity attribute exists and is not empty
		if len(c.AllowedToActOnBehalfOfOtherIdentity) > 0 {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Computer RBCD",
		Description: "Computer with Resource-Based Constrained Delegation. Enables privilege escalation via RBCD attack.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewRbcdDetector())
}
