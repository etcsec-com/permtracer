package security

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// WithSPNsOnDisabledAccountDetector checks for disabled computer accounts
// with Service Principal Names registered. Split out of WithSPNsDetector,
// on the same model as the service-account pair on the same condition
// (service-accounts.WithSpnDetector / WithSpnOnDisabledAccountDetector):
// servicePrincipalName and userAccountControl are independent LDAP
// attributes, so disabling a computer account never removes its SPNs - the
// KDC simply refuses to issue a service ticket for them while disabled.
type WithSPNsOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewWithSPNsOnDisabledAccountDetector creates a new detector
func NewWithSPNsOnDisabledAccountDetector() *WithSPNsOnDisabledAccountDetector {
	return &WithSPNsOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_WITH_SPNS_ON_DISABLED_ACCOUNT", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *WithSPNsOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if !c.Disabled {
			continue
		}
		if len(c.ServicePrincipalNames) > 0 {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Computer with Service Principal Names (Disabled Account)",
		Description: "Disabled computer account has Service Principal Names registered. Computer account passwords are long, random, and automatically rotated, making offline Kerberoasting impractical regardless of account state; the KDC also refuses to issue a service ticket for a disabled account's SPNs. This is a dormant inventory signal, not a confirmed attack path. Remediation: review and remove stale SPNs when the account is retired.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWithSPNsOnDisabledAccountDetector())
}
