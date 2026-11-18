package serviceaccounts

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// WithSpnOnDisabledAccountDetector detects disabled accounts carrying a
// Service Principal Name. Split out of WithSpnDetector:
// servicePrincipalName and userAccountControl are independent LDAP
// attributes, so disabling an account never removes its SPN. The SPN
// persists on the object and makes the account a Kerberoasting target
// again the instant it is re-enabled.
type WithSpnOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewWithSpnOnDisabledAccountDetector creates a new detector
func NewWithSpnOnDisabledAccountDetector() *WithSpnOnDisabledAccountDetector {
	return &WithSpnOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("SERVICE_ACCOUNT_WITH_SPN_ON_DISABLED_ACCOUNT", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *WithSpnOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User
	spnCount := 0

	for _, u := range data.Users {
		// Must have SPN
		if len(u.ServicePrincipalNames) == 0 {
			continue
		}
		// Must be disabled
		if !u.Disabled {
			continue
		}

		affected = append(affected, u)
		spnCount += len(u.ServicePrincipalNames)
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Service Account with SPN (Disabled Account)",
		Description: "Disabled user accounts with Service Principal Name configured. Not exploitable while disabled, but the SPN persists on the object and would make the account a Kerberoasting target again if it is re-enabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"recommendation": "Remove unused SPNs or delete the account if it is no longer needed.",
			"spnCount":       spnCount,
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWithSpnOnDisabledAccountDetector())
}
