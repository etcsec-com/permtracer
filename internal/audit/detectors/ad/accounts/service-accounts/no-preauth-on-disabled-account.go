package serviceaccounts

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// NoPreauthOnDisabledAccountDetector detects disabled service accounts
// without Kerberos pre-authentication. Split out of NoPreauthDetector: the
// KDC rejects the AS-REQ on account status before pre-authentication is
// ever considered, so a disabled account carrying this bit is not
// exploitable today. The bit persists on the object and would matter again
// the moment the account is re-enabled.
type NoPreauthOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewNoPreauthOnDisabledAccountDetector creates a new detector
func NewNoPreauthOnDisabledAccountDetector() *NoPreauthOnDisabledAccountDetector {
	return &NoPreauthOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("SERVICE_ACCOUNT_NO_PREAUTH_ON_DISABLED_ACCOUNT", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *NoPreauthOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if !isServiceAccount(u) {
			continue
		}
		if !u.Disabled {
			continue
		}
		if (u.UserAccountControl & types.UACDontRequirePreauth) != 0 {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Service Account Without Pre-Authentication (Disabled Account)",
		Description: "Disabled service accounts with 'Do not require Kerberos pre-authentication' enabled. Not exploitable while disabled - the KDC rejects the AS-REQ on account status first - but the bit remains set and would apply again if the account is re-enabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"recommendation": "Enable Kerberos pre-authentication for all service accounts.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoPreauthOnDisabledAccountDetector())
}
