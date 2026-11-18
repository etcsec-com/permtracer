package serviceaccounts

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// PrivilegedOnDisabledAccountDetector detects disabled service accounts
// that remain direct members of a privileged group. Split out of
// PrivilegedDetector: a disabled account cannot authenticate ([MS-KILE],
// "Check Account Policy for Every TGT Request", KDC_ERR_CLIENT_REVOKED), so
// the membership cannot be exercised today - but group membership is not
// removed by disabling the account, and returns to full effect the instant
// the account is re-enabled.
//
// Named SERVICE_ACCOUNT_PRIVILEGED_ON_DISABLED_ACCOUNT, not
// SERVICE_ACCOUNT_PRIVILEGED_DISABLED: the _DISABLED suffix is reserved
// elsewhere in this catalog for "a protection was turned off", which reads
// as bad news. Naming the population instead of a mechanism state avoids
// an auditor misreading this as the risk itself being off.
type PrivilegedOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewPrivilegedOnDisabledAccountDetector creates a new detector
func NewPrivilegedOnDisabledAccountDetector() *PrivilegedOnDisabledAccountDetector {
	return &PrivilegedOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("SERVICE_ACCOUNT_PRIVILEGED_ON_DISABLED_ACCOUNT", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *PrivilegedOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	groupSIDByDN := make(map[string]string, len(data.Groups))
	for _, g := range data.Groups {
		if g.DN != "" && g.ObjectSID != "" {
			groupSIDByDN[strings.ToLower(g.DN)] = g.ObjectSID
		}
	}

	var affected []types.User

	for _, u := range data.Users {
		// Must be a service account
		if !isServiceAccount(u) {
			continue
		}
		// Reported separately, at Critical, by PrivilegedDetector.
		if !u.Disabled {
			continue
		}
		// Check if in privileged groups
		if len(u.MemberOf) == 0 {
			continue
		}

		for _, dn := range u.MemberOf {
			sid, ok := groupSIDByDN[strings.ToLower(dn)]
			if !ok {
				continue
			}
			if audit.IsBuiltinAdminTrustee(sid) {
				affected = append(affected, u)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Service Account in Privileged Group (Disabled Account)",
		Description: "Disabled service accounts that are direct members of a privileged group (Domain Admins, etc.), resolved by well-known RID suffix so a renamed or localized group is still caught. Cannot authenticate while disabled, so the membership is not exploitable today - but it is not removed by disabling the account, and returns to full effect the instant the account is re-enabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"recommendation": "Remove the disabled service account from the privileged group, or delete the account if it is no longer needed.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPrivilegedOnDisabledAccountDetector())
}
