package password

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// VeryOldOnDisabledAccountDetector checks for disabled accounts with
// passwords older than 365 days. Split out of VeryOldDetector: a disabled
// account cannot obtain a ticket and cannot authenticate, so the stale
// password on it is not usable to log on today. PasswordLastSet is a
// persistent attribute of the object, though, that does not change when
// the account is disabled, so the signal becomes active again the instant
// the account is re-enabled.
//
// Named PASSWORD_VERY_OLD_ON_DISABLED_ACCOUNT, not
// PASSWORD_VERY_OLD_DISABLED: the _DISABLED suffix is reserved elsewhere in
// this catalog for "a protection was turned off", which reads as good
// news. Naming the population instead of a mechanism state avoids an
// auditor misreading this as the risk itself being off.
type VeryOldOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewVeryOldOnDisabledAccountDetector creates a new detector
func NewVeryOldOnDisabledAccountDetector() *VeryOldOnDisabledAccountDetector {
	return &VeryOldOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("PASSWORD_VERY_OLD_ON_DISABLED_ACCOUNT", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *VeryOldOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	now := data.Now
	oneYearAgo := now.AddDate(-1, 0, 0)

	var affected []types.User

	for _, u := range data.Users {
		if !u.Disabled {
			continue
		}

		// Skip if password last set is zero
		if u.PasswordLastSet.IsZero() {
			continue
		}

		// Check if password is older than 365 days
		if u.PasswordLastSet.Before(oneYearAgo) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Password Very Old (Disabled Account)",
		Description: "Disabled user accounts with passwords older than 365 days. A disabled account cannot obtain a ticket and cannot authenticate, but PasswordLastSet is a persistent attribute of the object that does not change when the account is disabled, and the signal becomes active again the instant the account is re-enabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewVeryOldOnDisabledAccountDetector())
}
