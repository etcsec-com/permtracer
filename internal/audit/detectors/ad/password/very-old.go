package password

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// VeryOldDetector detects active accounts with passwords older than 365
// days. Scoped to active accounts: a disabled account cannot authenticate,
// so the stale password on it is not usable today - see
// VeryOldOnDisabledAccountDetector (very-old-on-disabled-account.go) for
// the disabled-account claim, reported separately at Low because
// PasswordLastSet is a persistent attribute of the object that becomes
// relevant again the instant the account is re-enabled.
type VeryOldDetector struct {
	audit.BaseDetector
}

// NewVeryOldDetector creates a new detector
func NewVeryOldDetector() *VeryOldDetector {
	return &VeryOldDetector{
		BaseDetector: audit.NewBaseDetector("PASSWORD_VERY_OLD", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *VeryOldDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	now := data.Now
	oneYearAgo := now.AddDate(-1, 0, 0)

	var affected []types.User

	for _, u := range data.Users {
		if u.Disabled {
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
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Password Very Old",
		Description: "Active user accounts with passwords older than 365 days. Increases risk of credential compromise.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewVeryOldDetector())
}
