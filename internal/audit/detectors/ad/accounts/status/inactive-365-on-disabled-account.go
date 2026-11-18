package status

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// Inactive365OnDisabledAccountDetector checks for disabled accounts whose
// lastLogonTimestamp is 365+ days old. Split out of Inactive365Detector: the
// recommended action for that detector ("should be disabled or deleted") is
// already in effect for a disabled account, so mixing the two populations
// into one count would dilute the still-actionable signal (enabled accounts
// nobody has used in a year) with one that has already been addressed. This
// detector's criteria - inactivity duration alone - does not by itself imply
// membership in a privileged group, a delegation right, SIDHistory, shadow
// credentials, or an exposed secret, so it is reported at a lower severity
// than its active counterpart.
//
// Named INACTIVE_365_DAYS_ON_DISABLED_ACCOUNT, not INACTIVE_365_DAYS_DISABLED:
// the _DISABLED suffix is reserved elsewhere in this catalog for "a
// protection was turned off", which reads as bad news. Naming the population
// instead of a mechanism state avoids an auditor misreading this as the risk
// itself being off.
type Inactive365OnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewInactive365OnDisabledAccountDetector creates a new detector
func NewInactive365OnDisabledAccountDetector() *Inactive365OnDisabledAccountDetector {
	return &Inactive365OnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("INACTIVE_365_DAYS_ON_DISABLED_ACCOUNT", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *Inactive365OnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	now := data.Now
	cutoff := now.AddDate(-1, 0, 0).Add(-inactive365ReplicationTolerance)

	for _, u := range data.Users {
		// Must be disabled - mirror guard of Inactive365Detector
		if !u.Disabled {
			continue
		}
		// lastLogonTimestamp (replicated) instead of lastLogon (per-DC, never
		// replicated) - see inactive365ReplicationTolerance above.
		if u.LastLogonTimestamp.IsZero() {
			continue
		}
		if u.LastLogonTimestamp.Before(cutoff) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Inactive 365+ Days (Disabled Account)",
		Description: "Disabled user accounts inactive for 365+ days. Already disabled, so the recommended action has already been taken; kept as a separate low-severity signal for cleanup (deletion) rather than mixed with still-enabled inactive accounts.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewInactive365OnDisabledAccountDetector())
}
