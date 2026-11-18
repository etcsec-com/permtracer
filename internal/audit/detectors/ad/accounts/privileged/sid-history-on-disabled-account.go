package privileged

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// SidHistoryOnDisabledAccountDetector detects disabled accounts carrying a
// non-empty sIDHistory. Split out of SidHistoryDetector: a sIDHistory value
// is a static attribute, not an event - it stays on the object independent
// of account state, and only produces an access token at authentication,
// which a disabled account cannot perform ([MS-KILE],
// "Check Account Policy for Every TGT Request", KDC_ERR_CLIENT_REVOKED).
// The signal is therefore a dormant-persistence indicator while the
// account stays disabled, not an absent one: it returns to full relevance
// the instant the account is re-enabled.
//
// Named SID_HISTORY_ON_DISABLED_ACCOUNT, not SID_HISTORY_DISABLED: the
// _DISABLED suffix is reserved elsewhere in this catalog for "a protection
// was turned off", which reads as bad news. Naming the population instead
// of a mechanism state avoids an auditor misreading this as the risk
// itself being off.
type SidHistoryOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewSidHistoryOnDisabledAccountDetector creates a new detector
func NewSidHistoryOnDisabledAccountDetector() *SidHistoryOnDisabledAccountDetector {
	return &SidHistoryOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("SID_HISTORY_ON_DISABLED_ACCOUNT", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *SidHistoryOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if !u.Disabled {
			continue
		}
		if len(u.SIDHistory) > 0 {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "SID History Present (Disabled Account)",
		Description: "Disabled user accounts with sIDHistory attribute. Not exploitable while disabled - the KDC rejects any new authentication attempt on account status first - but the attribute persists on the object and would apply again if the account is re-enabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSidHistoryOnDisabledAccountDetector())
}
