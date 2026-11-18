package patterns

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// SharedAccountOnDisabledAccountDetector detects disabled accounts whose
// SAMAccountName matches a shared/generic naming pattern. Split out of
// SharedAccountDetector: a disabled account cannot authenticate, so the
// naming match carries no immediate exploitation risk while the account
// stays disabled. The match is a property of the name, not of the account
// state, and would apply again at full severity the moment the account is
// re-enabled.
//
// Named SHARED_ACCOUNT_ON_DISABLED_ACCOUNT, not SHARED_ACCOUNT_DISABLED: the
// _DISABLED suffix is reserved elsewhere in this catalog for "a protection
// was turned off", which reads as bad news. Naming the population instead
// of a mechanism state avoids an auditor misreading this as the risk itself
// being off.
type SharedAccountOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewSharedAccountOnDisabledAccountDetector creates a new detector
func NewSharedAccountOnDisabledAccountDetector() *SharedAccountOnDisabledAccountDetector {
	return &SharedAccountOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("SHARED_ACCOUNT_ON_DISABLED_ACCOUNT", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *SharedAccountOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if !u.Disabled {
			continue
		}
		for _, pattern := range sharedPatterns {
			if pattern.MatchString(u.SAMAccountName) {
				affected = append(affected, u)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Shared Account (Disabled Account)",
		Description: "Disabled user accounts with shared/generic naming. Not usable while disabled, but the naming match persists on the object and would apply again if the account is re-enabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSharedAccountOnDisabledAccountDetector())
}
