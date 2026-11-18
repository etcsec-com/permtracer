package industry

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// ChangeManagementBypassOnDisabledAccountDetector checks for disabled service
// accounts that still carry a privileged ACL (SPN + AdminCount). Split out of
// ChangeManagementBypassDetector's serviceAdmins sub-condition, which counted
// these accounts without any account-state guard: this is the gabarit used by
// AsrepRoastingRiskDetector / AsrepRoastingOnDisabledAccountDetector
// (public/internal/audit/detectors/ad/kerberos/asrep-roasting-risk.go) -
// the active detector now excludes disabled accounts from serviceAdmins, and
// this twin reports exactly that excluded population instead of silently
// dropping it.
//
// Unlike the active sub-condition, this twin does not reuse the ">5" product
// heuristic threshold: it reports each matching account individually
// (Count = number of accounts, AffectedEntities when IncludeDetails is set),
// the same convention AsrepRoastingOnDisabledAccountDetector uses for its own
// dormant population. See SPLIT.md
// (docs/security-validation/split/change-management-bypass/SPLIT.md) for why
// a second arbitrary threshold was not introduced for this smaller, dormant
// population.
//
// Named CHANGE_MANAGEMENT_BYPASS_ON_DISABLED_ACCOUNT, not
// CHANGE_MANAGEMENT_BYPASS_DISABLED: the _DISABLED suffix is reserved
// elsewhere in this catalog for "a protection was turned off", which would
// misread as good news here.
type ChangeManagementBypassOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewChangeManagementBypassOnDisabledAccountDetector creates a new detector
func NewChangeManagementBypassOnDisabledAccountDetector() *ChangeManagementBypassOnDisabledAccountDetector {
	return &ChangeManagementBypassOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("CHANGE_MANAGEMENT_BYPASS_ON_DISABLED_ACCOUNT", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *ChangeManagementBypassOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if u.Enabled() {
			continue
		}
		if len(u.ServicePrincipalNames) > 0 && u.AdminCount {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Change Management Compliance Review (Disabled Account)",
		Description: "Disabled service accounts with a Service Principal Name and AdminCount set (AdminSDHolder-protected ACL). Not actively bypassing change management while disabled, but the privileged ACL persists on disk and would apply again if the account is re-enabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewChangeManagementBypassOnDisabledAccountDetector())
}
