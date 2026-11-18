package password

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// CannotChangeOnDisabledAccountDetector checks for disabled accounts carrying
// the User-Change-Password Deny ACE (Everyone or NT AUTHORITY\SELF). Split
// out of CannotChangeDetector: the Deny ACE is a restriction on the object's
// own DACL, not a grant - it does not become any more usable while the
// account is disabled, but it also does not disappear, so it stays reported
// at a severity that reflects dormancy rather than active risk. Same
// convention as PASSWORD_NEVER_EXPIRES_ON_DISABLED_ACCOUNT and
// UNCONSTRAINED_DELEGATION_ON_DISABLED_ACCOUNT: the suffix names the
// population covered, not the state of a mechanism - _DISABLED alone is
// reserved elsewhere in this catalog for "a protection was turned off".
type CannotChangeOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewCannotChangeOnDisabledAccountDetector creates a new detector
func NewCannotChangeOnDisabledAccountDetector() *CannotChangeOnDisabledAccountDetector {
	return &CannotChangeOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("USER_CANNOT_CHANGE_PASSWORD_ON_DISABLED_ACCOUNT", audit.CategoryPassword),
	}
}

// Detect executes the detection. The firing condition (the Deny ACE itself)
// and the DN-to-user join both come from usersBlockedFromChangingPassword in
// cannot-change.go, shared with CannotChangeDetector rather than
// reimplemented here; only the disabled argument differs.
func (d *CannotChangeOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	affected := usersBlockedFromChangingPassword(data, true)

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityLow,
		Category: string(d.Category()),
		Title:    "User Cannot Change Password (Disabled Account)",
		Description: "Disabled user accounts denied the User-Change-Password extended right for Everyone or " +
			"NT AUTHORITY\\SELF. The Deny ACE is carried by the object itself and survives disabling the " +
			"account; the restriction becomes relevant to self-service password rotation again as soon as " +
			"the account is re-enabled.",
		Count: len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewCannotChangeOnDisabledAccountDetector())
}
