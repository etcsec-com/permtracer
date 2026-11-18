package privileged

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// DisabledAdminGroupDetector detects disabled accounts in admin groups
type DisabledAdminGroupDetector struct {
	audit.BaseDetector
}

// NewDisabledAdminGroupDetector creates a new detector
func NewDisabledAdminGroupDetector() *DisabledAdminGroupDetector {
	return &DisabledAdminGroupDetector{
		BaseDetector: audit.NewBaseDetector("DISABLED_ACCOUNT_IN_ADMIN_GROUP", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *DisabledAdminGroupDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	// Resolve admin groups by RID suffix (-512 Domain Admins, -519 Enterprise
	// Admins, -518 Schema Admins), not by CN: a homonym group grants no real
	// privilege, and a renamed real group is still recognized.
	adminGroupDNs := privgroups.DNsBySIDSuffix(data, []string{"-512", "-519", "-518"})

	for _, u := range data.Users {
		if len(u.MemberOf) == 0 {
			continue
		}

		// Check if disabled (UAC flag 0x2 or Disabled field)
		isDisabled := u.Disabled || (u.UserAccountControl&0x2) != 0

		if !isDisabled {
			continue
		}

		if privgroups.IsMemberOfAny(u.MemberOf, adminGroupDNs) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Disabled Account in Admin Group",
		Description: "Disabled user accounts still present in privileged groups. Should be removed immediately.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDisabledAdminGroupDetector())
}
