package privileged

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// ExpiredAdminGroupDetector detects expired accounts in admin groups
type ExpiredAdminGroupDetector struct {
	audit.BaseDetector
}

// NewExpiredAdminGroupDetector creates a new detector
func NewExpiredAdminGroupDetector() *ExpiredAdminGroupDetector {
	return &ExpiredAdminGroupDetector{
		BaseDetector: audit.NewBaseDetector("EXPIRED_ACCOUNT_IN_ADMIN_GROUP", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *ExpiredAdminGroupDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	// Resolve admin groups by RID suffix (-512 Domain Admins, -519 Enterprise
	// Admins, -518 Schema Admins), not by CN: a homonym group grants no real
	// privilege, and a renamed real group is still recognized.
	adminGroupDNs := privgroups.DNsBySIDSuffix(data, []string{"-512", "-519", "-518"})
	now := data.Now

	for _, u := range data.Users {
		if len(u.MemberOf) == 0 {
			continue
		}

		// Check if account is expired
		isExpired := !u.AccountExpires.IsZero() && u.AccountExpires.Before(now)

		if !isExpired {
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
		Title:       "Expired Account in Admin Group",
		Description: "Expired user accounts still present in privileged groups. Should be removed immediately.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewExpiredAdminGroupDetector())
}
