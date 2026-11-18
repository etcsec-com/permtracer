package membership

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// GpoModifyRightsOnDisabledAccountDetector checks for disabled members of
// Group Policy Creator Owners. Split out of GpoModifyRightsDetector: a
// disabled user cannot authenticate ([MS-KILE] "Check Account Policy for
// Every TGT Request" - KDC_ERR_CLIENT_REVOKED), so it cannot exercise the
// GPO creation/ownership privilege Group Policy Creator Owners membership
// grants while the account stays disabled. Membership is not removed by
// this state - it persists and returns to full effect the instant the
// account is re-enabled, which is the residual risk this detector keeps
// reporting.
//
// Severity Medium, not Low: Group Policy Creator Owners membership is a
// domain-level privilege (GPO creation/ownership, code execution on domain
// machines at policy application), per the split severity grid (D1) -
// dormant access to the highest tier of the domain is not a hygiene
// finding.
//
// Named GPO_MODIFY_RIGHTS_ON_DISABLED_ACCOUNT, not GPO_MODIFY_RIGHTS_DISABLED:
// the _DISABLED suffix is reserved elsewhere in this catalog for "a
// protection was turned off", which reads as bad news. Naming the
// population instead of a mechanism state avoids an auditor misreading
// this as the risk itself being off.
type GpoModifyRightsOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewGpoModifyRightsOnDisabledAccountDetector creates a new detector
func NewGpoModifyRightsOnDisabledAccountDetector() *GpoModifyRightsOnDisabledAccountDetector {
	return &GpoModifyRightsOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("GPO_MODIFY_RIGHTS_ON_DISABLED_ACCOUNT", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *GpoModifyRightsOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	gpoDNs := privgroups.DNsBySIDSuffix(data, gpoCreatorOwnersSIDSuffixes)

	for _, user := range data.Users {
		if !user.Disabled {
			continue
		}
		if privgroups.IsMemberOfAny(user.MemberOf, gpoDNs) || primaryGroupIsGpoCreatorOwners(data, user, gpoDNs) {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Group Policy Creator Owners Member (Disabled Account)",
		Description: "Disabled users in the Group Policy Creator Owners group. Not exploitable today - a disabled account cannot authenticate to abuse the group's ability to create/modify GPOs and execute code on domain machines - but membership persists and would re-apply its full, domain-level privilege the instant the account is re-enabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewGpoModifyRightsOnDisabledAccountDetector())
}
