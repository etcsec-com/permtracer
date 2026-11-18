package advanced

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// DangerousBuiltinMembershipOnDisabledAccountDetector detects disabled
// accounts that remain direct members of one of the 15 overlooked-but-
// dangerous built-in groups. Split out of DangerousBuiltinMembershipDetector,
// following the same convention already used elsewhere in this package
// (AdminCountOrphaned, ReplicaDirectoryChanges): a disabled account cannot
// authenticate ([MS-KILE], "Check Account Policy for Every TGT Request",
// KDC_ERR_CLIENT_REVOKED), so the membership cannot be exercised today -
// but it is not removed by disabling the account, and returns to full
// effect the instant the account is re-enabled.
//
// Named DANGEROUS_BUILTIN_MEMBERSHIP_ON_DISABLED_ACCOUNT, not
// DANGEROUS_BUILTIN_MEMBERSHIP_DISABLED: the _DISABLED suffix is reserved
// elsewhere in this catalog for "a protection was turned off", which reads
// as bad news. Naming the population instead of a mechanism state avoids
// an auditor misreading this as the risk itself being off.
type DangerousBuiltinMembershipOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewDangerousBuiltinMembershipOnDisabledAccountDetector creates a new detector
func NewDangerousBuiltinMembershipOnDisabledAccountDetector() *DangerousBuiltinMembershipOnDisabledAccountDetector {
	return &DangerousBuiltinMembershipOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("DANGEROUS_BUILTIN_MEMBERSHIP_ON_DISABLED_ACCOUNT", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *DangerousBuiltinMembershipOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	dangerousDNs := privgroups.DNsBySIDSuffix(data, dangerousBuiltinGroupSuffixes())

	for _, u := range data.Users {
		if !u.Disabled || len(u.MemberOf) == 0 {
			continue
		}

		if privgroups.IsMemberOfAny(u.MemberOf, dangerousDNs) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Dangerous Built-in Group Membership (Disabled Account)",
		Description: "Disabled accounts with membership in overlooked but dangerous built-in groups. Cannot authenticate while disabled, so the membership is not exploitable today - but it is not removed by disabling the account, and returns to full effect the instant the account is re-enabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"dangerousGroups": dangerousBuiltinGroupNames(),
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDangerousBuiltinMembershipOnDisabledAccountDetector())
}
