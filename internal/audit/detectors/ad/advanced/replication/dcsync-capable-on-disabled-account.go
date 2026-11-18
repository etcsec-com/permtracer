package replication

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// DcsyncCapableOnDisabledAccountDetector checks the same candidate
// population as DcsyncCapableDetector - non-admin trustees holding BOTH
// DS-Replication-Get-Changes and DS-Replication-Get-Changes-All on the
// domain root (dcsyncCapableTrustees, shared by both detectors) - restricted
// to a trustee that resolveTrusteeDisabledState resolves to a DISABLED user
// or computer account.
//
// Split out of DcsyncCapableDetector because it had no active/disabled
// guard at all and no join to data.Users or data.Computers (see
// docs/security-validation/split/dcsync-capable/SPLIT.md): a disabled
// account cannot obtain a ticket-granting ticket of its own ([MS-KILE],
// "Check Account Policy for Every TGT Request", KDC_ERR_CLIENT_REVOKED), so
// it cannot authenticate and cannot currently mount the DRSUAPI session
// DCSync requires - the residual ACE grant is dormant, not resolved, and
// returns to full relevance the instant the account is re-enabled.
//
// Reported at Medium rather than Low: replication rights are a domain-level
// privilege that the disabled account retains, the same reasoning as
// COMPUTER_DCSYNC_RIGHTS_ON_DISABLED_ACCOUNT
// (computers/delegation/dcsync-rights-on-disabled-account.go) and
// REPLICA_DIRECTORY_CHANGES_ON_DISABLED_ACCOUNT
// (accounts/advanced/replica-directory-changes-on-disabled-account.go).
//
// A trustee that resolves to a group, or a SID that resolves to neither a
// user nor a computer, is never routed here - resolveTrusteeDisabledState
// returns resolved=false for it and it stays counted by
// DcsyncCapableDetector, so it is never silently dropped from both halves
// of the split.
//
// Named DCSYNC_CAPABLE_ON_DISABLED_ACCOUNT, not DCSYNC_CAPABLE_DISABLED: the
// _DISABLED suffix is reserved elsewhere in this catalog for "a protection
// was turned off", which reads as bad news. Naming the population instead
// of a mechanism state avoids an auditor misreading this as the risk itself
// being off.
type DcsyncCapableOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewDcsyncCapableOnDisabledAccountDetector creates a new detector
func NewDcsyncCapableOnDisabledAccountDetector() *DcsyncCapableOnDisabledAccountDetector {
	return &DcsyncCapableOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("DCSYNC_CAPABLE_ON_DISABLED_ACCOUNT", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *DcsyncCapableOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var disabledTrustees []string
	for _, trustee := range dcsyncCapableTrustees(data) {
		if resolved, isDisabled := resolveTrusteeDisabledState(trustee, data); resolved && isDisabled {
			disabledTrustees = append(disabledTrustees, trustee)
		}
	}

	var affectedEntities []types.AffectedEntity
	if data.IncludeDetails {
		for _, trustee := range disabledTrustees {
			ent := audit.SIDToEntityWithCache(trustee, data)
			ent.Description = "Has DS-Replication-Get-Changes and DS-Replication-Get-Changes-All (disabled account)"
			affectedEntities = append(affectedEntities, ent)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "DCSync Capable (Disabled Account)",
		Description: "Disabled user or computer accounts hold both the DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights on the domain root. A disabled account cannot obtain a ticket-granting ticket of its own and so cannot currently mount the DRSUAPI session DCSync requires, but the ACE grant itself is not removed by disabling the account: it persists on the domain root and returns to full DCSync capability the instant the account is re-enabled.",
		Count:       len(disabledTrustees),
	}

	if data.IncludeDetails && len(affectedEntities) > 0 {
		finding.AffectedEntities = affectedEntities
		finding.Details = map[string]interface{}{
			"recommendation": "Remove the DCSync replication rights from the disabled account, or delete the account if it is no longer needed.",
			"impact":         "The account returns to full DCSync capability if re-enabled, with no further action required from an attacker who controls it.",
			"replicationRights": []string{
				"DS-Replication-Get-Changes (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)",
				"DS-Replication-Get-Changes-All (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)",
			},
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDcsyncCapableOnDisabledAccountDetector())
}
