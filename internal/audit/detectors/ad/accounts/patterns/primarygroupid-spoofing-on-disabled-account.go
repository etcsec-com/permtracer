package patterns

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// PrimaryGroupIdSpoofingOnDisabledAccountDetector detects disabled accounts
// with a non-standard primaryGroupID. Split out of
// PrimaryGroupIdSpoofingDetector: the primaryGroupID a user points to is a
// static attribute of group membership, not an event - it stays on the
// object independent of account state, and a Kerberos ticket embedding
// that primary group can only be built at authentication, which a disabled
// account cannot perform ([MS-KILE],
// "Check Account Policy for Every TGT Request", KDC_ERR_CLIENT_REVOKED).
// The signal is therefore a dormant-persistence indicator while the
// account stays disabled, not an absent one: it returns to full relevance
// the instant the account is re-enabled.
//
// Named PRIMARYGROUPID_SPOOFING_ON_DISABLED_ACCOUNT, not
// PRIMARYGROUPID_SPOOFING_DISABLED: the _DISABLED suffix is reserved
// elsewhere in this catalog for "a protection was turned off", which reads
// as bad news. Naming the population instead of a mechanism state avoids
// an auditor misreading this as the risk itself being off.
type PrimaryGroupIdSpoofingOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewPrimaryGroupIdSpoofingOnDisabledAccountDetector creates a new detector
func NewPrimaryGroupIdSpoofingOnDisabledAccountDetector() *PrimaryGroupIdSpoofingOnDisabledAccountDetector {
	return &PrimaryGroupIdSpoofingOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("PRIMARYGROUPID_SPOOFING_ON_DISABLED_ACCOUNT", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *PrimaryGroupIdSpoofingOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	// Standard primaryGroupID for Domain Users is 513
	const standardPrimaryGroupID = 513

	for _, u := range data.Users {
		if !u.Disabled {
			continue
		}
		if u.PrimaryGroupID == 0 || u.PrimaryGroupID == standardPrimaryGroupID {
			continue
		}
		if isKnownLegitimateNonStandardPrimaryGroup(u) {
			continue
		}
		affected = append(affected, u)
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "primaryGroupID Spoofing (Disabled Account)",
		Description: "Disabled user accounts with a non-standard primaryGroupID, excluding Windows' own factory-default exceptions (e.g. the built-in Guest account, gMSAs). Not exploitable while disabled - a Kerberos ticket embedding the primary group can only be built at authentication, which the KDC refuses for a disabled account - but the attribute persists on the object and would apply again if the account is re-enabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPrimaryGroupIdSpoofingOnDisabledAccountDetector())
}
