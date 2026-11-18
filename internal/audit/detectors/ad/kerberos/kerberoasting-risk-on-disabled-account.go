package kerberos

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// KerberoastingRiskOnDisabledAccountDetector checks for disabled user
// accounts that still carry a Service Principal Name. Split out of
// KerberoastingRiskDetector: measured directly against a real KDC (Windows
// Server 2022), a TGS request for a disabled account's own SPN is refused
// (confirmed by toggling the same account's enabled bit twice - refused
// while disabled, granted once enabled, refused again once re-disabled), so
// this population is not exploitable today. The configuration itself is not
// removed by disabling the account - userAccountControl and
// servicePrincipalName are independent LDAP attributes, so the SPN survives
// the disable - and the account becomes Kerberoastable again the instant it
// is re-enabled. That dormant population is not dropped: it stays reported
// here, partitioned by Tier 0 membership exactly like the active detector
// (helpers.Tier0Members, same recursive/SID-based resolution plus
// tier0_groups.yaml customer overrides), at a severity that reflects
// dormancy rather than active risk - Medium for Tier 0 members (a
// domain-level privilege is retained, D1/D2 severity grid), Low for
// ordinary service accounts. See docs/security-validation/results/
// kerberoasting-risk-fix/VERDICT.md for the raw KDC measurement.
//
// Named KERBEROASTING_RISK_ON_DISABLED_ACCOUNT, not
// KERBEROASTING_RISK_DISABLED: the _DISABLED suffix is reserved elsewhere in
// this catalog for "a protection was turned off". Naming the population
// instead of a mechanism state avoids an auditor misreading this as the
// risk itself being off. Same convention as
// ADMIN_ASREP_ROASTABLE_ON_DISABLED_ACCOUNT and
// ASREP_ROASTING_ON_DISABLED_ACCOUNT (same package).
type KerberoastingRiskOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewKerberoastingRiskOnDisabledAccountDetector creates a new detector
func NewKerberoastingRiskOnDisabledAccountDetector() *KerberoastingRiskOnDisabledAccountDetector {
	return &KerberoastingRiskOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("KERBEROASTING_RISK_ON_DISABLED_ACCOUNT", audit.CategoryKerberos),
	}
}

// Detect partitions Kerberoastable disabled users by Tier 0 membership and
// emits one finding per non-empty partition - the mirror of
// KerberoastingRiskDetector.Detect on the disabled half of the population.
func (d *KerberoastingRiskOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	tier0 := helpers.Tier0Members(data, customTier0Groups(data))

	var tier0Affected, otherAffected []types.User
	for _, user := range data.Users {
		if !user.Disabled || len(user.ServicePrincipalNames) == 0 {
			continue
		}
		if tier0[strings.ToLower(user.DN)] {
			tier0Affected = append(tier0Affected, user)
		} else {
			otherAffected = append(otherAffected, user)
		}
	}

	var out []types.Finding
	if len(tier0Affected) > 0 {
		f := types.Finding{
			Type:     d.ID(),
			Severity: types.SeverityMedium,
			Category: string(d.Category()),
			Title:    "Kerberoasting Risk - Tier 0 admin exposes a SPN (Disabled Account)",
			Description: fmt.Sprintf(
				"%d disabled Tier 0 admin account(s) still carry a SPN. Not exploitable while disabled - the KDC refuses to issue a TGS for a disabled account's own SPN - but the SPN is not removed by disabling the account, and the account becomes Kerberoastable again the instant it is re-enabled. Tier 0 is recognized by well-known SID (fixed RID, e.g. Domain Admins, Enterprise Admins), by name for DnsAdmins (no fixed RID exists), plus recursive group nesting and tier0_groups.yaml customer config. Remove the SPN, or move it to a dedicated service identity outside Tier 0, before re-enabling the account.",
				len(tier0Affected)),
			Count: len(tier0Affected),
		}
		if data.IncludeDetails {
			f.AffectedEntities = helpers.ToAffectedUserEntities(tier0Affected)
		}
		out = append(out, f)
	}
	if len(otherAffected) > 0 {
		f := types.Finding{
			Type:     d.ID(),
			Severity: types.SeverityLow,
			Category: string(d.Category()),
			Title:    "Kerberoasting Risk - service accounts with SPN (Disabled Account)",
			Description: fmt.Sprintf(
				"%d disabled non-Tier-0 user account(s) still carry a SPN. Not exploitable while disabled - the KDC refuses to issue a TGS for a disabled account's own SPN - but the SPN remains set and the account becomes Kerberoastable again the instant it is re-enabled. Remove the SPN, or use a Group Managed Service Account (gMSA) if the identity is reactivated.",
				len(otherAffected)),
			Count: len(otherAffected),
		}
		if data.IncludeDetails {
			f.AffectedEntities = helpers.ToAffectedUserEntities(otherAffected)
		}
		out = append(out, f)
	}
	return out
}

func init() {
	audit.MustRegister(NewKerberoastingRiskOnDisabledAccountDetector())
}
