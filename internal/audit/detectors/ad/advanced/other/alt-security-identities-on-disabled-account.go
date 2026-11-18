package other

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// AltSecurityIdentitiesOnDisabledAccountDetector checks for disabled
// privileged accounts with altSecurityIdentities configured. Split out of
// AltSecurityIdentitiesDetector: altSecurityIdentities maps an external
// certificate or Kerberos principal to this account for the purpose of
// PKINIT/Schannel authentication (KB5014754, "Certificate mappings"), and
// UF_ACCOUNTDISABLE blocks that authentication the same way it blocks every
// other protocol, so a disabled account cannot be impersonated via this
// mapping today. The exposure itself does not go away - the mapping stays
// readable on the object - so it stays reported, at a severity that
// reflects dormancy rather than active risk, for when the account is
// re-enabled.
//
// Named ALT_SECURITY_IDENTITIES_ON_DISABLED_ACCOUNT, not
// ALT_SECURITY_IDENTITIES_DISABLED: the _DISABLED suffix is reserved
// elsewhere in this catalog for "a protection was turned off"
// (LDAP_SIGNING_DISABLED, TRUST_AES_DISABLED, ...), which reads as bad news.
// Naming the population instead of a mechanism state avoids an auditor
// misreading this as the risk itself being off.
type AltSecurityIdentitiesOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewAltSecurityIdentitiesOnDisabledAccountDetector creates a new detector
func NewAltSecurityIdentitiesOnDisabledAccountDetector() *AltSecurityIdentitiesOnDisabledAccountDetector {
	return &AltSecurityIdentitiesOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("ALT_SECURITY_IDENTITIES_ON_DISABLED_ACCOUNT", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *AltSecurityIdentitiesOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	adminDNs := privgroups.DNsBySIDSuffix(data, altSecAdminGroupSIDSuffixes)

	for _, user := range data.Users {
		if !user.Disabled {
			continue
		}
		if len(user.AltSecurityIdentities) == 0 {
			continue
		}

		if privgroups.IsMemberOfAny(user.MemberOf, adminDNs) {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Privileged Accounts with altSecurityIdentities Configured (Disabled Account)",
		Description: "Disabled privileged accounts have the altSecurityIdentities attribute configured, mapping an external certificate or Kerberos principal to the account for PKINIT/Schannel authentication. Not usable to authenticate today - UF_ACCOUNTDISABLE blocks it across every protocol - but the account retains its privileged group membership (a domain-level privilege) and the mapping stays readable on the object, so it would again allow certificate-based impersonation of this privileged account the instant it is re-enabled. A dormant domain-level privilege, not an absent one.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAltSecurityIdentitiesOnDisabledAccountDetector())
}
