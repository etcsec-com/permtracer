package privileged

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// DomainAdminInDescriptionOnDisabledAccountDetector checks for disabled
// accounts carrying admin/privileged keywords in their description field.
// Split out of DomainAdminDescriptionDetector: UF_ACCOUNTDISABLE blocks
// authentication for this account across every protocol (interactive logon,
// LDAP bind, NTLM, Kerberos), so a keyword revealing this account's
// privileged status cannot be leveraged to compromise an active session
// today.
//
// Unlike a UAC bit or a group membership, though, this exposure is not
// merely dormant until re-enable: the description text is readable RIGHT
// NOW by anyone with ordinary directory-read access, independent of the
// account's disabled state. That gives an attacker who already holds a
// foothold (or an insider with routine read access) reconnaissance value
// today - identifying which specific, otherwise-inert object was privileged
// lets them target password-spray, social-engineering, or physical-security
// effort at it, or pre-stage an attack for the moment it is re-enabled. The
// disabled state only closes the live-session half of the risk; the
// information disclosure half stays fully current, which is why this twin
// is reported at Medium rather than Low.
//
// Named DOMAIN_ADMIN_IN_DESCRIPTION_ON_DISABLED_ACCOUNT, not
// DOMAIN_ADMIN_IN_DESCRIPTION_DISABLED: the _DISABLED suffix is reserved
// elsewhere in this catalog for "a protection was turned off"
// (LDAP_SIGNING_DISABLED, TRUST_AES_DISABLED, ...), which reads as bad news.
// Naming the population instead of a mechanism state avoids an auditor
// misreading this as the risk itself being off.
type DomainAdminInDescriptionOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewDomainAdminInDescriptionOnDisabledAccountDetector creates a new detector
func NewDomainAdminInDescriptionOnDisabledAccountDetector() *DomainAdminInDescriptionOnDisabledAccountDetector {
	return &DomainAdminInDescriptionOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("DOMAIN_ADMIN_IN_DESCRIPTION_ON_DISABLED_ACCOUNT", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *DomainAdminInDescriptionOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if !u.Disabled {
			continue
		}
		if u.Description == "" {
			continue
		}

		for _, pattern := range sensitiveKeywords {
			if pattern.MatchString(u.Description) {
				affected = append(affected, u)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Sensitive Terms in Description - Disabled Accounts",
		Description: "Disabled user accounts with admin/privileged keywords in the description field. Not usable to target an active session today - UF_ACCOUNTDISABLE blocks authentication for this account across every protocol - but the description text remains readable on the object right now by anyone with ordinary directory-read access, giving reconnaissance value independent of the disabled state, and would matter again for an active session if the account is re-enabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDomainAdminInDescriptionOnDisabledAccountDetector())
}
