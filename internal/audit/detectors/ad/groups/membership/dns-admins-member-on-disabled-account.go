package membership

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// DnsAdminsMemberOnDisabledAccountDetector checks for disabled direct
// members of DnsAdmins. Split out of DnsAdminsMemberDetector: a disabled
// user cannot authenticate ([MS-KILE] "Check Account Policy for Every TGT
// Request" - KDC_ERR_CLIENT_REVOKED), so it cannot exercise the DLL-load
// privilege DnsAdmins membership grants while the account stays disabled.
// Membership is not removed by this state - it persists and returns to
// full effect the instant the account is re-enabled, which is the residual
// risk this detector keeps reporting.
//
// Severity Medium, not Low: DnsAdmins membership is a domain-level
// privilege (arbitrary DLL load on a domain controller, equivalent to
// Domain Admin), per the split severity grid (D1) - dormant access to the
// highest tier of the domain is not a hygiene finding.
//
// Named DNS_ADMINS_MEMBER_ON_DISABLED_ACCOUNT, not DNS_ADMINS_MEMBER_DISABLED:
// the _DISABLED suffix is reserved elsewhere in this catalog for "a
// protection was turned off" (LDAP_SIGNING_DISABLED, TRUST_AES_DISABLED,
// ...), which reads as bad news. Naming the population instead of a
// mechanism state avoids an auditor misreading this as the risk itself
// being off.
type DnsAdminsMemberOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewDnsAdminsMemberOnDisabledAccountDetector creates a new detector
func NewDnsAdminsMemberOnDisabledAccountDetector() *DnsAdminsMemberOnDisabledAccountDetector {
	return &DnsAdminsMemberOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("DNS_ADMINS_MEMBER_ON_DISABLED_ACCOUNT", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *DnsAdminsMemberOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	dnsAdminsDNs := dnsAdminsGroupDNs(data.Groups)

	var affected []types.User
	for _, user := range data.Users {
		if !user.Disabled {
			continue
		}
		if isMemberOfDnsAdmins(user.MemberOf, dnsAdminsDNs) {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "DnsAdmins Member (Disabled Account)",
		Description: "Disabled users in the DnsAdmins group. Not exploitable today - a disabled account cannot authenticate to abuse the group's ability to load arbitrary DLLs on domain controllers - but membership persists and would re-apply its full, domain-level privilege the instant the account is re-enabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDnsAdminsMemberOnDisabledAccountDetector())
}
