package membership

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// DnsAdminsMemberDetector checks for DnsAdmins membership
type DnsAdminsMemberDetector struct {
	audit.BaseDetector
}

// NewDnsAdminsMemberDetector creates a new detector
func NewDnsAdminsMemberDetector() *DnsAdminsMemberDetector {
	return &DnsAdminsMemberDetector{
		BaseDetector: audit.NewBaseDetector("DNS_ADMINS_MEMBER", audit.CategoryGroups),
	}
}

// dnsAdminsGroupDNs returns the lowercased DN of every collected group whose
// sAMAccountName equals "DnsAdmins" (case-insensitive). sAMAccountName, not
// CN, is what identifies the real group: "The logon name must be 20 or
// fewer characters long and be unique among all security principal objects
// within the domain." (Microsoft, "User Naming Attributes" -
// learn.microsoft.com/en-us/windows/win32/ad/naming-properties, section
// sAMAccountName). A group's CN carries no such guarantee - any object
// anywhere in the domain can be created with the same CN as another,
// regardless of container.
//
// DnsAdmins has NO well-known/fixed RID suffix: it is created by the DNS
// Server role installation with a RID assigned at creation time, which
// varies per forest - unlike Domain Admins (-512) or Backup Operators
// (-551), it cannot be resolved through privgroups.DNsBySIDSuffix.
// sAMAccountName is therefore the non-localized identifier available for
// this one group; it carries a declared, accepted limitation - a DnsAdmins
// group renamed on a non-English or customized forest is NOT recognized by
// this detector, since its sAMAccountName would then differ too. Other
// detectors (e.g. kerberos/kerberoasting-risk.go) read data.Tier0Config,
// loaded from an operator-provided tier0_groups.yaml, to let a rename be
// declared explicitly; this detector does NOT consult that config today, so
// it carries no such recourse - adding one is future work, not something
// this comment should claim already exists.
//
// If no group with this sAMAccountName was collected, the returned set is
// empty and every membership check below fails: the detector fails CLOSED
// (under-detection, never a false positive) rather than falling back to any
// CN-based heuristic.
func dnsAdminsGroupDNs(groups []types.Group) map[string]bool {
	dns := make(map[string]bool)
	for _, g := range groups {
		if strings.EqualFold(g.SAMAccountName, "DnsAdmins") {
			dns[strings.ToLower(g.DN)] = true
		}
	}
	return dns
}

// isMemberOfDnsAdmins reports whether any DN in memberOf, compared
// case-insensitively, is in dnsAdminsDNs (as built by dnsAdminsGroupDNs).
// Direct membership only, same scope as the code this replaces: no nested
// or transitive group membership is considered.
func isMemberOfDnsAdmins(memberOf []string, dnsAdminsDNs map[string]bool) bool {
	for _, dn := range memberOf {
		if dnsAdminsDNs[strings.ToLower(dn)] {
			return true
		}
	}
	return false
}

// Detect executes the detection
//
// Disabled accounts are excluded here on purpose: a disabled user cannot
// authenticate ([MS-KILE] "Check Account Policy for Every TGT Request" -
// KDC_ERR_CLIENT_REVOKED), so DnsAdmins membership cannot be exercised to
// load a malicious DLL on a domain controller while the account stays
// disabled. Membership itself is not removed by this state - it persists
// and returns to full effect the instant the account is re-enabled, which
// is why it is not dropped from the audit: it is reported separately, at
// Medium, by DnsAdminsMemberOnDisabledAccountDetector - the privilege it
// guards is domain-level (arbitrary DLL load on a DC, equivalent to Domain
// Admin), unlike a dormant hygiene finding.
func (d *DnsAdminsMemberDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	dnsAdminsDNs := dnsAdminsGroupDNs(data.Groups)

	var affected []types.User
	for _, user := range data.Users {
		if user.Disabled {
			continue
		}
		if isMemberOfDnsAdmins(user.MemberOf, dnsAdminsDNs) {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "DnsAdmins Member",
		Description: "Active (non-disabled) users in DnsAdmins group. Can load arbitrary DLLs on domain controllers (escalation to Domain Admin). Disabled members are reported separately by DNS_ADMINS_MEMBER_ON_DISABLED_ACCOUNT.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDnsAdminsMemberDetector())
}
