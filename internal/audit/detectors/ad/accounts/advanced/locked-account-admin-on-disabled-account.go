package advanced

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// LockedAccountAdminOnDisabledAccountDetector checks for disabled admin
// accounts that are also currently/recently locked out. Split out of
// LockedAccountAdminDetector: a disabled account cannot obtain a
// ticket-granting ticket of its own ([MS-KILE], "Check Account Policy for
// Every TGT Request", KDC_ERR_CLIENT_REVOKED), so it cannot authenticate
// today - but membership in a domain-level privileged group is not removed
// by disabling the account, and returns to full effect the instant the
// account is re-enabled. The lockout itself remains a legitimate
// investigation signal (recent authentication attempts on an otherwise
// neutralized account), which this detector keeps reporting separately from
// the enabled population. Same convention as the delegation family
// (*_ON_DISABLED_ACCOUNT): the suffix names the population covered, not the
// state of a mechanism - _DISABLED alone is reserved elsewhere in this
// catalog for "a protection was turned off".
type LockedAccountAdminOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewLockedAccountAdminOnDisabledAccountDetector creates a new detector
func NewLockedAccountAdminOnDisabledAccountDetector() *LockedAccountAdminOnDisabledAccountDetector {
	return &LockedAccountAdminOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("LOCKED_ACCOUNT_ADMIN_ON_DISABLED_ACCOUNT", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *LockedAccountAdminOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	// adminGroupSIDSuffixes is the RID-suffix form of the same 7 groups:
	// Domain Admins, Enterprise Admins, Schema Admins,
	// Administrators, Account Operators, Server Operators, Backup
	// Operators - matched by SID, not CN, so a homonym doesn't
	// false-positive and a renamed real group is still caught. All 7
	// suffixes already appear in types.PrivilegedSIDSuffixes.
	adminGroupSIDSuffixes := []string{"-512", "-519", "-518", "-544", "-548", "-549", "-551"}
	adminDNs := privgroups.DNsBySIDSuffix(data, adminGroupSIDSuffixes)

	for _, u := range data.Users {
		if !u.Disabled {
			continue
		}

		if len(u.MemberOf) == 0 {
			continue
		}

		// Check if account is locked via lockoutTime, not the UAC LOCKOUT
		// bit (0x10). Since Windows Server 2003 that bit no longer reflects
		// live lockout state (KB305144); AD stamps lockoutTime with the
		// FILETIME of the lockout event and clears it to 0 on unlock or
		// reset, so it is the authoritative signal and is already collected
		// (internal/providers/ldap/parser.go parses "lockoutTime" into
		// types.User.LockoutTime).
		isLocked := !u.LockoutTime.IsZero() && u.LockoutTime.Year() > 1970

		if !isLocked {
			continue
		}

		// Check if in admin group
		if privgroups.IsMemberOfAny(u.MemberOf, adminDNs) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Locked Administrative Account (Disabled Account)",
		Description: "Disabled administrative accounts that are also currently locked out. Cannot authenticate while disabled, so the account cannot be used today - but the lockout remains a legitimate investigation signal, and group membership returns to full effect the instant the account is re-enabled. Investigate why these admin accounts were locked before re-enabling them.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"recommendation": "Investigate why these disabled admin accounts were locked. Check security logs for failed authentication attempts before considering re-enabling the account.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLockedAccountAdminOnDisabledAccountDetector())
}
