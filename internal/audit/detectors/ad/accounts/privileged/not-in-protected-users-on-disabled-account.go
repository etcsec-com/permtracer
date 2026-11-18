package privileged

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// NotInProtectedUsersOnDisabledAccountDetector detects disabled privileged
// accounts not in the Protected Users group. Split out of
// NotInProtectedUsersDetector: AdminCount and privileged-group membership
// are not removed by ACCOUNTDISABLE - both persist on the object and
// return to full effect the instant the account is re-enabled. Protected
// Users membership is a Kerberos ticket hardening the account would still
// lack at that point, so this stays reported even though the account
// cannot authenticate today.
type NotInProtectedUsersOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewNotInProtectedUsersOnDisabledAccountDetector creates a new detector
func NewNotInProtectedUsersOnDisabledAccountDetector() *NotInProtectedUsersOnDisabledAccountDetector {
	return &NotInProtectedUsersOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("NOT_IN_PROTECTED_USERS_ON_DISABLED_ACCOUNT", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *NotInProtectedUsersOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	// protectedUsersDNs is the DN of every collected group whose SID ends in
	// the well-known Protected Users RID (-525, Microsoft Learn "Security
	// identifiers"), resolved the same non-localized, non-homonym-prone way
	// privgroups already resolves the 7 privileged groups below.
	protectedUsersDNs := privgroups.DNsBySIDSuffix(data, []string{"-525"})

	// If no group carries the -525 RID, the detector stays silent - same
	// behavior as NotInProtectedUsersDetector's own miss case.
	if len(protectedUsersDNs) == 0 {
		return []types.Finding{}
	}

	// protectedUsersMembers is the member DN set of every group identified
	// above, read straight from data.Groups: DNsBySIDSuffix only resolves a
	// group's own DN, not its Member list.
	protectedUsersMembers := make(map[string]bool)
	for i := range data.Groups {
		if protectedUsersDNs[strings.ToLower(data.Groups[i].DN)] {
			for _, m := range data.Groups[i].Member {
				protectedUsersMembers[strings.ToLower(m)] = true
			}
		}
	}

	// privilegedGroupSIDSuffixes is the same 7 groups NotInProtectedUsersDetector
	// uses (Domain Admins, Enterprise Admins, Schema Admins, Administrators,
	// Account Operators, Backup Operators, Server Operators), matched by RID
	// suffix instead of CN.
	privilegedGroupSIDSuffixes := []string{"-512", "-519", "-518", "-544", "-548", "-551", "-549"}
	privilegedDNs := privgroups.DNsBySIDSuffix(data, privilegedGroupSIDSuffixes)

	for _, u := range data.Users {
		if !u.Disabled {
			continue
		}

		// Check if privileged
		isPrivileged := false

		// Criterion 1: AdminCount=true
		if u.AdminCount {
			isPrivileged = true
		}

		// Criterion 2: Member of privileged groups
		if !isPrivileged && len(u.MemberOf) > 0 {
			isPrivileged = privgroups.IsMemberOfAny(u.MemberOf, privilegedDNs)
		}

		if !isPrivileged {
			continue
		}

		// Exclusions by well-known RID (Microsoft Learn "Security
		// identifiers"): krbtgt (-502) and the built-in Administrator
		// (-500) can be renamed, so their SAMAccountName is not a reliable
		// signal in either direction - only the RID is.
		if strings.HasSuffix(u.ObjectSID, "-502") {
			continue
		}
		if strings.HasSuffix(u.ObjectSID, "-500") {
			continue
		}
		if len(u.ServicePrincipalNames) > 0 {
			continue // Service accounts incompatible with Protected Users
		}

		// Check if in Protected Users (both methods, both by resolved DN)

		// Method 1: Check user's MemberOf
		isInProtectedUsers := privgroups.IsMemberOfAny(u.MemberOf, protectedUsersDNs)

		// Method 2: Check group's member list
		if !isInProtectedUsers && protectedUsersMembers[strings.ToLower(u.DN)] {
			isInProtectedUsers = true
		}

		if !isInProtectedUsers {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Privileged Accounts Not in Protected Users (Disabled Account)",
		Description: "Disabled privileged accounts not in Protected Users group. AdminCount and privileged group membership are not removed by disabling the account, and would apply again if the account is re-enabled.",
		Count:       len(affected),
		Details: map[string]interface{}{
			"recommendation": "Add privileged accounts to Protected Users group",
			"exclusions":     "Service accounts with SPNs excluded (incompatible)",
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNotInProtectedUsersOnDisabledAccountDetector())
}
