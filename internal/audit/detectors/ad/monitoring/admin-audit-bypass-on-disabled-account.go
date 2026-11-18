package monitoring

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// AdminAuditBypassOnDisabledAccountDetector checks for disabled privileged
// accounts left outside the Protected Users group with a stale password.
// Split out of AdminAuditBypassDetector: AdminCount and privileged-group
// membership are not removed by ACCOUNTDISABLE - both persist on the
// object and return to full effect the instant the account is re-enabled
// (see NotInProtectedUsersOnDisabledAccountDetector, the same split applied
// to the narrower base predicate this detector adds a password-age test
// on top of). Protected Users membership is a Kerberos ticket hardening
// the account would still lack at that point, so this stays reported even
// though the account cannot authenticate today.
type AdminAuditBypassOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewAdminAuditBypassOnDisabledAccountDetector creates a new detector
func NewAdminAuditBypassOnDisabledAccountDetector() *AdminAuditBypassOnDisabledAccountDetector {
	return &AdminAuditBypassOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("ADMIN_AUDIT_BYPASS_ON_DISABLED_ACCOUNT", audit.CategoryMonitoring),
	}
}

// Detect executes the detection
func (d *AdminAuditBypassOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Find disabled users with adminCount=1
	var adminUsers []types.User
	for _, user := range data.Users {
		if user.AdminCount && user.Disabled {
			adminUsers = append(adminUsers, user)
		}
	}

	protectedUsersDNs := privgroups.DNsBySIDSuffix(data, protectedUsersSIDSuffixes)

	// Check for admins not in Protected Users group
	var adminsNotProtected []types.User
	for _, admin := range adminUsers {
		if !privgroups.IsMemberOfAny(admin.MemberOf, protectedUsersDNs) {
			adminsNotProtected = append(adminsNotProtected, admin)
		}
	}

	// Check for admins with old passwords (higher risk)
	sixMonthsAgo := data.Now.AddDate(0, -6, 0)
	var credentialTheftExposure []types.User
	for _, admin := range adminsNotProtected {
		if admin.PasswordLastSet.IsZero() || admin.PasswordLastSet.Before(sixMonthsAgo) {
			credentialTheftExposure = append(credentialTheftExposure, admin)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Privileged Accounts Not Protected Against Credential Theft (Disabled Account)",
		Description: "Disabled privileged accounts are not members of the Protected Users group and have a stale password. AdminCount and privileged group membership are not removed by disabling the account, and would apply again if the account is re-enabled - at which point these credentials would again be exposed to theft techniques (NTLM authentication, weak Kerberos encryption, credential caching) that the group is designed to block.",
		Count:       len(credentialTheftExposure),
	}

	if len(credentialTheftExposure) > 0 {
		if data.IncludeDetails {
			finding.AffectedEntities = helpers.ToAffectedUserEntities(credentialTheftExposure)
		}
		finding.Details = map[string]interface{}{
			"totalAdmins":            len(adminUsers),
			"adminsNotProtected":     len(adminsNotProtected),
			"adminsWithOldPasswords": len(credentialTheftExposure),
			"recommendation":         "Add admin accounts to the Protected Users group and enforce regular password rotation before re-enabling.",
			"risks": []string{
				"AdminCount and privileged-group membership persist across disablement and return to full effect on re-enable",
				"Credentials can be authenticated via NTLM or weak Kerberos encryption types once re-enabled",
				"Long-unrotated passwords widen the window for credential theft once re-enabled",
			},
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminAuditBypassOnDisabledAccountDetector())
}
