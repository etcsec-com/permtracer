package password

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// CleartextStorageOnDisabledAccountDetector checks for disabled accounts
// with cleartext password storage attributes. Split out of
// CleartextStorageDetector: a disabled account cannot obtain a ticket and
// cannot authenticate, so the stored value cannot be used to log on as this
// account today. The attribute is a persistent attribute of the object,
// though, not a mechanism tied to authentication: it stays readable by
// anyone with LDAP access independent of the account's disabled state, and
// the signal becomes active again the instant the account is re-enabled.
//
// Named PASSWORD_CLEARTEXT_STORAGE_ON_DISABLED_ACCOUNT, not
// PASSWORD_CLEARTEXT_STORAGE_DISABLED: the _DISABLED suffix is reserved
// elsewhere in this catalog for "a protection was turned off", which reads
// as good news. Naming the population instead of a mechanism state avoids
// an auditor misreading this as the risk itself being off.
type CleartextStorageOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewCleartextStorageOnDisabledAccountDetector creates a new detector
func NewCleartextStorageOnDisabledAccountDetector() *CleartextStorageOnDisabledAccountDetector {
	return &CleartextStorageOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("PASSWORD_CLEARTEXT_STORAGE_ON_DISABLED_ACCOUNT", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *CleartextStorageOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if !u.Disabled {
			continue
		}
		if u.UnixUserPassword || u.UserPassword {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Cleartext Password Storage (Disabled Account)",
		Description: "Disabled user accounts with attributes that may store passwords in cleartext or reversible format (userPassword, unixUserPassword). A disabled account cannot obtain a ticket and cannot authenticate, but the attribute is a persistent attribute of the object: it stays readable by anyone with LDAP access independent of the account's disabled state, and the signal becomes active again the instant the account is re-enabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewCleartextStorageOnDisabledAccountDetector())
}
