package password

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// CleartextStorageDetector detects active accounts with cleartext password
// storage attributes. Scoped to active accounts: a disabled account cannot
// authenticate, so the stored value cannot be used to log on as this
// account today - see CleartextStorageOnDisabledAccountDetector
// (cleartext-storage-on-disabled-account.go) for the disabled-account
// claim, reported separately at Medium because the stored attribute stays
// readable by anyone with LDAP access independent of the account's ability
// to authenticate.
type CleartextStorageDetector struct {
	audit.BaseDetector
}

// NewCleartextStorageDetector creates a new detector
func NewCleartextStorageDetector() *CleartextStorageDetector {
	return &CleartextStorageDetector{
		BaseDetector: audit.NewBaseDetector("PASSWORD_CLEARTEXT_STORAGE", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *CleartextStorageDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if u.Disabled {
			continue
		}
		// Check Unix password attributes (from LDAP)
		if u.UnixUserPassword || u.UserPassword {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Cleartext Password Storage",
		Description: "Active user accounts with attributes that may store passwords in cleartext or reversible format. These attributes (userPassword, unixUserPassword) can be read by attackers with LDAP access.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewCleartextStorageDetector())
}
