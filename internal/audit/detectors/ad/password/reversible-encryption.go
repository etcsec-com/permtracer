package password

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// ReversibleEncryptionDetector detects active accounts whose password is
// persisted with reversible encryption (UAC
// ENCRYPTED_TEXT_PASSWORD_ALLOWED, 0x80). Scoped to active accounts: a
// disabled account cannot authenticate, so the reversibly-encrypted
// password on it is not usable to log on today - see
// ReversibleEncryptionOnDisabledAccountDetector
// (reversible-encryption-on-disabled-account.go) for the disabled-account
// claim, reported separately at Medium because the stored secret stays
// readable at rest independent of the account's ability to authenticate.
type ReversibleEncryptionDetector struct {
	audit.BaseDetector
}

// NewReversibleEncryptionDetector creates a new detector
func NewReversibleEncryptionDetector() *ReversibleEncryptionDetector {
	return &ReversibleEncryptionDetector{
		BaseDetector: audit.NewBaseDetector("REVERSIBLE_ENCRYPTION", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *ReversibleEncryptionDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if u.Disabled {
			continue
		}
		if (u.UserAccountControl & types.UACEncryptedTextPasswordAllowed) != 0 {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Reversible Encryption",
		Description: "Active user accounts with passwords stored with reversible encryption (UAC flag 0x80, ENCRYPTED_TEXT_PASSWORD_ALLOWED). Equivalent to storing the password in cleartext in the directory.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewReversibleEncryptionDetector())
}
