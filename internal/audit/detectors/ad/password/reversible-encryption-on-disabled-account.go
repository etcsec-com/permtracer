package password

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// ReversibleEncryptionOnDisabledAccountDetector checks for disabled
// accounts whose password is persisted with reversible encryption (UAC
// ENCRYPTED_TEXT_PASSWORD_ALLOWED, 0x80). Split out of
// ReversibleEncryptionDetector: a disabled account cannot obtain a ticket
// and cannot authenticate, so the reversibly-encrypted password on it is
// not usable to log on today. The bit is a persistent attribute of the
// object, though, not a mechanism tied to authentication: disabling the
// account does not clear or re-encrypt the stored secret, which stays
// readable at rest independent of the account's disabled state, and the
// signal becomes active again the instant the account is re-enabled.
//
// Named REVERSIBLE_ENCRYPTION_ON_DISABLED_ACCOUNT, not
// REVERSIBLE_ENCRYPTION_DISABLED: the _DISABLED suffix is reserved
// elsewhere in this catalog for "a protection was turned off", which reads
// as good news. Naming the population instead of a mechanism state avoids
// an auditor misreading this as the risk itself being off.
type ReversibleEncryptionOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewReversibleEncryptionOnDisabledAccountDetector creates a new detector
func NewReversibleEncryptionOnDisabledAccountDetector() *ReversibleEncryptionOnDisabledAccountDetector {
	return &ReversibleEncryptionOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("REVERSIBLE_ENCRYPTION_ON_DISABLED_ACCOUNT", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *ReversibleEncryptionOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if !u.Disabled {
			continue
		}
		if (u.UserAccountControl & types.UACEncryptedTextPasswordAllowed) != 0 {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Reversible Encryption (Disabled Account)",
		Description: "Disabled user accounts with passwords stored with reversible encryption (UAC flag 0x80, ENCRYPTED_TEXT_PASSWORD_ALLOWED). A disabled account cannot obtain a ticket and cannot authenticate, but the flag is a persistent attribute of the object: the stored secret stays readable at rest independent of the account's disabled state, and the signal becomes active again the instant the account is re-enabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewReversibleEncryptionOnDisabledAccountDetector())
}
