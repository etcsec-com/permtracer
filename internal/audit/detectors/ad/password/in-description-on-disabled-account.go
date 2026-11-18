package password

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// PasswordInDescriptionOnDisabledAccountDetector checks for disabled
// accounts with a password or password-like string in the description
// field. Split out of InDescriptionDetector: UF_ACCOUNTDISABLE blocks
// authentication for this account across every protocol (interactive logon,
// LDAP bind, NTLM, Kerberos), so the leaked credential cannot be used to log
// on as this account today.
//
// Unlike a UAC bit or a group membership, though, this exposure is not
// merely dormant until re-enable: the plaintext credential is readable RIGHT
// NOW by anyone with ordinary directory-read access, independent of the
// account's disabled state. That gives an attacker who already holds a
// foothold (or an insider with routine read access) a usable credential
// today - the same password is commonly reused elsewhere (another account,
// a shared service, a personal account), so the leak stays exploitable even
// while this particular account cannot authenticate. The disabled state
// only closes the live-session half of the risk; the credential-disclosure
// half stays fully current, which is why this twin is reported at Medium
// rather than Low.
//
// Named PASSWORD_IN_DESCRIPTION_ON_DISABLED_ACCOUNT, not
// PASSWORD_IN_DESCRIPTION_DISABLED: the _DISABLED suffix is reserved
// elsewhere in this catalog for "a protection was turned off"
// (LDAP_SIGNING_DISABLED, TRUST_AES_DISABLED, ...), which reads as bad news.
// Naming the population instead of a mechanism state avoids an auditor
// misreading this as the risk itself being off.
type PasswordInDescriptionOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewPasswordInDescriptionOnDisabledAccountDetector creates a new detector
func NewPasswordInDescriptionOnDisabledAccountDetector() *PasswordInDescriptionOnDisabledAccountDetector {
	return &PasswordInDescriptionOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("PASSWORD_IN_DESCRIPTION_ON_DISABLED_ACCOUNT", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *PasswordInDescriptionOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User
	// matchedPatterns[i] holds the pattern names for affected[i], same
	// contract as InDescriptionDetector: name the credential's shape, never
	// carry the value.
	var matchedPatterns [][]string

	for _, u := range data.Users {
		if !u.Disabled {
			continue
		}

		if names := types.MatchSecretPatterns(u.Description); len(names) > 0 {
			affected = append(affected, u)
			matchedPatterns = append(matchedPatterns, names)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Password in Description (Disabled Account)",
		Description: "Disabled user accounts with passwords or password-like strings in the description field. Not usable to log on as this account today - UF_ACCOUNTDISABLE blocks authentication for this account across every protocol - but the plaintext value remains readable on the object right now by anyone with ordinary directory-read access, and the same credential is often reused elsewhere, so the exposure stays exploitable independent of the disabled state.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		entities := helpers.ToAffectedUserEntities(affected)
		for i := range entities {
			entities[i].Description = "matched credential pattern: " + strings.Join(matchedPatterns[i], ", ")
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPasswordInDescriptionOnDisabledAccountDetector())
}
