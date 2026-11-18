package security

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// WeakEncryptionOnDisabledAccountDetector checks for disabled computer
// accounts configured with weak Kerberos encryption types only. Split out
// of WeakEncryptionDetector, on the same model as the user-account pair on
// the same attribute (kerberos.WeakEncryptionDESDetector /
// WeakEncryptionDESOnDisabledAccountDetector): a disabled computer account
// cannot obtain its own ticket-granting ticket, and the KDC also refuses to
// issue a service ticket for its SPNs, so the negotiated encryption type
// has no practical effect in either role while disabled. The configuration
// itself is not removed by this state - it persists and reasserts full
// exploitability the instant the account is re-enabled, which is the
// residual risk this detector keeps reporting.
type WeakEncryptionOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewWeakEncryptionOnDisabledAccountDetector creates a new detector
func NewWeakEncryptionOnDisabledAccountDetector() *WeakEncryptionOnDisabledAccountDetector {
	return &WeakEncryptionOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_WEAK_ENCRYPTION_ON_DISABLED_ACCOUNT", audit.CategoryComputers),
	}
}

// Detect executes the detection. Uses the same encryption-type masks as
// WeakEncryptionDetector, in this same file's sibling weak-encryption.go.
func (d *WeakEncryptionOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	const aesMask = 0x18 // AES128 | AES256
	const weakMask = 0x7 // DES_CBC_CRC | DES_CBC_MD5 | RC4_HMAC

	var affected []types.Computer

	for _, c := range data.Computers {
		encTypes := c.SupportedEncryptionTypes
		if encTypes == 0 {
			continue
		}

		if !c.Disabled {
			continue
		}

		hasAES := (encTypes & aesMask) != 0
		hasWeak := (encTypes & weakMask) != 0

		if !hasAES && hasWeak {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Computer Weak Encryption (Disabled Account)",
		Description: "Disabled computer account is configured with weak Kerberos encryption types only (DES/RC4, no AES). It cannot obtain its own ticket-granting ticket while disabled, and the KDC also refuses to issue a service ticket for its SPNs, so the encryption downgrade has no practical effect in either role today. The configuration persists on the object and becomes exploitable again the instant the account is re-enabled; by itself it does not carry a privileged group membership, a replication right, or an exposed secret. Remediation: enable AES support or delete the account.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWeakEncryptionOnDisabledAccountDetector())
}
