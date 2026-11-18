package security

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// LegacyProtocolOnDisabledAccountDetector checks for disabled computer
// accounts running an end-of-life operating system, or configured with
// weak Kerberos encryption types only. Split out of LegacyProtocolDetector,
// on the same model as WeakEncryptionOnDisabledAccountDetector in this same
// package: both facts measured here (installed OS version string,
// msDS-SupportedEncryptionTypes) are persistent attributes of the object,
// not privileges. A disabled computer account cannot obtain its own
// ticket-granting ticket, so neither signal has a practical effect while
// disabled. The attribute itself is not cleared by the disabled state, and
// the signal becomes active again the instant the account is re-enabled.
type LegacyProtocolOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewLegacyProtocolOnDisabledAccountDetector creates a new detector
func NewLegacyProtocolOnDisabledAccountDetector() *LegacyProtocolOnDisabledAccountDetector {
	return &LegacyProtocolOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_LEGACY_PROTOCOL_ON_DISABLED_ACCOUNT", audit.CategoryComputers),
	}
}

// Detect executes the detection. Uses the same legacyOSPatterns and
// encryption mask as LegacyProtocolDetector, in this same file's sibling
// legacy-protocol.go.
func (d *LegacyProtocolOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if c.Enabled() {
			continue
		}

		hasLegacyOS := false
		for _, pattern := range legacyOSPatterns {
			if pattern.MatchString(c.OperatingSystem) {
				hasLegacyOS = true
				break
			}
		}
		if hasLegacyOS {
			affected = append(affected, c)
			continue
		}

		// Same guard as the active detector: != 0, not > 0, so a negative
		// value that still carries zero AES bits is not missed; only the
		// literal zero value means "attribute never set".
		if c.SupportedEncryptionTypes != 0 {
			onlyLegacy := (c.SupportedEncryptionTypes & 0x18) == 0
			if onlyLegacy {
				affected = append(affected, c)
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Legacy Operating System or Weak Kerberos Encryption (Disabled Account)",
		Description: "Disabled computer account runs an end-of-life Windows version, or has no AES Kerberos encryption type enabled (DES/RC4 only). Both are persistent attributes of the object, not privileges: a disabled account cannot obtain a ticket-granting ticket, so neither signal has a practical effect today. The attribute is not cleared by the disabled state, and the signal becomes active again the instant the account is re-enabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLegacyProtocolOnDisabledAccountDetector())
}
