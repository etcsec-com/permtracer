package kerberos

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// KerberosRc4FallbackOnDisabledAccountDetector checks for disabled accounts
// that support both AES and RC4 Kerberos encryption types. Split out of
// KerberosRc4FallbackDetector: msDS-SupportedEncryptionTypes is a
// configuration attribute that does not change when the account is
// disabled. Per [MS-KILE] "Check Account Policy for Every TGT Request", a
// disabled account cannot obtain a new TGT (KDC_ERR_CLIENT_REVOKED at
// AS-REQ), so it cannot reach the initial exchange where an RC4 downgrade
// would be negotiated - but the configuration persists on disk and would
// matter again the moment the account is re-enabled, so it stays reported,
// at a severity that reflects dormancy rather than active risk.
//
// Named KERBEROS_RC4_FALLBACK_ON_DISABLED_ACCOUNT, not
// KERBEROS_RC4_FALLBACK_DISABLED: the _DISABLED suffix is reserved elsewhere
// in this catalog for "a protection was turned off" (LDAP_SIGNING_DISABLED,
// TRUST_AES_DISABLED, ...), which reads as bad news. Naming the population
// instead of a mechanism state avoids an auditor misreading this as the risk
// itself being off.
type KerberosRc4FallbackOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewKerberosRc4FallbackOnDisabledAccountDetector creates a new detector
func NewKerberosRc4FallbackOnDisabledAccountDetector() *KerberosRc4FallbackOnDisabledAccountDetector {
	return &KerberosRc4FallbackOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("KERBEROS_RC4_FALLBACK_ON_DISABLED_ACCOUNT", audit.CategoryKerberos),
	}
}

// Detect executes the detection
func (d *KerberosRc4FallbackOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, user := range data.Users {
		if !user.Disabled {
			continue
		}

		encTypes := user.SupportedEncryptionTypes
		if encTypes == 0 {
			continue
		}

		if hasRc4Fallback(encTypes) {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "RC4 Fallback Enabled (Disabled Account)",
		Description: "Disabled user accounts that support both AES and RC4 Kerberos encryption types. msDS-SupportedEncryptionTypes persists on the object regardless of account state; a disabled account cannot obtain the TGT needed to negotiate an RC4 downgrade, so this is not exploitable today, but the signal becomes active again as soon as the account is re-enabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewKerberosRc4FallbackOnDisabledAccountDetector())
}
