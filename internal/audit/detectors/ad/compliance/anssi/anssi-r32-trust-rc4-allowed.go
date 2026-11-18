package anssi

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// --- Trust allows RC4 (not AES-only) ---
//
// This is a product-level hygiene control on msDS-SupportedEncryptionTypes,
// not a numbered ANSSI PA-099 recommendation: PA-099's full text has no
// recommendation covering Kerberos trust encryption specifically.

type R32TrustRC4Detector struct{ audit.BaseDetector }

func NewR32TrustRC4Detector() *R32TrustRC4Detector {
	return &R32TrustRC4Detector{BaseDetector: audit.NewBaseDetector("ANSSI_R32_TRUST_RC4_ALLOWED", audit.CategoryCompliance)}
}
func (d *R32TrustRC4Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	count := 0
	for _, t := range data.Trusts {
		// AES not enabled OR RC4 explicitly enabled = downgrade risk.
		if !t.AESEnabled || t.RC4Enabled {
			count++
		}
	}
	return wrapFinding(d, "Trust Allows RC4 (Not AES-Only)",
		"Trust relationship allows RC4 on cross-realm Kerberos referrals (msDS-SupportedEncryptionTypes attribute): AES is not enabled, or RC4 is explicitly permitted. RC4 cross-realm tickets are kerberoastable and downgrade attacks remain possible. This is a product-level hygiene control; no ANSSI PA-099 recommendation names this check specifically.",
		types.SeverityMedium, count, nil)
}

func init() {
	audit.MustRegister(NewR32TrustRC4Detector())
}
