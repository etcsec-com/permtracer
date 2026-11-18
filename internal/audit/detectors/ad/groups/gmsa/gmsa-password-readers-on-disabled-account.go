package gmsa

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// GMSAPasswordReadersOnDisabledAccountDetector checks for disabled gMSAs
// whose managed password remains readable by a non-privileged principal.
// Split out of GMSAPasswordReadersDetector: a disabled gMSA's own
// ACCOUNTDISABLE closes only its own ability to authenticate ([MS-KILE]
// "Check Account Policy for Every TGT Request" - KDC_ERR_CLIENT_REVOKED);
// it does not remove, encrypt or hide the msDS-GroupMSAMembership
// attribute, and the reader's own ability to retrieve the managed password
// via an ordinary LDAP read depends on the READER's authentication, not on
// the gMSA's. The managed password therefore stays fully readable by the
// same non-privileged principal regardless of the gMSA's account state -
// the residual risk this detector keeps reporting.
//
// Severity Medium, not Low: per the split severity grid (D1), a disabled
// account that still exposes a secret (here, msDS-ManagedPassword readable
// by a non-privileged principal) is rated Medium - the same reasoning
// already applied to PASSWORD_IN_DESCRIPTION_ON_DISABLED_ACCOUNT. The
// secret is exploitable today, not only upon reactivation of the gMSA.
//
// Named GMSA_PASSWORD_READERS_ON_DISABLED_ACCOUNT, not
// GMSA_PASSWORD_READERS_DISABLED: the _DISABLED suffix is reserved
// elsewhere in this catalog for "a protection was turned off", which reads
// as bad news. Naming the population instead of a mechanism state avoids
// an auditor misreading this as the risk itself being off.
type GMSAPasswordReadersOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewGMSAPasswordReadersOnDisabledAccountDetector creates a new detector.
func NewGMSAPasswordReadersOnDisabledAccountDetector() *GMSAPasswordReadersOnDisabledAccountDetector {
	return &GMSAPasswordReadersOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("GMSA_PASSWORD_READERS_ON_DISABLED_ACCOUNT", audit.CategoryGroups),
	}
}

// Detect returns one finding listing every (disabled gMSA, non-privileged
// reader) pair, mirroring GMSAPasswordReadersDetector.Detect but on the
// opposite account state.
func (d *GMSAPasswordReadersOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	idx := buildGMSAReaderIndex(data)

	var affected []types.User
	pairs := make([]string, 0)

	for i := range data.Users {
		u := &data.Users[i]
		if !u.IsGMSA || len(u.GMSAMembership) == 0 {
			continue
		}
		if !u.Disabled {
			continue
		}

		readerPairs := idx.nonPrivilegedReaderPairs(u)
		if len(readerPairs) > 0 {
			affected = append(affected, *u)
			pairs = append(pairs, readerPairs...)
		}
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityMedium,
		Category: string(d.Category()),
		Title:    "Non-privileged principal can read gMSA password (Disabled Account)",
		Description: "One or more disabled Group Managed Service Accounts (gMSA) allow non-privileged " +
			"principals to retrieve their managed password via msDS-GroupMSAMembership. The managed " +
			"password remains fully readable by an ordinary LDAP read regardless of the gMSA's own " +
			"account state, so a non-privileged reader can still retrieve and reuse this secret " +
			"elsewhere. A reader that is a computer account, or a group whose transitively resolved " +
			"members are exclusively computer accounts, is not reported: granting computer accounts " +
			"retrieval rights is Microsoft's recommended gMSA configuration.",
		Count: len(affected),
		Details: map[string]interface{}{
			"recommendation": "Remove non-privileged principals from the gMSA PrincipalsAllowedToRetrieveManagedPassword set.",
			"pairs":          pairs,
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewGMSAPasswordReadersOnDisabledAccountDetector())
}
