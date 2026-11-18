package other

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// DCShadowOnDisabledAccountDetector checks for DISABLED computer objects
// carrying the SERVER_TRUST_ACCOUNT UAC flag (or already known as a domain
// controller) located outside the standard OU=Domain Controllers container.
// Split out of DCShadowDetector (see dcshadow.go): an object matching the
// SERVER_TRUST_ACCOUNT bit keeps its DCSync-equivalent replication rights
// and native membership in the "Domain Controllers" privileged group
// attached to the object itself, not to its current ability to
// authenticate - that domain-level privilege would be fully exercisable
// again on the mere re-enabling of the object. A disabled misplaced DC
// object can also be the leftover of an incomplete demotion, or an object
// deliberately hidden there, so it stays reported here rather than mixed
// with the active population.
//
// Named DCSHADOW_EVIDENCE_ON_DISABLED_ACCOUNT, not ..._DISABLED: the
// _DISABLED suffix is reserved elsewhere in this catalog for "a protection
// was turned off" (LDAP_SIGNING_DISABLED, TRUST_AES_DISABLED, ...), which
// reads as bad news. Naming the population instead of a mechanism state
// avoids an auditor misreading this as the risk itself being off.
//
// Gabarit: DCNotInDCOUOnDisabledAccountDetector
// (ad/computers/organization/dc-not-in-dc-ou-on-disabled-account.go), which
// tests a quasi-identical condition on the same uacServerTrustAccount bit,
// at the same Medium severity.
type DCShadowOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewDCShadowOnDisabledAccountDetector creates a new detector
func NewDCShadowOnDisabledAccountDetector() *DCShadowOnDisabledAccountDetector {
	return &DCShadowOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("DCSHADOW_EVIDENCE_ON_DISABLED_ACCOUNT", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *DCShadowOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	// Check DomainControllers for any DISABLED DC outside the standard
	// Domain Controllers OU.
	for _, dc := range data.DomainControllers {
		if !dc.Disabled {
			continue
		}

		if !isInDomainControllersOU(dc.DistinguishedName) && !isInDomainControllersOU(dc.DN) {
			affected = append(affected, dc)
		}
	}

	// Also check Computers for a DISABLED SERVER_TRUST_ACCOUNT outside
	// Domain Controllers OU.
	seen := make(map[string]bool)
	for _, dc := range affected {
		if dc.DN != "" {
			seen[dc.DN] = true
		}
		if dc.DistinguishedName != "" {
			seen[dc.DistinguishedName] = true
		}
	}

	for _, computer := range data.Computers {
		if !computer.Disabled {
			continue
		}

		if (computer.UserAccountControl & uacServerTrustAccountFlag) == 0 {
			continue
		}

		dn := computer.DistinguishedName
		if dn == "" {
			dn = computer.DN
		}

		if seen[dn] {
			continue
		}

		if !isInDomainControllersOU(dn) {
			affected = append(affected, computer)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Domain Controller Object Outside Standard OU (Disabled Account)",
		Description: "A DISABLED computer object with the SERVER_TRUST_ACCOUNT flag (or an already-known domain controller) was found outside the standard OU=Domain Controllers container. Not usable to authenticate or replicate today - UF_ACCOUNTDISABLE blocks it - but the object still carries the SERVER_TRUST_ACCOUNT bit's DCSync-equivalent replication rights and native membership in the privileged \"Domain Controllers\" group, both attached to the object itself and immediately exercisable again if it were re-enabled. Like the active-account detector, this is ONE of several evidence classes MITRE ATT&CK T1207 associates with a DCShadow rogue-DC registration (object placement), not the full set; treat a hit as a directory anomaly to investigate, not as confirmed evidence of an attack.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDCShadowOnDisabledAccountDetector())
}
