package kerberos

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// DelegationUnknownTargetOnDisabledAccountDetector checks for disabled
// accounts with constrained delegation configured to SPNs whose target
// hostname does not match any known computer. Split out of
// DelegationUnknownTargetDetector: msDS-AllowedToDelegateTo is only
// exploitable through S4U2Proxy, which per [MS-SFU] starts from a
// KRB_TGS_REQ that requires the delegating account's own valid TGT. Per
// [MS-KILE] "Check Account Policy for Every TGT Request", a disabled account
// cannot obtain a new TGT (KDC_ERR_CLIENT_REVOKED at AS-REQ), so it cannot
// initiate S4U2Proxy toward any target, known or unknown - but the
// configuration persists on disk and would matter again the moment the
// account is re-enabled, so it stays reported, at a severity that reflects
// dormancy rather than active risk.
//
// Named DELEGATION_UNKNOWN_TARGET_ON_DISABLED_ACCOUNT, not
// DELEGATION_UNKNOWN_TARGET_DISABLED: the _DISABLED suffix is reserved
// elsewhere in this catalog for "a protection was turned off"
// (LDAP_SIGNING_DISABLED, TRUST_AES_DISABLED, ...), which reads as bad news.
// Naming the population instead of a mechanism state avoids an auditor
// misreading this as the risk itself being off.
type DelegationUnknownTargetOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewDelegationUnknownTargetOnDisabledAccountDetector creates a new detector
func NewDelegationUnknownTargetOnDisabledAccountDetector() *DelegationUnknownTargetOnDisabledAccountDetector {
	return &DelegationUnknownTargetOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("DELEGATION_UNKNOWN_TARGET_ON_DISABLED_ACCOUNT", audit.CategoryKerberos),
	}
}

// Detect executes the detection
func (d *DelegationUnknownTargetOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	knownHosts := buildKnownDelegationHosts(data.Computers)

	var affected []types.User
	unknownTargets := make(map[string][]string) // user → unknown SPNs

	for _, u := range data.Users {
		if !u.Disabled {
			continue
		}
		if len(u.AllowedToDelegateTo) == 0 {
			continue
		}
		unknownSPNs := unknownDelegationSPNs(u.AllowedToDelegateTo, knownHosts)
		if len(unknownSPNs) > 0 {
			affected = append(affected, u)
			unknownTargets[u.SAMAccountName] = unknownSPNs
		}
	}

	// Also check computers with constrained delegation
	var affectedComputers []types.Computer
	for _, c := range data.Computers {
		if !c.Disabled {
			continue
		}
		if len(c.AllowedToDelegateTo) == 0 {
			continue
		}
		unknownSPNs := unknownDelegationSPNs(c.AllowedToDelegateTo, knownHosts)
		if len(unknownSPNs) > 0 {
			affectedComputers = append(affectedComputers, c)
			unknownTargets[c.SAMAccountName] = unknownSPNs
		}
	}

	totalCount := len(affected) + len(affectedComputers)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Constrained Delegation to Unknown Target (Disabled Account)",
		Description: "Disabled accounts with constrained delegation configured to SPNs whose target hostname does not match any known computer in Active Directory. msDS-AllowedToDelegateTo persists on the object regardless of account state; a disabled account cannot obtain the TGT that S4U2Proxy requires, so it cannot act on this configuration today, but the signal becomes active again as soon as the account is re-enabled.",
		Count:       totalCount,
	}

	if data.IncludeDetails && totalCount > 0 {
		var entities []types.AffectedEntity
		if len(affected) > 0 {
			entities = append(entities, helpers.ToAffectedUserEntities(affected)...)
		}
		if len(affectedComputers) > 0 {
			entities = append(entities, helpers.ToAffectedComputerEntities(affectedComputers)...)
		}
		finding.AffectedEntities = entities
		finding.Details = map[string]interface{}{
			"unknownTargets": unknownTargets,
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDelegationUnknownTargetOnDisabledAccountDetector())
}
