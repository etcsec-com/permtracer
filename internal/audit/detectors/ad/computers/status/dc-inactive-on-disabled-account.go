package status

import (
	"context"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// DCInactiveOnDisabledAccountDetector checks for disabled domain controller
// objects whose last logon timestamp is older than 45 days. Split out of
// DCInactiveDetector: a disabled DC object still carries DCSync-equivalent
// replication rights and native membership in the "Domain Controllers"
// privileged group, both attached to the object itself rather than to its
// current ability to authenticate - that privilege would be fully
// exercisable again on the mere re-enabling of the object, so it stays
// reported, at Medium, rather than mixed with the active population.
//
// Named DC_INACTIVE_ON_DISABLED_ACCOUNT, not DC_INACTIVE_DISABLED: the
// _DISABLED suffix is reserved elsewhere in this catalog for "a protection
// was turned off" (LDAP_SIGNING_DISABLED, TRUST_AES_DISABLED, ...), which
// reads as bad news. Naming the population instead of a mechanism state
// avoids an auditor misreading this as the risk itself being off.
type DCInactiveOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewDCInactiveOnDisabledAccountDetector creates a new detector
func NewDCInactiveOnDisabledAccountDetector() *DCInactiveOnDisabledAccountDetector {
	return &DCInactiveOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("DC_INACTIVE_ON_DISABLED_ACCOUNT", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *DCInactiveOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	cutoff := data.Now.AddDate(0, 0, -45)
	var affected []types.Computer

	for i := range data.DomainControllers {
		dc := &data.DomainControllers[i]
		if !dc.Disabled {
			continue
		}
		last := dc.LastLogonTimestamp
		if last.IsZero() {
			last = dc.LastLogon
		}
		if last.IsZero() || last.Before(cutoff) {
			affected = append(affected, *dc)
		}
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityMedium,
		Category: string(d.Category()),
		Title:    "Inactive Domain Controller (Disabled Account)",
		Description: "One or more disabled domain controller objects have not authenticated in over 45 days. " +
			"Not a live decommission or replication failure while disabled, but the object still carries " +
			"DCSync-equivalent replication rights and native membership in the \"Domain Controllers\" group, " +
			"both of which would be immediately exercisable again if the object were re-enabled.",
		Count: len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDCInactiveOnDisabledAccountDetector())
}
