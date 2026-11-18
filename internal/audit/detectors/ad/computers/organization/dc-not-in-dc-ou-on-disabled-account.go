package organization

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// DCNotInDCOUOnDisabledAccountDetector checks for disabled domain controller
// objects located outside the Domain Controllers OU. Split out of
// DCNotInDCOUDetector: an object matching isDC's most reliable branch (the
// SERVER_TRUST_ACCOUNT UAC bit) keeps its DCSync-equivalent replication
// rights and native membership in the "Domain Controllers" privileged group
// attached to the object itself, not to its current ability to
// authenticate - that domain-level privilege would be fully exercisable
// again on the mere re-enabling of the object. A disabled DC object outside
// its OU can also be the leftover of an incomplete demotion, or an object
// deliberately hidden there, so it stays reported here rather than mixed
// with the active population.
//
// Named DC_NOT_IN_DC_OU_ON_DISABLED_ACCOUNT, not DC_NOT_IN_DC_OU_DISABLED:
// the _DISABLED suffix is reserved elsewhere in this catalog for "a
// protection was turned off" (LDAP_SIGNING_DISABLED, TRUST_AES_DISABLED,
// ...), which reads as bad news. Naming the population instead of a
// mechanism state avoids an auditor misreading this as the risk itself
// being off.
type DCNotInDCOUOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewDCNotInDCOUOnDisabledAccountDetector creates a new detector
func NewDCNotInDCOUOnDisabledAccountDetector() *DCNotInDCOUOnDisabledAccountDetector {
	return &DCNotInDCOUOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("DC_NOT_IN_DC_OU_ON_DISABLED_ACCOUNT", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *DCNotInDCOUOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if !c.Disabled {
			continue
		}

		// Name and dNSHostName are operator-chosen and not a reliable signal
		// of DC role; only the UAC bit set by the DC promotion process is.
		isDC := (c.UserAccountControl & uacServerTrustAccount) != 0

		if !isDC {
			continue
		}

		// Check if it's in the Domain Controllers OU
		isInDCOU := strings.Contains(strings.ToLower(c.DN), "ou=domain controllers")

		if !isInDCOU {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Domain Controller Not in Domain Controllers OU (Disabled Account)",
		Description: "Disabled domain controller object found outside the Domain Controllers OU. The object still carries DCSync-equivalent replication rights and native membership in the \"Domain Controllers\" group, both attached to the object itself and immediately exercisable again if it were re-enabled. May be the leftover of an incomplete demotion, or an object deliberately hidden outside its OU.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}
	if len(affected) > 0 {
		finding.Details = map[string]interface{}{
			"recommendation": "Move all Domain Controllers to the Domain Controllers OU for proper GPO application and management.",
			"risks": []string{
				"DCSync-equivalent replication rights remain attached to the object and would be exercisable again if re-enabled",
				"May indicate an incomplete demotion or a deliberately hidden rogue DC object",
			},
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDCNotInDCOUOnDisabledAccountDetector())
}
