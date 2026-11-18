package organization

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// DCNotInDCOUDetector detects DCs not in Domain Controllers OU.
//
// Disabled DC objects are excluded here and reported instead, at Medium, by
// DCNotInDCOUOnDisabledAccountDetector (see dc-not-in-dc-ou-on-disabled-account.go):
// an object matching isDC's most reliable branch (the SERVER_TRUST_ACCOUNT
// UAC bit) keeps its DCSync-equivalent replication rights and native
// membership in the "Domain Controllers" privileged group attached to the
// object itself, not to its current ability to authenticate - that
// domain-level privilege would be fully exercisable again on the mere
// re-enabling of the object, so a disabled misplaced DC stays reported
// rather than mixed with the active population.
type DCNotInDCOUDetector struct {
	audit.BaseDetector
}

// NewDCNotInDCOUDetector creates a new detector
func NewDCNotInDCOUDetector() *DCNotInDCOUDetector {
	return &DCNotInDCOUDetector{
		BaseDetector: audit.NewBaseDetector("DC_NOT_IN_DC_OU", audit.CategoryComputers),
	}
}

// UAC flag for server trust account (DC)
const uacServerTrustAccount = 0x2000

// Detect executes the detection
func (d *DCNotInDCOUDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if c.Disabled {
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
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Domain Controller Not in Domain Controllers OU",
		Description: "Domain Controllers found outside the Domain Controllers OU. This may indicate misconfiguration or an attempt to hide a rogue DC.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}
	if len(affected) > 0 {
		finding.Details = map[string]interface{}{
			"recommendation": "Move all Domain Controllers to the Domain Controllers OU for proper GPO application and management.",
			"risks": []string{
				"GPOs targeting Domain Controllers OU may not apply",
				"May indicate rogue or compromised DC",
				"Security baselines may not be applied correctly",
			},
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDCNotInDCOUDetector())
}
