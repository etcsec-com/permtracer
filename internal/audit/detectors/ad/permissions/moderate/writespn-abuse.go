package moderate

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// WriteSPNAbuseDetector detects WriteProperty permission for servicePrincipalName
type WriteSPNAbuseDetector struct {
	audit.BaseDetector
}

// NewWriteSPNAbuseDetector creates a new detector
func NewWriteSPNAbuseDetector() *WriteSPNAbuseDetector {
	return &WriteSPNAbuseDetector{
		BaseDetector: audit.NewBaseDetector("WRITESPN_ABUSE", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *WriteSPNAbuseDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	const spnPropertyGUID = "f3a64788-5306-11d1-a9c5-0000f80367c1"

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		if !audit.IsGrantACE(ace.AceType) {
			continue
		}
		if audit.IsBuiltinAdminTrustee(ace.Trustee) {
			continue
		}

		// GenericAll and GenericWrite subsume WriteProperty on every
		// attribute, servicePrincipalName included. A WriteProperty ACE with
		// no ObjectType covers every property for the same reason; only a
		// WriteProperty ACE scoped to another property's GUID is out of
		// scope.
		var grants bool
		switch {
		case ace.AccessMask&types.MaskGenericAll != 0:
			grants = true
		case ace.AccessMask&types.MaskGenericWrite != 0:
			grants = true
		case ace.AccessMask&types.MaskWriteProperty != 0:
			switch strings.ToLower(ace.ObjectType) {
			case "", spnPropertyGUID:
				grants = true
			}
		}
		if !grants {
			continue
		}

		// servicePrincipalName is only meaningful on accounts; same
		// restriction as force-change-password.go.
		meta := data.ObjectByDN[ace.ObjectDN]
		if meta == nil || (meta.EntityType != types.EntityTypeUser && meta.EntityType != types.EntityTypeComputer) {
			continue
		}

		affected = append(affected, ace)
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Write SPN Abuse",
		Description: "WriteProperty permission for servicePrincipalName attribute. Can set SPNs for targeted Kerberoasting.",
		Count:       len(uniqueObjects),
	}

	if totalInstances != len(uniqueObjects) {
		finding.TotalInstances = totalInstances
	}

	if data.IncludeDetails && len(uniqueObjects) > 0 {
		finding.AffectedEntities = audit.GetUniqueObjectEntities(affected, data.ObjectByDN)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWriteSPNAbuseDetector())
}
