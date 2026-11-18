package moderate

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// AddMemberDetector detects Add-Member rights on groups
type AddMemberDetector struct {
	audit.BaseDetector
}

// NewAddMemberDetector creates a new detector
func NewAddMemberDetector() *AddMemberDetector {
	return &AddMemberDetector{
		BaseDetector: audit.NewBaseDetector("ACL_ADD_MEMBER", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *AddMemberDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Member attribute GUID: bf9679c0-0de6-11d0-a285-00aa003049e2
	const memberGUID = "bf9679c0-0de6-11d0-a285-00aa003049e2"
	const writeProperty = 0x20

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		// A DENY ace grants nothing (DET_10).
		if !audit.IsGrantACE(ace.AceType) {
			continue
		}
		// SYSTEM / Domain Admins / Enterprise Admins / BUILTIN\Administrators
		// hold write access to every AD object by construction - see
		// genericwrite.go's note in this same package (1134/1167 objects on a
		// real domain without this filter).
		if audit.IsBuiltinAdminTrustee(ace.Trustee) {
			continue
		}

		hasWriteProperty := (ace.AccessMask & writeProperty) != 0
		isMemberProperty := strings.ToLower(ace.ObjectType) == memberGUID

		if hasWriteProperty && isMemberProperty {
			affected = append(affected, ace)
		}
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Add-Member Rights on Groups",
		Description: "Principals with rights to add members to groups. Can be abused to add accounts to privileged groups.",
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
	audit.MustRegister(NewAddMemberDetector())
}
