package moderate

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// UserForceChangePasswordDetector detects User-Force-Change-Password rights
type UserForceChangePasswordDetector struct {
	audit.BaseDetector
}

// NewUserForceChangePasswordDetector creates a new detector
func NewUserForceChangePasswordDetector() *UserForceChangePasswordDetector {
	return &UserForceChangePasswordDetector{
		BaseDetector: audit.NewBaseDetector("ACL_USER_FORCE_CHANGE_PASSWORD", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *UserForceChangePasswordDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// User-Force-Change-Password: 00299570-246d-11d0-a768-00aa006e0529
	const forceChangePasswordGUID = "00299570-246d-11d0-a768-00aa006e0529"

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		// A DENY ace grants nothing, and built-in admins hold this right on
		// every account by construction - neither is a delegation to flag.
		if !audit.IsGrantACE(ace.AceType) {
			continue
		}
		if audit.IsBuiltinAdminTrustee(ace.Trustee) {
			continue
		}

		// The GUID only names the extended right; the mask must actually
		// grant CONTROL_ACCESS for the ACE to confer it (a ReadProperty ACE
		// on the same ObjectType reads the attribute, it does not invoke
		// the right). GenericAll subsumes every right including this one,
		// and a CONTROL_ACCESS ACE with no ObjectType grants every
		// extended right - this one included - same equivalence as dcsync.go.
		var grants bool
		switch {
		case ace.AccessMask&types.MaskGenericAll != 0:
			grants = true
		case ace.AccessMask&types.MaskControlAccess != 0:
			switch strings.ToLower(ace.ObjectType) {
			case "", forceChangePasswordGUID:
				grants = true
			}
		}
		if !grants {
			continue
		}

		// This detector's Description is about user accounts; GenericAll and
		// an ObjectType-less CONTROL_ACCESS ACE grant the right on any target
		// (groups, OUs, GPOs...), which overlaps with ACL_GENERICALL there.
		meta := data.ObjectByDN[ace.ObjectDN]
		if meta == nil || meta.EntityType != types.EntityTypeUser {
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
		Title:       "User-Force-Change-Password Rights",
		Description: "Principals with rights to force password change on user accounts. Can reset passwords to take over accounts.",
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
	audit.MustRegister(NewUserForceChangePasswordDetector())
}
