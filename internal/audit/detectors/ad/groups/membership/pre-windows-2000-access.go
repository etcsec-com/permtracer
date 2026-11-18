package membership

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// preWindows2000CompatibleAccessSID is the fixed, forest-wide well-known SID
// of the built-in "Pre-Windows 2000 Compatible Access" group
// (internal/audit/wellknown_sids.go:89), the same non-localized match
// GROUP_AUTHENTICATED_USERS_PRIVILEGED and GPO_MODIFY_RIGHTS use for their
// own built-in groups. The previous CN/SAMAccountName substring match on the
// English name missed the group on a localized DC and false-positived on
// any homonym group that merely shares the English name with a different
// SID.
const preWindows2000CompatibleAccessSID = "S-1-5-32-554"

// PreWindows2000AccessDetector checks for Pre-Windows 2000 Compatible Access membership
type PreWindows2000AccessDetector struct {
	audit.BaseDetector
}

// NewPreWindows2000AccessDetector creates a new detector
func NewPreWindows2000AccessDetector() *PreWindows2000AccessDetector {
	return &PreWindows2000AccessDetector{
		BaseDetector: audit.NewBaseDetector("PRE_WINDOWS_2000_ACCESS", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *PreWindows2000AccessDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Find the "Pre-Windows 2000 Compatible Access" group by its fixed,
	// well-known SID, not by its (localizable, spoofable) name.
	var targetGroup *types.Group
	for i := range data.Groups {
		if strings.EqualFold(data.Groups[i].ObjectSID, preWindows2000CompatibleAccessSID) {
			targetGroup = &data.Groups[i]
			break
		}
	}

	memberCount := 0
	if targetGroup != nil {
		memberCount = len(targetGroup.Members)
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityMedium,
		Category: string(d.Category()),
		Title:    "Pre-Windows 2000 Compatible Access",
		Description: "Pre-Windows 2000 Compatible Access group has members. Overly permissive read access to AD objects. " +
			"This detector does not distinguish default special principals (Everyone, Anonymous Logon, " +
			"Authenticated Users) from accounts added manually among the group's members.",
		Count: memberCount,
	}

	if data.IncludeDetails && targetGroup != nil && memberCount > 0 {
		finding.AffectedEntities = []types.AffectedEntity{
			types.GroupToAffectedEntity(targetGroup),
		}
		finding.Details = map[string]interface{}{
			"members": targetGroup.Members,
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPreWindows2000AccessDetector())
}
