package nesting

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// DangerousNestingDetector checks for sensitive groups nested in less sensitive groups
type DangerousNestingDetector struct {
	audit.BaseDetector
}

// NewDangerousNestingDetector creates a new detector
func NewDangerousNestingDetector() *DangerousNestingDetector {
	return &DangerousNestingDetector{
		BaseDetector: audit.NewBaseDetector("DANGEROUS_GROUP_NESTING", audit.CategoryGroups),
	}
}

// protectedGroupSIDSuffixes matches the same eight privileged groups the
// previous strings.Contains(group.DN, "CN="+name) logic listed, but by
// their fixed, well-known RID (Microsoft Learn, "Security identifiers",
// learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers)
// instead of their English CN: the CN-based match was blind on a localized
// forest (the CN differs per language) and false-positived on any homonym
// group whose CN merely contained the same English text.
var protectedGroupSIDSuffixes = []string{
	"-512", // Domain Admins
	"-519", // Enterprise Admins
	"-518", // Schema Admins
	"-544", // Administrators
	"-548", // Account Operators
	"-551", // Backup Operators
	"-549", // Server Operators
	"-550", // Print Operators
}

// Detect executes the detection
func (d *DangerousNestingDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Group

	protectedDNs := privgroups.DNsBySIDSuffix(data, protectedGroupSIDSuffixes)

	for _, group := range data.Groups {
		if len(group.MemberOf) == 0 {
			continue
		}

		// Check if this is a protected group, by SID
		if !protectedDNs[strings.ToLower(group.DN)] {
			continue
		}

		// Check if it's nested in a non-protected group, by SID
		hasUnexpectedNesting := false
		for _, parentDN := range group.MemberOf {
			if !protectedDNs[strings.ToLower(parentDN)] {
				hasUnexpectedNesting = true
				break
			}
		}

		if hasUnexpectedNesting {
			affected = append(affected, group)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Dangerous Group Nesting",
		Description: "Sensitive group nested in less sensitive group. Unintended privilege escalation path.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDangerousNestingDetector())
}
