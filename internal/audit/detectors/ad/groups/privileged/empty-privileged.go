package privileged

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// EmptyPrivilegedDetector checks for empty privileged groups
type EmptyPrivilegedDetector struct {
	audit.BaseDetector
}

// NewEmptyPrivilegedDetector creates a new detector
func NewEmptyPrivilegedDetector() *EmptyPrivilegedDetector {
	return &EmptyPrivilegedDetector{
		BaseDetector: audit.NewBaseDetector("GROUP_EMPTY_PRIVILEGED", audit.CategoryGroups),
	}
}

// emptyPrivilegedSIDSuffixes matches nine of the ten groups this detector
// tracks by their fixed, well-known RID (Microsoft Learn, "Security
// identifiers", learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers),
// not by their English name: the previous strings.EqualFold(name, pg) /
// strings.Contains(group.DistinguishedName, "cn="+pg) match was blind on a
// localized forest (the name differs per language), false-positived on any
// homonym group whose name merely equaled the same English text, and
// additionally read DistinguishedName - an "alias for DN" field the LDAP
// parser never populates - so the substring half never fired on real data.
var emptyPrivilegedSIDSuffixes = []string{
	"-512", // Domain Admins
	"-519", // Enterprise Admins
	"-518", // Schema Admins
	"-544", // Administrators
	"-548", // Account Operators
	"-549", // Server Operators
	"-551", // Backup Operators
	"-550", // Print Operators
	"-520", // Group Policy Creator Owners
}

// emptyPrivilegedNamedGroups holds DnsAdmins only: unlike the nine groups
// above, DnsAdmins is created by the DNS Server role installation with a
// RID assigned at install time, not a fixed forest-wide well-known RID, so
// it has no SID that can be hardcoded here without being wrong on some
// forests. It stays matched by exact, case-insensitive name - no substring
// fallback.
var emptyPrivilegedNamedGroups = []string{"DnsAdmins"}

// Detect executes the detection
func (d *EmptyPrivilegedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Group
	var affectedNames []string

	privilegedDNs := privgroups.DNsBySIDSuffix(data, emptyPrivilegedSIDSuffixes)

	for _, group := range data.Groups {
		name := group.SAMAccountName
		if name == "" {
			name = group.DisplayName
		}

		// Check if it's a privileged group: by SID for the nine groups with
		// a well-known RID, by exact name for DnsAdmins (no fixed RID).
		isPrivileged := privilegedDNs[strings.ToLower(group.DN)]
		if !isPrivileged {
			for _, pg := range emptyPrivilegedNamedGroups {
				if strings.EqualFold(name, pg) {
					isPrivileged = true
					break
				}
			}
		}
		if !isPrivileged {
			continue
		}

		// Check if group is empty
		if len(group.Member) == 0 {
			affected = append(affected, group)
			affectedNames = append(affectedNames, name)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Empty Privileged Group",
		Description: "Privileged groups with no members. While not a vulnerability, empty admin groups may indicate misconfiguration or unused infrastructure.",
		Count:       len(affected),
	}

	if len(affected) > 0 {
		if data.IncludeDetails {
			finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
		}
		finding.Details = map[string]interface{}{
			"groups":         affectedNames,
			"recommendation": "Document intentionally empty groups or remove if unused.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewEmptyPrivilegedDetector())
}
