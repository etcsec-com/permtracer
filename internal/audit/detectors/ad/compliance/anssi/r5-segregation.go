package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// R5SegregationDetector checks ANSSI PA-099 R7/R8 Tier segregation
// compliance. Name/ID kept as "R5" for backward compatibility (frozen by
// internal/audit/compliance/mappings.go, out of scope here),
// which already tags this detector's real controls as PA-099 R7 + R8 - R5 in
// PA-099 is "Identifier les valeurs métiers du Tier 1", unrelated to account
// segregation. R8 ("Cloisonner l'administration de chaque Tier", p.24-25)
// requires dedicated accounts per trust zone so that no account creates an
// attack path from one Tier to another of lower sensitivity; a single
// account holding membership in two different privileged-Tier groups
// (Domain Admins + Schema Admins, say) is exactly that path. R7
// ("Catégoriser les ressources du SI en Tiers") is the categorization
// prerequisite R8 builds on.
type R5SegregationDetector struct {
	audit.BaseDetector
}

// NewR5SegregationDetector creates a new detector
func NewR5SegregationDetector() *R5SegregationDetector {
	return &R5SegregationDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R5_SEGREGATION", audit.CategoryCompliance),
	}
}

// privilegedTierSIDSuffixes are the four privileged-Tier groups R8 asks to
// keep segregated, identified by their fixed, well-known RID (Microsoft
// Learn "Security identifiers") instead of an English CN substring match -
// the same fix DANGEROUS_GROUP_NESTING applies
// (groups/nesting/dangerous-nesting.go): a CN-substring match is blind on a
// localized forest (the CN differs per language) and false-positives on any
// homonym group whose CN merely contains the same English text.
var privilegedTierSIDSuffixes = []string{
	"-512", // Domain Admins
	"-519", // Enterprise Admins
	"-518", // Schema Admins
	"-548", // Account Operators
}

// backupOperatorsSIDSuffix identifies Backup Operators the same way.
var backupOperatorsSIDSuffix = []string{"-551"}

const (
	everyoneSID           = "S-1-1-0"
	authenticatedUsersSID = "S-1-5-11"
)

// Detect executes the detection
func (d *R5SegregationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var issues []string

	backupOpsDNs := privgroups.DNsBySIDSuffix(data, backupOperatorsSIDSuffix)

	// Backup Operators is a domain-local Builtin group: a special principal
	// (Everyone/Authenticated Users) can be a member of it without that
	// membership EVER appearing in any real user's memberOf (Windows
	// computes it at logon, it never writes a back-link on a user object).
	// Without this, the loop below is structurally blind to that case no
	// matter the real state of the domain (R5/NIST_AC_6 confrontation).
	backupOpsOpenToAll := groupOpenToSpecialPrincipal(data.Groups, backupOpsDNs)

	// privilegedTierDNSets holds one DN set per privileged-Tier group, so
	// each group is counted at most once per user - the same count as
	// before, where at most one memberOf entry per group matched its
	// substring.
	privilegedTierDNSets := make([]map[string]bool, len(privilegedTierSIDSuffixes))
	for i, suffix := range privilegedTierSIDSuffixes {
		privilegedTierDNSets[i] = privgroups.DNsBySIDSuffix(data, []string{suffix})
	}

	// Check for users in multiple privileged groups (no segregation)
	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}

		privilegedGroupCount := 0
		hasBackupOps := backupOpsOpenToAll
		for _, dns := range privilegedTierDNSets {
			if privgroups.IsMemberOfAny(u.MemberOf, dns) {
				privilegedGroupCount++
			}
		}
		if privgroups.IsMemberOfAny(u.MemberOf, backupOpsDNs) {
			hasBackupOps = true
		}
		if hasBackupOps {
			privilegedGroupCount++
		}

		if privilegedGroupCount > 1 {
			issues = append(issues, "Users in multiple privileged groups (no segregation)")
			break
		}
	}

	// A second check used to flag "standard users with admin
	// privileges" as users with AdminCount=true and no SPN, threshold >20.
	// Removed - it was self-contradictory (adminCount=true is set by the
	// adminSDHolder mechanism precisely BECAUSE the account is/was a member
	// of a protected/privileged group; PA-099 p.40 footnote 16 confirms this
	// explicitly), so it mislabeled privileged accounts as "standard users",
	// and the >20 threshold had no source (ANSSI or otherwise). No
	// replacement is substituted: retiring an unfounded, internally
	// inconsistent check rather than inventing a new one.

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "ANSSI PA-099 R7/R8 - Tier Segregation Non-Compliant",
		Description: "Privilege segregation does not meet ANSSI PA-099 R8 (\"Cloisonner l'administration de chaque Tier\", p.24-25): accounts, admin workstations and methods must not create attack paths from one Tier to a less sensitive one. A single account holding multiple privileged-Tier group memberships is such a path.",
		Count:       0,
	}

	if len(issues) > 0 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"violations": issues,
			"framework":  "ANSSI-PA-099",
			"control":    "R7/R8",
		}
	}

	return []types.Finding{finding}
}

// groupOpenToSpecialPrincipal reports whether any group whose DN is in
// groupDNs (as produced by privgroups.DNsBySIDSuffix) has Everyone
// (S-1-1-0) or Authenticated Users (S-1-5-11) as a raw LDAP member, matched
// by exact SID rather than a name or SID substring - the same match used by
// GROUP_EVERYONE_IN_PRIVILEGED / GROUP_AUTHENTICATED_USERS_PRIVILEGED
// (groups/privileged package) to spot this exact pattern, except exact
// instead of substring: a substring match on the SID would wrongly treat
// S-1-5-110 (an unrelated, longer SID) as Authenticated Users (S-1-5-11).
func groupOpenToSpecialPrincipal(groups []types.Group, groupDNs map[string]bool) bool {
	for _, g := range groups {
		if !groupDNs[strings.ToLower(g.DN)] {
			continue
		}
		for _, m := range g.Members {
			sid := memberSID(m)
			if strings.EqualFold(sid, everyoneSID) || strings.EqualFold(sid, authenticatedUsersSID) {
				return true
			}
		}
	}
	return false
}

// memberSID extracts the SID value from a raw LDAP member DN of the form
// "CN=<SID>,CN=ForeignSecurityPrincipals,DC=..." (how AD renders a foreign
// security principal such as Everyone/Authenticated Users as a group
// member), or returns the member string unchanged if it carries no leading
// "attr=" component.
func memberSID(member string) string {
	first := member
	if idx := strings.IndexByte(member, ','); idx >= 0 {
		first = member[:idx]
	}
	if idx := strings.IndexByte(first, '='); idx >= 0 {
		return strings.TrimSpace(first[idx+1:])
	}
	return strings.TrimSpace(first)
}

func init() {
	audit.MustRegister(NewR5SegregationDetector())
}
