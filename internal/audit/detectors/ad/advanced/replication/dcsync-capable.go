package replication

import (
	"context"
	"sort"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// DcsyncCapableDetector detects accounts capable of DCSync. Trustees that
// resolve to a DISABLED user or computer account are reported separately,
// at Medium, by DcsyncCapableOnDisabledAccountDetector
// (dcsync-capable-on-disabled-account.go) - see
// docs/security-validation/split/dcsync-capable/SPLIT.md. A trustee that
// resolves to a group, or a SID that resolves to neither a user nor a
// computer, is never routed to the twin and stays counted here.
type DcsyncCapableDetector struct {
	audit.BaseDetector
}

// NewDcsyncCapableDetector creates a new detector
func NewDcsyncCapableDetector() *DcsyncCapableDetector {
	return &DcsyncCapableDetector{
		BaseDetector: audit.NewBaseDetector("DCSYNC_CAPABLE", audit.CategoryAdvanced),
	}
}

// DCSync replication right GUIDs
const (
	DSReplicationGetChanges    = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
	DSReplicationGetChangesAll = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
)

// isAdminSID checks if a SID is a well-known admin SID that should have DCSync rights
func isAdminSID(sid, domainSID string) bool {
	adminSIDs := []string{
		domainSID + "-512", // Domain Admins
		domainSID + "-519", // Enterprise Admins
		domainSID + "-518", // Schema Admins
		"S-1-5-32-544",     // Administrators
		"S-1-5-18",         // SYSTEM
		"S-1-5-32-548",     // Account Operators
	}

	for _, adminSID := range adminSIDs {
		if sid == adminSID {
			return true
		}
	}
	return false
}

// isDCSyncGUID checks if the ObjectType GUID is a DCSync replication right
func isDCSyncGUID(guid string) bool {
	guidLower := strings.ToLower(guid)
	return guidLower == strings.ToLower(DSReplicationGetChanges) ||
		guidLower == strings.ToLower(DSReplicationGetChangesAll)
}

// dcsyncCapableTrustees scans data.ACLEntries for grant ACEs on the domain
// root and returns, sorted by SID, every non-admin trustee (acl.Trustee) that
// holds BOTH DS-Replication-Get-Changes AND DS-Replication-Get-Changes-All -
// the pair actually required to perform DCSync. isAdminSID is applied here,
// before the active/disabled split, so an admin SID never appears in either
// half of it. Shared by DcsyncCapableDetector and
// DcsyncCapableOnDisabledAccountDetector so both detectors start from
// exactly the same candidate population; each then applies its own
// resolveTrusteeDisabledState filter.
func dcsyncCapableTrustees(data *audit.DetectorData) []string {
	if data.DomainInfo == nil {
		return nil
	}

	domainSID := data.DomainInfo.DomainSID
	domainDN := data.DomainInfo.DomainDN

	dcsyncTrustees := make(map[string]map[string]bool) // trustee -> set of replication GUIDs

	for _, acl := range data.ACLEntries {
		if !strings.EqualFold(acl.ObjectDN, domainDN) {
			continue
		}

		// Skip deny ACEs. This used to compare AceType to the literal "deny",
		// but acl_parser.go emits Windows-style values (ACCESS_ALLOWED,
		// ACCESS_DENIED, ACCESS_ALLOWED_OBJECT, ACCESS_DENIED_OBJECT,
		// SYSTEM_AUDIT…), so the guard could never be true - dead code that
		// would have counted a DENY DCSync ace as a grant (DET_10).
		if !audit.IsGrantACE(acl.AceType) {
			continue
		}

		if !isDCSyncGUID(acl.ObjectType) {
			continue
		}

		trusteeSID := acl.Trustee
		if isAdminSID(trusteeSID, domainSID) {
			continue
		}

		if dcsyncTrustees[trusteeSID] == nil {
			dcsyncTrustees[trusteeSID] = make(map[string]bool)
		}
		dcsyncTrustees[trusteeSID][strings.ToLower(acl.ObjectType)] = true
	}

	var dcsyncCapable []string
	for trustee, rights := range dcsyncTrustees {
		hasGetChanges := rights[strings.ToLower(DSReplicationGetChanges)]
		hasGetChangesAll := rights[strings.ToLower(DSReplicationGetChangesAll)]

		if hasGetChanges && hasGetChangesAll {
			dcsyncCapable = append(dcsyncCapable, trustee)
		}
	}

	// dcsyncTrustees is a map, so the range above visits trustees in a
	// randomized order - sort before returning so both callers (and their
	// entity emission order) are deterministic regardless of resolution.
	sort.Strings(dcsyncCapable)
	return dcsyncCapable
}

// resolveTrusteeDisabledState resolves a trustee SID to a user or computer
// account by an exact ObjectSID match against data.Users / data.Computers,
// and reports whether it was resolved and, if so, whether that account is
// Disabled. A trustee that resolves to neither (a group SID, or a SID the
// collector never saw) returns resolved=false - callers must keep such a
// trustee on the active side, never drop it from both halves of the split.
// Shared by DcsyncCapableDetector and DcsyncCapableOnDisabledAccountDetector
// so a trustee's account state is decided identically by both halves.
func resolveTrusteeDisabledState(trustee string, data *audit.DetectorData) (resolved, disabled bool) {
	if trustee == "" {
		return false, false
	}
	for i := range data.Users {
		if data.Users[i].ObjectSID != "" && data.Users[i].ObjectSID == trustee {
			return true, data.Users[i].Disabled
		}
	}
	for i := range data.Computers {
		if data.Computers[i].ObjectSID != "" && data.Computers[i].ObjectSID == trustee {
			return true, data.Computers[i].Disabled
		}
	}
	return false, false
}

// Detect executes the detection
func (d *DcsyncCapableDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if data.DomainInfo == nil {
		finding := types.Finding{
			Type:        d.ID(),
			Severity:    types.SeverityHigh,
			Category:    string(d.Category()),
			Title:       "DCSync Capable",
			Description: "Account with DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights. Can extract all password hashes.",
			Count:       0,
			Details: map[string]interface{}{
				"note": "Domain information not available for analysis.",
			},
		}
		return []types.Finding{finding}
	}

	candidates := dcsyncCapableTrustees(data)

	// Exclude trustees that resolve to a disabled user or computer account:
	// reported separately, at Medium, by
	// DcsyncCapableOnDisabledAccountDetector. A trustee that resolves to a
	// group, or an unresolved SID, is never excluded here - resolved stays
	// false for both and the trustee is kept on the active side.
	var dcsyncCapable []string
	for _, trustee := range candidates {
		if resolved, isDisabled := resolveTrusteeDisabledState(trustee, data); resolved && isDisabled {
			continue
		}
		dcsyncCapable = append(dcsyncCapable, trustee)
	}

	var affectedEntities []types.AffectedEntity
	if data.IncludeDetails {
		for _, trustee := range dcsyncCapable {
			ent := audit.SIDToEntityWithCache(trustee, data)
			ent.Description = "Has DS-Replication-Get-Changes and DS-Replication-Get-Changes-All"
			affectedEntities = append(affectedEntities, ent)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "DCSync Capable",
		Description: "Principals with both DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights on the domain root. These accounts can perform DCSync attacks to extract all password hashes.",
		Count:       len(dcsyncCapable),
	}

	if data.IncludeDetails && len(affectedEntities) > 0 {
		finding.AffectedEntities = affectedEntities
		finding.Details = map[string]interface{}{
			"recommendation": "Remove DCSync replication rights from non-admin principals. Only Domain Controllers should have these rights.",
			"replicationRights": []string{
				"DS-Replication-Get-Changes (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)",
				"DS-Replication-Get-Changes-All (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)",
			},
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDcsyncCapableDetector())
}
