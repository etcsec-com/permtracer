package dangerous

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// DCSyncDetector detects DS-Replication-Get-Changes rights (DCSync capability)
type DCSyncDetector struct {
	audit.BaseDetector
}

// NewDCSyncDetector creates a new detector
func NewDCSyncDetector() *DCSyncDetector {
	return &DCSyncDetector{
		BaseDetector: audit.NewBaseDetector("ACL_DS_REPLICATION_GET_CHANGES", audit.CategoryPermissions),
	}
}

// dcsyncRightsHolder tracks, per trustee, which of the two rights required
// for DCSync have been granted by at least one ACE on the domain root.
// Mirrors replicaRightsHolder in accounts/advanced/replica-directory-changes.go,
// which this detector cannot import (forbidden file for this ticket) and so
// re-derives locally.
type dcsyncRightsHolder struct {
	getChanges    bool
	getChangesAll bool
	ace           types.ACLEntry
}

// Detect executes the detection
func (d *DCSyncDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// DS-Replication-Get-Changes: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
	// DS-Replication-Get-Changes-All: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
	getChangesGUID := strings.ToLower(types.GUIDDSReplicationGetChanges)
	getChangesAllGUID := strings.ToLower(types.GUIDDSReplicationGetChangesAll)

	var domainDN string
	if data.DomainInfo != nil {
		domainDN = strings.ToLower(data.DomainInfo.DomainDN)
		if domainDN == "" {
			domainDN = strings.ToLower(data.DomainInfo.DN)
		}
	}
	if domainDN == "" {
		return []types.Finding{d.finding(nil, data)}
	}

	held := make(map[string]*dcsyncRightsHolder)

	for _, ace := range data.ACLEntries {
		// Only the domain root carries DCSync's real-world semantics
		// (Applies-To: Domain-DNS); an ACE posed elsewhere grants nothing,
		// same restriction as the voisin REPLICA_DIRECTORY_CHANGES.
		if strings.ToLower(ace.ObjectDN) != domainDN {
			continue
		}
		// MS-ADTS 3.1: an INHERIT_ONLY ACE does not apply to the object it
		// is set on, only to descendants that inherit it.
		if ace.InheritOnly {
			continue
		}
		// A DENY ace grants nothing (DET_10).
		if !audit.IsGrantACE(ace.AceType) {
			continue
		}
		// SYSTEM, Domain/Enterprise Admins, BUILTIN\Administrators, Domain
		// Controllers and Enterprise Domain Controllers hold replication
		// rights on every domain by construction - a DC cannot replicate
		// without them. Reporting them describes AD's design, not a
		// misconfiguration.
		if audit.IsBuiltinAdminTrustee(ace.Trustee) {
			continue
		}

		var grantsGetChanges, grantsGetChangesAll bool
		switch {
		case ace.AccessMask&types.MaskGenericAll != 0:
			grantsGetChanges = true
			grantsGetChangesAll = true
		case ace.AccessMask&types.MaskControlAccess != 0:
			switch strings.ToLower(ace.ObjectType) {
			case "":
				grantsGetChanges = true
				grantsGetChangesAll = true
			case getChangesGUID:
				grantsGetChanges = true
			case getChangesAllGUID:
				grantsGetChangesAll = true
			}
		}
		if !grantsGetChanges && !grantsGetChangesAll {
			continue
		}

		r := held[ace.Trustee]
		if r == nil {
			r = &dcsyncRightsHolder{ace: ace}
			held[ace.Trustee] = r
		}
		r.getChanges = r.getChanges || grantsGetChanges
		r.getChangesAll = r.getChangesAll || grantsGetChangesAll
	}

	var affected []types.ACLEntry
	for _, r := range held {
		if r.getChanges && r.getChangesAll {
			affected = append(affected, r.ace)
		}
	}

	return []types.Finding{d.finding(affected, data)}
}

func (d *DCSyncDetector) finding(affected []types.ACLEntry, data *audit.DetectorData) types.Finding {
	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "DS-Replication-Get-Changes Rights (DCSync)",
		Description: "Non-standard principals with directory replication rights. Enables DCSync attacks to extract all password hashes from the domain.",
		Count:       len(uniqueObjects),
		Details: map[string]interface{}{
			"risk":           "Complete domain compromise through password hash extraction.",
			"recommendation": "Remove replication rights from all non-DC accounts.",
		},
	}

	if totalInstances != len(uniqueObjects) {
		finding.TotalInstances = totalInstances
	}

	if data.IncludeDetails && len(uniqueObjects) > 0 {
		finding.AffectedEntities = audit.GetUniqueObjectEntities(affected, data.ObjectByDN)
	}

	return finding
}

func init() {
	audit.MustRegister(NewDCSyncDetector())
}
