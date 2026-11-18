package moderate

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// AdminSDHolderBackdoorDetector detects unexpected ACL on AdminSDHolder object
type AdminSDHolderBackdoorDetector struct {
	audit.BaseDetector
}

// NewAdminSDHolderBackdoorDetector creates a new detector
func NewAdminSDHolderBackdoorDetector() *AdminSDHolderBackdoorDetector {
	return &AdminSDHolderBackdoorDetector{
		BaseDetector: audit.NewBaseDetector("ADMINSDHOLDER_BACKDOOR", audit.CategoryPermissions),
	}
}

// adminSDHolderWriteOrControlMask is the set of access bits that constitute
// an actual write/control capability on AdminSDHolder - as opposed to mere
// read access. Only an ACE granting at least one of these bits represents a
// persistence backdoor; a read-only grant does not.
const adminSDHolderWriteOrControlMask = types.MaskGenericAll | types.MaskGenericWrite |
	types.MaskWriteDACL | types.MaskWriteOwner | types.MaskWriteProperty |
	types.MaskSelf | types.MaskControlAccess

// adminSDHolderBaselineACE identifies one default, documented ACE on
// AdminSDHolder's default security descriptor that is not itself a backdoor:
// same trustee (either an exact well-known SID, or a domain-relative group
// matched by its RID suffix, since a domain group's SID is not a fixed
// constant across forests), same ObjectType (empty when the ACE is not
// property/right scoped), same write/control bits already recognized by this
// detector.
type adminSDHolderBaselineACE struct {
	trusteeSID    string // exact match, lowercase, for a well-known/forest-wide SID
	trusteeSuffix string // "-<RID>" suffix match, lowercase, for a domain-relative group
	objectType    string
	mask          int
}

// adminSDHolderDefaultACEs lists the non-builtin-admin, write-or-control ACEs
// present on AdminSDHolder's DEFAULT security descriptor on any unmodified AD
// domain (Microsoft Learn, "Security Descriptor Reference", Appendix K:
// learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772684(v=ws.10)).
// Trustees that are read-only by default (Authenticated Users, Pre-Windows
// 2000 Compatible Access, Windows Authorization Access Group) are already
// excluded by adminSDHolderWriteOrControlMask above and do not need an entry
// here; only the default ACEs that DO carry a write/control bit are listed,
// so the detector does not flag Windows' own baseline as a backdoor.
var adminSDHolderDefaultACEs = []adminSDHolderBaselineACE{
	// Everyone (S-1-1-0): Change Password - CONTROL_ACCESS extended right
	// ab721a53-1e2f-11d0-9819-00aa0040529b, Appendix K "(OA;;CR;ab721a53-...;;WD)".
	{trusteeSID: "s-1-1-0", objectType: "ab721a53-1e2f-11d0-9819-00aa0040529b", mask: types.MaskControlAccess},
	// Cert Publishers: well-known RID 517, domain-relative SID (not in
	// PrivilegedSIDSuffixes) - Write user-cert, WriteProperty on userCert,
	// bf967a7f-0de6-11d0-a285-00aa003049e2, Appendix K "(OA;;RPWP;bf967a7f-...;;CA)".
	// Legitimate certificate enrollment, not a backdoor.
	{trusteeSuffix: "-517", objectType: "bf967a7f-0de6-11d0-a285-00aa003049e2", mask: types.MaskWriteProperty},
	// Terminal Server License Servers (S-1-5-32-561, builtin alias, forest-wide
	// constant): Write terminalServer* property set, Appendix K
	// "(OA;;WPRP;...;;S-1-5-32-561)".
	{trusteeSID: "s-1-5-32-561", mask: types.MaskWriteProperty},
}

func isAdminSDHolderDefaultACE(ace types.ACLEntry) bool {
	trustee := strings.ToLower(ace.Trustee)
	objectType := strings.ToLower(ace.ObjectType)
	for _, baseline := range adminSDHolderDefaultACEs {
		switch {
		case baseline.trusteeSID != "":
			if trustee != baseline.trusteeSID {
				continue
			}
		case baseline.trusteeSuffix != "":
			if !strings.HasSuffix(trustee, baseline.trusteeSuffix) {
				continue
			}
		default:
			continue
		}
		if baseline.objectType != "" && objectType != baseline.objectType {
			continue
		}
		if ace.AccessMask&baseline.mask != 0 {
			return true
		}
	}
	return false
}

// Detect executes the detection
func (d *AdminSDHolderBackdoorDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		if !strings.Contains(strings.ToLower(ace.ObjectDN), "cn=adminsdholder,cn=system") {
			continue
		}
		// A DENY ace grants nothing, and built-in admins hold full
		// control on AdminSDHolder by construction (SDProp baseline) - not
		// a finding, same pattern as writeowner.go / genericall.go.
		if !audit.IsGrantACE(ace.AceType) {
			continue
		}
		if audit.IsBuiltinAdminTrustee(ace.Trustee) {
			continue
		}
		// A read-only grant (ReadProperty, ListChildren, ReadControl, ...)
		// is not a persistence backdoor: only a write or control-access bit
		// is.
		if ace.AccessMask&adminSDHolderWriteOrControlMask == 0 {
			continue
		}
		// Documented default ACEs (Appendix K) describe AD's own baseline,
		// not an attacker-added backdoor.
		if isAdminSDHolderDefaultACE(ace) {
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
		Title:       "AdminSDHolder Backdoor",
		Description: "Unexpected ACL on AdminSDHolder object. Persistent permissions on admin accounts.",
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
	audit.MustRegister(NewAdminSDHolderBackdoorDetector())
}
