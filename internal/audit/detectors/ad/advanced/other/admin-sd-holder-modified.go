package other

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// AdminSdHolderModifiedDetector detects modified AdminSDHolder permissions
type AdminSdHolderModifiedDetector struct {
	audit.BaseDetector
}

// NewAdminSdHolderModifiedDetector creates a new detector
func NewAdminSdHolderModifiedDetector() *AdminSdHolderModifiedDetector {
	return &AdminSdHolderModifiedDetector{
		BaseDetector: audit.NewBaseDetector("ADMIN_SD_HOLDER_MODIFIED", audit.CategoryAdvanced),
	}
}

// Attribute/property-set GUIDs referenced by the AdminSDHolder default DACL
// (see adminSDHolderWhitelist below for the sources).
const (
	// guidPrivateInformation is the Private-Information property set
	// (learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/
	// 1522b774-6464-41a3-87a5-1e5633c3fbbb, Appendix: Control Access Rights).
	guidPrivateInformation = "91e647de-d96f-4b70-9557-d63ff4f3ccd8"
	// guidTerminalServer is the terminalServer attribute.
	guidTerminalServer = "5805bc62-bdc9-4428-a5e2-856a0f4c185e"
	// guidTerminalServerPropertySet is the Terminal-Server property set that
	// also carries the terminalServer attribute's WriteProperty grant on some
	// schema versions.
	guidTerminalServerPropertySet = "6db69a1c-9422-11d1-aebd-0000f80367c1"
	// guidUserCertificate is the userCertificate attribute.
	guidUserCertificate = "bf967a7f-0de6-11d0-a285-00aa003049e2"
)

// adminSDHolderWhitelistEntry describes one principal's legitimate default
// grant on AdminSDHolder. When objectTypes is empty the SID's grant is
// whitelisted regardless of ObjectType or AccessMask (a whole-object default,
// e.g. Domain Admins' full control). When objectTypes is non-empty, the ACE
// is only whitelisted if its ObjectType matches one of them AND its
// AccessMask is a subset of allowedMask - an OA ACE scoped to one attribute
// or property set never justifies a wider grant.
type adminSDHolderWhitelistEntry struct {
	sid         string
	objectTypes []string
	allowedMask int
}

// adminSDHolderWhitelist returns the sourced default DACL entries for
// AdminSDHolder.
//
// Source: Microsoft's own published default DACL for the AdminSDHolder object
// - "Appendix K: Default Settings in the Master Security Descriptor of the
// AdminSDHolder Object" (learn.microsoft.com/en-us/previous-versions/windows/
// it-pro/windows-server-2003/cc772684(v=ws.10)) for the whole-object grants
// to Domain Admins, Enterprise Admins, Administrators and SYSTEM, and for
// Cert Publishers' attribute-scoped grant
// "(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CP)": ReadProperty+
// WriteProperty (mask 0x30) scoped to the userCertificate attribute only -
// not the whole object. Plus the adprep /domainprep schema operations that
// extended that DACL:
//   - Operation 59 (learn.microsoft.com/en-us/previous-versions/windows/
//     it-pro/windows-server-2008-r2-and-2008/cc770385(v=ws.10), Windows
//     Server 2008 adprep) adds
//     "(OA;CI;CRRPWP;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)": SELF
//     (S-1-5-10) gets ControlAccess+ReadProperty+WriteProperty (mask 0x130)
//     scoped to the Private-Information property set only. Any domain that
//     has run this adprep step carries this ACE at rest, which this detector
//     previously flagged as "Modified".
//   - Operation 61 (same page) adds
//     "(OA;;WPRP;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)": Terminal
//     Server License Servers gets ReadProperty+WriteProperty (mask 0x30)
//     scoped to the terminalServer attribute (also recognized under the
//     Terminal-Server property set GUID on some schema versions) - not the
//     whole object.
//
// Schema Admins (-518) and Account Operators (S-1-5-32-548) are NOT
// whitelisted: neither Appendix K nor any adprep /domainprep operation
// (2008 through the current Server Annual Channel) grants either principal
// any right on AdminSDHolder, so no source justifies the exception.
func adminSDHolderWhitelist(domainSID string) []adminSDHolderWhitelistEntry {
	return []adminSDHolderWhitelistEntry{
		{sid: domainSID + "-512"}, // Domain Admins - whole-object default
		{sid: domainSID + "-519"}, // Enterprise Admins - whole-object default
		{sid: "S-1-5-32-544"},     // Administrators - whole-object default
		{sid: "S-1-5-18"},         // SYSTEM - whole-object default
		{
			// Cert Publishers: Appendix K, userCertificate attribute only.
			sid:         domainSID + "-517",
			objectTypes: []string{guidUserCertificate},
			allowedMask: types.MaskReadProperty | types.MaskWriteProperty, // 0x30
		},
		{
			// SELF: operation 59, Private-Information property set only.
			sid:         "S-1-5-10",
			objectTypes: []string{guidPrivateInformation},
			allowedMask: types.MaskControlAccess | types.MaskReadProperty | types.MaskWriteProperty, // 0x130
		},
		{
			// Terminal Server License Servers: operation 61, terminalServer
			// attribute (or its property set) only.
			sid:         "S-1-5-32-561",
			objectTypes: []string{guidTerminalServer, guidTerminalServerPropertySet},
			allowedMask: types.MaskReadProperty | types.MaskWriteProperty, // 0x30
		},
	}
}

// isWhitelistedAdminSDHolderACE checks whether acl is a sourced default grant
// on AdminSDHolder for the given domain, per adminSDHolderWhitelist.
func isWhitelistedAdminSDHolderACE(acl types.ACLEntry, domainSID string) bool {
	for _, entry := range adminSDHolderWhitelist(domainSID) {
		if entry.sid != acl.Trustee {
			continue
		}
		if len(entry.objectTypes) == 0 {
			return true
		}
		for _, objectType := range entry.objectTypes {
			if strings.EqualFold(acl.ObjectType, objectType) && acl.AccessMask&^entry.allowedMask == 0 {
				return true
			}
		}
	}
	return false
}

// isAdminSDHolderObject checks if dn is exactly the AdminSDHolder object for
// domainDN (CN=AdminSDHolder,CN=System,<domain DN>), case-insensitively. An
// exact match avoids treating a look-alike object (e.g. one named
// AdminSDHolder under an OU) as the real one, which a substring test would.
func isAdminSDHolderObject(dn, domainDN string) bool {
	if domainDN == "" {
		return false
	}
	return strings.EqualFold(dn, "CN=AdminSDHolder,CN=System,"+domainDN)
}

// dangerousMask mirrors the sibling permission-family detectors (schema-permissions.go,
// dpapi-key-acl.go): only ACEs granting actual write-level control are a real SDProp
// propagation risk. This detector never read AccessMask at all before this fix
// (motif(b), same signature as the other grant-check bugs), so ANY allow ACE from a non-default SID -
// even a read-only grant - flagged HIGH severity indiscriminately.
const dangerousMask = types.MaskGenericAll | types.MaskWriteDACL | types.MaskWriteOwner | types.MaskWriteProperty

// Detect executes the detection
func (d *AdminSdHolderModifiedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if data.DomainInfo == nil {
		finding := types.Finding{
			Type:        d.ID(),
			Severity:    types.SeverityHigh,
			Category:    string(d.Category()),
			Title:       "AdminSDHolder Review Required",
			Description: "AdminSDHolder permissions should be reviewed. Modifications propagate to all protected accounts (Domain Admins, Enterprise Admins, etc.) via SDProp process.",
			Count:       0,
			Details: map[string]interface{}{
				"note": "Domain information not available for analysis.",
			},
		}
		return []types.Finding{finding}
	}

	domainSID := data.DomainInfo.DomainSID
	domainDN := data.DomainInfo.DomainDN
	seen := make(map[string]bool)
	var nonStandardACEs []types.ACLEntry

	// Check ACL entries for AdminSDHolder object
	for _, acl := range data.ACLEntries {
		// Check if this is the AdminSDHolder object
		if !isAdminSDHolderObject(acl.ObjectDN, domainDN) {
			continue
		}

		// Skip deny ACEs for this analysis. This used to compare
		// against the literal string "deny", which real AceType values
		// (aceTypeToString, acl_parser.go: "ACCESS_DENIED", "ACCESS_DENIED_OBJECT", …)
		// never equal - the filter was a silent no-op, letting every deny ACE
		// through as if it were a grant. audit.IsGrantACE is the established
		// substring-based check every sibling permission detector already uses.
		if !audit.IsGrantACE(acl.AceType) {
			continue
		}

		// Only ACEs granting a dangerous (write-level) right are a real
		// SDProp propagation risk - a read-only grant is noise, not a
		// modification (this mask test was missing before).
		if (acl.AccessMask & dangerousMask) == 0 {
			continue
		}

		// Check if this is a non-default SID with permissions
		trusteeSID := acl.Trustee
		if !isWhitelistedAdminSDHolderACE(acl, domainSID) {
			key := trusteeSID + ":" + acl.ObjectDN
			if seen[key] {
				continue
			}
			seen[key] = true
			nonStandardACEs = append(nonStandardACEs, acl)
		}
	}

	count := 0
	if len(nonStandardACEs) > 0 {
		count = 1 // Report as a single finding since it's one object
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "AdminSDHolder Modified",
		Description: "AdminSDHolder contains non-standard permissions. These modifications propagate to all protected accounts (Domain Admins, Enterprise Admins, etc.) via the SDProp process.",
		Count:       count,
	}

	if data.IncludeDetails && len(nonStandardACEs) > 0 {
		entities := make([]types.AffectedEntity, 0, len(nonStandardACEs))
		for _, ace := range nonStandardACEs {
			ent := audit.ACLEntryToAffectedEntity(ace, data.ObjectByDN, data.ObjectBySID)
			if ent.Type == "" {
				continue // unknown right - skip
			}
			entities = append(entities, ent)
		}
		finding.AffectedEntities = entities
		finding.Details = map[string]interface{}{
			"recommendation": "Review AdminSDHolder ACL and remove any non-standard principals. Only default admin groups should have permissions.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminSdHolderModifiedDetector())
}
