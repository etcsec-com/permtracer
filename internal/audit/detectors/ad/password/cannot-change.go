package password

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// CannotChangeDetector detects active accounts forbidden from changing
// their own password. Scoped to active accounts: see
// CannotChangeOnDisabledAccountDetector for the disabled-account population,
// reported separately at Low because the ACE restricts self-service rather
// than granting anything, and is dormant until the account is re-enabled.
type CannotChangeDetector struct {
	audit.BaseDetector
}

// NewCannotChangeDetector creates a new detector
func NewCannotChangeDetector() *CannotChangeDetector {
	return &CannotChangeDetector{
		BaseDetector: audit.NewBaseDetector("USER_CANNOT_CHANGE_PASSWORD", audit.CategoryPassword),
	}
}

// Trustees whose Deny ACE on the Change-Password extended right blocks an
// account from changing its own password. Everyone (S-1-1-0) is present in
// every access token, including the one built for the account's own
// self-change bind; NT AUTHORITY\SELF (S-1-5-10) is the placeholder that
// resolves to the object the ACE sits on. Either one alone is sufficient:
// see the Detect doc comment below for why this detector requires only one,
// not both.
const (
	sidEveryone = "S-1-1-0"
	sidSelf     = "S-1-5-10"
)

// blockedChangePasswordDNs returns the set of lowercased object DNs carrying
// a Deny ACE for Everyone or NT AUTHORITY\SELF on the User-Change-Password
// extended right, deduplicated by ObjectDN (see the Detect doc comment below
// for why one Deny ACE from either trustee is sufficient, and why an account
// carrying both still counts once). Shared by CannotChangeDetector and
// CannotChangeOnDisabledAccountDetector so the firing condition is defined
// in exactly one place.
func blockedChangePasswordDNs(entries []types.ACLEntry) map[string]bool {
	blocked := make(map[string]bool, len(entries))
	for _, ace := range entries {
		if ace.ObjectType == "" || !strings.EqualFold(ace.ObjectType, types.GUIDChangePassword) {
			continue
		}
		if !strings.Contains(strings.ToUpper(ace.AceType), "DENIED") {
			continue // ACCESS_ALLOWED[_OBJECT] grants the right; it doesn't restrict it
		}
		if ace.Trustee != sidEveryone && ace.Trustee != sidSelf {
			continue
		}
		blocked[strings.ToLower(ace.ObjectDN)] = true
	}
	return blocked
}

// usersBlockedFromChangingPassword resolves blockedChangePasswordDNs against
// data.Users and keeps only those whose Disabled state matches disabled.
// Walking data.Users (rather than the blocked-DN set) to do that join means
// an ObjectDN with a Deny ACE that does not match any known user is counted
// by neither this detector nor its disabled-account twin: there is no user
// record to read a Disabled state from, so it cannot be attributed to either
// population.
func usersBlockedFromChangingPassword(data *audit.DetectorData, disabled bool) []types.User {
	blockedDNs := blockedChangePasswordDNs(data.ACLEntries)

	var affected []types.User
	for _, u := range data.Users {
		if u.Disabled != disabled {
			continue
		}
		if blockedDNs[strings.ToLower(u.DN)] {
			affected = append(affected, u)
		}
	}
	return affected
}

// Detect executes the detection.
//
// (userAccountControl & 0x0040) can never be true on a real LDAP read
// (ADS_UF_PASSWD_CANT_CHANGE only ever existed on the legacy SAM-backed
// WinNT provider) - established by plant/revert on DC01, full measurements
// in VERDICT.md. The real, documented representation of the
// state is two Deny ACEs on the User-Change-Password extended right
// (types.GUIDChangePassword, {AB721A53-1E2F-11D0-9819-00AA0040529B}, read
// from CN=Extended-Rights of the lab forest, not retyped - see VERDICT.md),
// one for Everyone (S-1-1-0) and one for NT AUTHORITY\SELF (S-1-5-10), in
// the object's own DACL - exactly the ACE shape data.ACLEntries already
// carries for every user (engine.go passes every user DN to GetACLs).
//
// PROVEN: the GUID above is correct at the source; AceType for a denied
// object ACE is literally "ACCESS_DENIED_OBJECT" (acl_parser.go's
// aceTypeToString, case aceTypeAccessDeniedObject) and Trustee arrives as a
// raw SID string, e.g. "S-1-1-0" (parseSID), never a resolved name - both
// established by reading the parser, not assumed. The condition below
// requires only ONE of the two documented trustees to be denied, not both:
// under the standard Windows ACL evaluation algorithm (MS-DTYP 2.5.3),
// explicit Deny ACEs are evaluated before Allow ACEs for a matching SID in
// the requester's token, and Everyone is a member of every token including
// the account's own self-change bind - so a Deny on Everyone alone already
// blocks self-change, independently of whatever the SELF entry says, and
// vice versa. ADUC's "User cannot change password" checkbox always flips
// both together, but nothing in the access-check requires both to be
// present for the effect to hold, so OR is the correct - not merely
// convenient - condition. Counting groups by ObjectDN, not by ACE: an
// account carries two matching ACEs (Everyone + Self) when planted through
// the documented mechanism, and must count as one affected account, not two.
//
// internal/providers/ldap/acl_parser.go's parseACE keeps ACCESS_DENIED and
// ACCESS_DENIED_OBJECT ACEs (aceTypeToString maps both), so the Deny ACEs
// this detector looks for do reach data.ACLEntries from a real collector
// run.
func (d *CannotChangeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	affected := usersBlockedFromChangingPassword(data, false)

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityMedium,
		Category: string(d.Category()),
		Title:    "User Cannot Change Password",
		Description: "Active user accounts denied the User-Change-Password extended right for Everyone or " +
			"NT AUTHORITY\\SELF, preventing self-service password rotation. Detects the real AD DS " +
			"representation (Deny ACEs on the Change-Password extended right); does not depend on the " +
			"userAccountControl bit, which real AD DS never sets over LDAP.",
		Count: len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewCannotChangeDetector())
}
