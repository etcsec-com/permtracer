package gmsa

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// GMSAPasswordReadersDetector enumerates non-privileged principals that can retrieve
// a gMSA managed password via the msDS-GroupMSAMembership security descriptor.
// Matches Purple Knight SI000083.
type GMSAPasswordReadersDetector struct {
	audit.BaseDetector
}

// NewGMSAPasswordReadersDetector creates a new detector.
func NewGMSAPasswordReadersDetector() *GMSAPasswordReadersDetector {
	return &GMSAPasswordReadersDetector{
		BaseDetector: audit.NewBaseDetector("GMSA_PASSWORD_READERS", audit.CategoryGroups),
	}
}

// gmsaReaderIndex holds the reader-resolution lookups built once per Detect
// call from data.Users/data.Groups/data.Computers, shared between
// GMSAPasswordReadersDetector and GMSAPasswordReadersOnDisabledAccountDetector
// so index construction and the non-privileged-reader condition (including
// the computer-reader fix) are not duplicated between the active detector
// and its disabled-account twin.
type gmsaReaderIndex struct {
	usersBySID     map[string]*types.User
	groupsBySID    map[string]*types.Group
	computersBySID map[string]*types.Computer
	computersByDN  map[string]*types.Computer
	groupsByDN     map[string]*types.Group
}

// buildGMSAReaderIndex indexes data.Users, data.Groups and data.Computers by
// ObjectSID (and, for groups/computers, by DN) for fast reader-privilege
// lookup and computer-only-group resolution.
func buildGMSAReaderIndex(data *audit.DetectorData) gmsaReaderIndex {
	idx := gmsaReaderIndex{
		usersBySID:     make(map[string]*types.User, len(data.Users)),
		groupsBySID:    make(map[string]*types.Group, len(data.Groups)),
		computersBySID: make(map[string]*types.Computer, len(data.Computers)),
		computersByDN:  make(map[string]*types.Computer, len(data.Computers)),
		groupsByDN:     make(map[string]*types.Group, len(data.Groups)),
	}
	for i := range data.Users {
		if sid := data.Users[i].ObjectSID; sid != "" {
			idx.usersBySID[sid] = &data.Users[i]
		}
	}
	for i := range data.Groups {
		g := &data.Groups[i]
		if g.ObjectSID != "" {
			idx.groupsBySID[g.ObjectSID] = g
		}
		if g.DN != "" {
			idx.groupsByDN[strings.ToLower(g.DN)] = g
		}
	}
	for i := range data.Computers {
		c := &data.Computers[i]
		if c.ObjectSID != "" {
			idx.computersBySID[c.ObjectSID] = c
		}
		if c.DN != "" {
			idx.computersByDN[strings.ToLower(c.DN)] = c
		}
	}
	return idx
}

// nonPrivilegedReaderPairs returns one "<reader> can read password of
// <gMSA>" pair per non-privileged principal allowed to retrieve u's managed
// password. A reader that is privileged (well-known SID, or resolves to a
// user/group with AdminCount), a computer account, or a group whose
// transitively resolved members are exclusively computer accounts, is
// excluded - the same condition for both the active detector and its
// disabled-account twin, so a privilege or scope fix made here applies to
// both without being copied.
func (idx gmsaReaderIndex) nonPrivilegedReaderPairs(u *types.User) []string {
	var pairs []string
	readers := audit.ParseRBCDTrustees(u.GMSAMembership)
	for _, sid := range readers {
		if audit.IsPrivilegedSID(sid) {
			continue
		}
		// Skip if reader resolves to a user/group already flagged as privileged.
		if ru, ok := idx.usersBySID[sid]; ok && ru.AdminCount {
			continue
		}
		if rg, ok := idx.groupsBySID[sid]; ok && rg.AdminCount {
			continue
		}
		// Skip a reader that is a computer account.
		if _, ok := idx.computersBySID[sid]; ok {
			continue
		}
		// Skip a reader that is a group whose transitive members are
		// exclusively computer accounts.
		if rg, ok := idx.groupsBySID[sid]; ok && groupIsComputerOnly(rg.DN, idx.computersByDN, idx.groupsByDN, map[string]bool{}) {
			continue
		}

		readerName := sid
		if ru, ok := idx.usersBySID[sid]; ok && ru.SAMAccountName != "" {
			readerName = ru.SAMAccountName
		} else if rg, ok := idx.groupsBySID[sid]; ok && rg.SAMAccountName != "" {
			readerName = rg.SAMAccountName
		}
		gmsaName := u.SAMAccountName
		if gmsaName == "" {
			gmsaName = u.DN
		}
		pairs = append(pairs, fmt.Sprintf("%s can read password of %s", readerName, gmsaName))
	}
	return pairs
}

// Detect returns one finding listing every (active gMSA, non-privileged
// reader) pair.
//
// A reader that is itself a computer account, or a group whose transitively
// resolved members are EXCLUSIVELY computer accounts, is not counted: a
// computer account cannot be phished or reused by a human operator the way a
// user or a mixed group can, and granting computer accounts the ability to
// retrieve the gMSA's password (e.g. so the hosts that run the service can
// fetch it) is Microsoft's documented, recommended configuration for gMSA
// PrincipalsAllowedToRetrieveManagedPassword. A group that contains at least
// one non-computer member (a user, or an unresolved/empty member) is still
// counted in full, and an unresolved reader SID is still counted - only a
// SID that resolves to a known computer-only population is excluded.
//
// A disabled gMSA is excluded here: its own ACCOUNTDISABLE closes only ITS
// own ability to authenticate ([MS-KILE] "Check Account Policy for Every
// TGT Request" - KDC_ERR_CLIENT_REVOKED), not the reader's, and does not
// remove, encrypt or hide the msDS-GroupMSAMembership attribute. The reader
// (itself active) still retrieves the managed password via an ordinary
// LDAP read of msDS-ManagedPassword regardless of the gMSA's account state,
// so a disabled gMSA with a non-privileged reader is reported separately,
// at Medium, by GMSAPasswordReadersOnDisabledAccountDetector.
func (d *GMSAPasswordReadersDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	idx := buildGMSAReaderIndex(data)

	var affected []types.User
	pairs := make([]string, 0)

	for i := range data.Users {
		u := &data.Users[i]
		if !u.IsGMSA || len(u.GMSAMembership) == 0 {
			continue
		}
		if u.Disabled {
			continue
		}

		readerPairs := idx.nonPrivilegedReaderPairs(u)
		if len(readerPairs) > 0 {
			affected = append(affected, *u)
			pairs = append(pairs, readerPairs...)
		}
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityHigh,
		Category: string(d.Category()),
		Title:    "Non-privileged principal can read gMSA password",
		Description: "One or more active (non-disabled) Group Managed Service Accounts (gMSA) allow " +
			"non-privileged principals to retrieve their managed password via msDS-GroupMSAMembership. " +
			"Any reader of the password can impersonate the service account. A reader that is a computer " +
			"account, or a group whose transitively resolved members are exclusively computer " +
			"accounts, is not reported: granting computer accounts retrieval rights is Microsoft's " +
			"recommended gMSA configuration. Disabled gMSAs are reported separately by " +
			"GMSA_PASSWORD_READERS_ON_DISABLED_ACCOUNT.",
		Count: len(affected),
		Details: map[string]interface{}{
			"recommendation": "Remove non-privileged principals from the gMSA PrincipalsAllowedToRetrieveManagedPassword set.",
			"pairs":          pairs,
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

// groupIsComputerOnly reports whether every member of the group at groupDN,
// resolved transitively through nested groups, is a computer account. It
// returns false (not computer-only) whenever a member is a user, an
// unresolved DN, or the group has no resolvable members at all - ambiguous
// or empty populations are never silently treated as computer-only, the same
// fail-closed default this package uses for unresolved reader SIDs. visited
// guards against membership cycles: a cycle re-entering an already-visited
// group returns false rather than looping, so a cyclic group is counted
// rather than silently exempted.
func groupIsComputerOnly(groupDN string, computersByDN map[string]*types.Computer, groupsByDN map[string]*types.Group, visited map[string]bool) bool {
	key := strings.ToLower(groupDN)
	if visited[key] {
		return false
	}
	visited[key] = true

	g, ok := groupsByDN[key]
	if !ok || len(g.Members) == 0 {
		return false
	}

	for _, memberDN := range g.Members {
		memberKey := strings.ToLower(memberDN)
		if _, isComputer := computersByDN[memberKey]; isComputer {
			continue
		}
		if _, isGroup := groupsByDN[memberKey]; isGroup {
			if !groupIsComputerOnly(memberDN, computersByDN, groupsByDN, visited) {
				return false
			}
			continue
		}
		// Neither a known computer nor a known group (e.g. a user, or an
		// unresolved member) - the group is not computer-only.
		return false
	}
	return true
}

func init() {
	audit.MustRegister(NewGMSAPasswordReadersDetector())
}
