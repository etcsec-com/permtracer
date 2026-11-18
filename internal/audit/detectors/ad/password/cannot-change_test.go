package password

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/providers/ldap"
	"github.com/etcsec-com/permtracer/pkg/types"
)

const testChangePasswordGUID = types.GUIDChangePassword

// guidChangePasswordBytes is the hand-built MS-DTYP mixed-endian binary
// encoding of types.GUIDChangePassword ("ab721a53-1e2f-11d0-9819-00aa0040529b"),
// written byte by byte rather than derived from the constant under test, so
// this fixture cannot drift in lockstep with a bug in the encoder it feeds.
var guidChangePasswordBytes = []byte{
	0x53, 0x1a, 0x72, 0xab, // Data1, little-endian
	0x2f, 0x1e, // Data2, little-endian
	0xd0, 0x11, // Data3, little-endian
	0x98, 0x19, 0x00, 0xaa, 0x00, 0x40, 0x52, 0x9b, // Data4, raw bytes
}

// sidBytesEveryone / sidBytesSelf are S-1-1-0 and S-1-5-10 in MS-DTYP binary
// SID form: revision(1) + sub-authority count(1) + 6-byte big-endian
// authority + little-endian sub-authorities.
var sidBytesEveryone = []byte{0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
var sidBytesSelf = []byte{0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x0a, 0x00, 0x00, 0x00}

// buildDeniedObjectACE builds one standalone ACCESS_DENIED_OBJECT ACE
// (type 0x06, MS-DTYP 2.4.4.4) carrying guidChangePasswordBytes as
// ObjectType, for sidBytes.
func buildDeniedObjectACE(sidBytes []byte) []byte {
	const aceTypeAccessDeniedObject = 0x06
	const aceObjectTypePresent = 0x00000001
	ace := make([]byte, 8+4+16+len(sidBytes))
	ace[0] = aceTypeAccessDeniedObject
	ace[1] = 0x00
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace)))
	binary.LittleEndian.PutUint32(ace[4:8], 0x00000100) // CONTROL_ACCESS
	binary.LittleEndian.PutUint32(ace[8:12], aceObjectTypePresent)
	copy(ace[12:28], guidChangePasswordBytes)
	copy(ace[28:], sidBytes)
	return ace
}

// buildChangePasswordDenySD assembles a full binary ntSecurityDescriptor
// carrying one ACCESS_DENIED_OBJECT ACE per sid in sids, each on the
// User-Change-Password extended right - the real on-the-wire shape AD
// produces for ADUC's "User cannot change password" checkbox - so it can be
// fed to the real parser (internal/providers/ldap.ParseSecurityDescriptor)
// instead of a hand-built types.ACLEntry literal.
func buildChangePasswordDenySD(t *testing.T, sids ...[]byte) []byte {
	t.Helper()

	var aces [][]byte
	total := 0
	for _, sid := range sids {
		ace := buildDeniedObjectACE(sid)
		aces = append(aces, ace)
		total += len(ace)
	}

	dacl := make([]byte, 8+total)
	dacl[0] = 0x04 // AclRevision
	binary.LittleEndian.PutUint16(dacl[2:4], uint16(len(dacl)))
	binary.LittleEndian.PutUint16(dacl[4:6], uint16(len(sids)))
	offset := 8
	for _, ace := range aces {
		copy(dacl[offset:], ace)
		offset += len(ace)
	}

	const sdHeaderSize = 20
	sd := make([]byte, sdHeaderSize+len(dacl))
	sd[0] = 0x01
	binary.LittleEndian.PutUint16(sd[2:4], 0x0004) // SE_DACL_PRESENT
	binary.LittleEndian.PutUint32(sd[16:20], sdHeaderSize)
	copy(sd[sdHeaderSize:], dacl)
	return sd
}

// TestCannotChange_RealParserDenyACEDetected is the end-to-end proof that
// USER_CANNOT_CHANGE_PASSWORD must see a Deny ACE that actually came out of
// internal/providers/ldap's ParseSecurityDescriptor, not one hand-built as a
// types.ACLEntry literal like the tests below. Before the parser fix,
// parseACE discarded every ACCESS_DENIED_OBJECT ACE, so
// ParseSecurityDescriptor returned zero entries here and this detector, fed
// the real collector's output, never fired - exactly the Count=0 the
// detector's own doc comment documents against a live planted Deny ACE.
func TestCannotChange_RealParserDenyACEDetected(t *testing.T) {
	const targetDN = "CN=locked-out,DC=example,DC=com"
	sd := buildChangePasswordDenySD(t, sidBytesEveryone, sidBytesSelf)

	entries := ldap.ParseSecurityDescriptor(sd, targetDN)
	if len(entries) != 2 {
		t.Fatalf("parser must return 2 ACL entries (Everyone + Self denies), got %d: %+v", len(entries), entries)
	}

	data := &audit.DetectorData{
		Users:      []types.User{{SAMAccountName: "locked-out", DN: targetDN}},
		ACLEntries: entries,
	}

	findings := NewCannotChangeDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: USER_CANNOT_CHANGE_PASSWORD must see the parser-sourced Deny ACEs", findings[0].Count)
	}
}

// TestCannotChange_DenyEveryoneFlagged covers the documented state with only
// the Everyone Deny ACE present. Real plant/revert on DC01 established that
// AD always sets both trustees together via the supported mechanism, but the
// access-check reasoning in the Detect doc comment holds for either alone -
// this pins that this detector does not require both.
func TestCannotChange_DenyEveryoneFlagged(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users:          []types.User{{SAMAccountName: "locked-out", DN: "CN=locked-out,DC=example,DC=com"}},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=locked-out,DC=example,DC=com", Trustee: sidEveryone, AceType: "ACCESS_DENIED_OBJECT", ObjectType: testChangePasswordGUID},
		},
	}

	findings := NewCannotChangeDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
}

// TestCannotChange_DenySelfFlagged mirrors the above for the SELF trustee
// alone, the other half of the OR condition.
func TestCannotChange_DenySelfFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "locked-out", DN: "CN=locked-out,DC=example,DC=com"}},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=locked-out,DC=example,DC=com", Trustee: sidSelf, AceType: "ACCESS_DENIED_OBJECT", ObjectType: testChangePasswordGUID},
		},
	}

	findings := NewCannotChangeDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
}

// TestCannotChange_BothDenyACEsCountOnce is the grouping requirement: the
// documented plant mechanism (ADUC's "User cannot change password"
// checkbox) always produces TWO Deny ACEs (Everyone + Self) on one account.
// The counter must count the account once, not the ACE twice.
func TestCannotChange_BothDenyACEsCountOnce(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "locked-out", DN: "CN=locked-out,DC=example,DC=com"}},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=locked-out,DC=example,DC=com", Trustee: sidEveryone, AceType: "ACCESS_DENIED_OBJECT", ObjectType: testChangePasswordGUID},
			{ObjectDN: "CN=locked-out,DC=example,DC=com", Trustee: sidSelf, AceType: "ACCESS_DENIED_OBJECT", ObjectType: testChangePasswordGUID},
		},
	}

	findings := NewCannotChangeDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (one account, two ACEs)", findings[0].Count)
	}
}

// TestCannotChange_AllowACENotFlagged guards the default AD DS state: two
// ACCESS_ALLOWED_OBJECT ACEs on the same right, same trustees, must not
// trigger the finding.
func TestCannotChange_AllowACENotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "ordinary", DN: "CN=ordinary,DC=example,DC=com"}},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=ordinary,DC=example,DC=com", Trustee: sidEveryone, AceType: "ACCESS_ALLOWED_OBJECT", ObjectType: testChangePasswordGUID},
			{ObjectDN: "CN=ordinary,DC=example,DC=com", Trustee: sidSelf, AceType: "ACCESS_ALLOWED_OBJECT", ObjectType: testChangePasswordGUID},
		},
	}

	findings := NewCannotChangeDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestCannotChange_DenyOnDifferentRightNotFlagged guards the ObjectType
// filter: a Deny ACE for the two documented trustees, but on an unrelated
// extended right, must not trigger.
func TestCannotChange_DenyOnDifferentRightNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "unrelated", DN: "CN=unrelated,DC=example,DC=com"}},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=unrelated,DC=example,DC=com", Trustee: sidEveryone, AceType: "ACCESS_DENIED_OBJECT", ObjectType: types.GUIDForceChangePassword},
		},
	}

	findings := NewCannotChangeDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestCannotChange_DenyOtherTrusteeNotFlagged guards the trustee filter: a
// Deny ACE on the right GUID, but for neither Everyone nor SELF, must not
// trigger - it restricts some other principal, not the account's own
// self-change path.
func TestCannotChange_DenyOtherTrusteeNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "unrelated", DN: "CN=unrelated,DC=example,DC=com"}},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=unrelated,DC=example,DC=com", Trustee: "S-1-5-21-1-2-3-1234", AceType: "ACCESS_DENIED_OBJECT", ObjectType: testChangePasswordGUID},
		},
	}

	findings := NewCannotChangeDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestCannotChange_DisabledAccountExcluded pins the split: a disabled
// account carrying the Deny ACE must not inflate the active (Medium)
// population - it is reported separately by
// CannotChangeOnDisabledAccountDetector instead, at Low. Mirrors
// TestCannotChangeOnDisabledAccount_ActiveNotCounted in the sibling file.
func TestCannotChange_DisabledAccountExcluded(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "blocked-active", DN: "CN=blocked-active,DC=example,DC=com", Disabled: false},
			{SAMAccountName: "blocked-disabled", DN: "CN=blocked-disabled,DC=example,DC=com", Disabled: true},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=blocked-active,DC=example,DC=com", Trustee: sidEveryone, AceType: "ACCESS_DENIED_OBJECT", ObjectType: testChangePasswordGUID},
			{ObjectDN: "CN=blocked-disabled,DC=example,DC=com", Trustee: sidEveryone, AceType: "ACCESS_DENIED_OBJECT", ObjectType: testChangePasswordGUID},
		},
	}

	findings := NewCannotChangeDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled account must be excluded)", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityMedium {
		t.Fatalf("Severity = %s, want medium", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "blocked-active" {
		t.Fatalf("AffectedEntities = %+v, want only blocked-active", findings[0].AffectedEntities)
	}
}

// TestCannotChange_UnknownObjectDNNotCounted guards the DN join: a Deny ACE
// whose ObjectDN matches no entry in data.Users cannot be attributed to the
// active population - there is no user record to confirm it is not
// disabled. See TestCannotChangeOnDisabledAccount_UnknownObjectDNNotCounted
// for the twin's side of the same guard.
func TestCannotChange_UnknownObjectDNNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "someone-else", DN: "CN=someone-else,DC=example,DC=com", Disabled: false}},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=ghost-object,DC=example,DC=com", Trustee: sidEveryone, AceType: "ACCESS_DENIED_OBJECT", ObjectType: testChangePasswordGUID},
		},
	}

	findings := NewCannotChangeDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: the Deny ACE's ObjectDN matches no known user", findings[0].Count)
	}
}
