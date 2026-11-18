package ldap

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

// buildSecurityDescriptorWithTwoACEs hand-builds a minimal, valid binary
// ntSecurityDescriptor (MS-DTYP §2.4.6) carrying a DACL with exactly two
// ACCESS_ALLOWED ACEs on the same trustee SID (S-1-1-0, the shortest valid
// SID: revision 1, one sub-authority), differing only in AceFlags. This is
// the "SD binaire construit à la main" the ticket asks for: every field is
// laid out explicitly, byte offset by byte offset, rather than obtained by
// calling into the parser under test.
func buildSecurityDescriptorWithTwoACEs(t *testing.T, aceFlags1, aceFlags2 byte) []byte {
	t.Helper()
	return buildSecurityDescriptorWithACEs(t, aceFlags1, aceFlags2)
}

// buildSecurityDescriptorWithACEs is the N-ACE generalization of
// buildSecurityDescriptorWithTwoACEs, needed to pin down a single bit
// (0x08, INHERIT_ONLY) against its neighbors (0x02 CONTAINER_INHERIT, 0x10
// INHERITED_ACE) with more than two ACEs in one descriptor.
func buildSecurityDescriptorWithACEs(t *testing.T, aceFlagsList ...byte) []byte {
	t.Helper()

	// SID S-1-1-0 (Everyone): revision(1) + subAuthorityCount(1) +
	// identifierAuthority(6, big-endian, value 1) + subAuthority[0](4, LE, value 0).
	sid := []byte{
		0x01,                               // revision
		0x01,                               // sub-authority count
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // identifier authority = 1 (big-endian)
		0x00, 0x00, 0x00, 0x00, // sub-authority[0] = 0
	}
	if len(sid) != 12 {
		t.Fatalf("test setup: SID must be 12 bytes, got %d", len(sid))
	}

	buildACE := func(flags byte) []byte {
		ace := make([]byte, 8+len(sid))
		ace[0] = 0x00                                             // AceType = ACCESS_ALLOWED
		ace[1] = flags                                            // AceFlags
		binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace))) // AceSize
		binary.LittleEndian.PutUint32(ace[4:8], 0x00000001)       // AccessMask (arbitrary non-zero bit)
		copy(ace[8:], sid)
		return ace
	}

	var aces [][]byte
	totalACEBytes := 0
	for _, flags := range aceFlagsList {
		ace := buildACE(flags)
		aces = append(aces, ace)
		totalACEBytes += len(ace)
	}

	dacl := make([]byte, 8+totalACEBytes)
	dacl[0] = 0x04                                                      // AclRevision
	dacl[1] = 0x00                                                      // Sbz1
	binary.LittleEndian.PutUint16(dacl[2:4], uint16(len(dacl)))         // AclSize
	binary.LittleEndian.PutUint16(dacl[4:6], uint16(len(aceFlagsList))) // AceCount
	offset := 8
	for _, ace := range aces {
		copy(dacl[offset:], ace)
		offset += len(ace)
	}

	const sdHeaderSize = 20
	sd := make([]byte, sdHeaderSize+len(dacl))
	sd[0] = 0x01                                           // Revision
	sd[1] = 0x00                                           // Sbz1
	binary.LittleEndian.PutUint16(sd[2:4], 0x0004)         // Control = SE_DACL_PRESENT
	binary.LittleEndian.PutUint32(sd[4:8], 0)              // OffsetOwner (absent)
	binary.LittleEndian.PutUint32(sd[8:12], 0)             // OffsetGroup (absent)
	binary.LittleEndian.PutUint32(sd[12:16], 0)            // OffsetSacl (absent)
	binary.LittleEndian.PutUint32(sd[16:20], sdHeaderSize) // OffsetDacl
	copy(sd[sdHeaderSize:], dacl)

	return sd
}

// buildSecurityDescriptorWithTypedACE hand-builds a minimal, valid binary
// ntSecurityDescriptor carrying a DACL with exactly one ACE of the given
// AceType byte, standard (non-object) layout: type(1)+flags(1)+size(2)+mask(4)+SID(12).
// Used to pin parseACE's type gate directly, independently of
// buildSecurityDescriptorWithACEs above (which hardcodes AceType=0x00).
func buildSecurityDescriptorWithTypedACE(t *testing.T, aceType byte) []byte {
	t.Helper()

	sid := []byte{
		0x01,
		0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	}

	ace := make([]byte, 8+len(sid))
	ace[0] = aceType
	ace[1] = 0x00
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace)))
	binary.LittleEndian.PutUint32(ace[4:8], 0x00000001)
	copy(ace[8:], sid)

	dacl := make([]byte, 8+len(ace))
	dacl[0] = 0x04
	dacl[1] = 0x00
	binary.LittleEndian.PutUint16(dacl[2:4], uint16(len(dacl)))
	binary.LittleEndian.PutUint16(dacl[4:6], 1)
	copy(dacl[8:], ace)

	const sdHeaderSize = 20
	sd := make([]byte, sdHeaderSize+len(dacl))
	sd[0] = 0x01
	sd[1] = 0x00
	binary.LittleEndian.PutUint16(sd[2:4], 0x0004)
	binary.LittleEndian.PutUint32(sd[16:20], sdHeaderSize)
	copy(sd[sdHeaderSize:], dacl)

	return sd
}

// buildSecurityDescriptorWithTypedObjectACE is buildSecurityDescriptorWithTypedACE's
// sibling for OBJECT ACE types (0x05/0x06/0x07): these carry a mandatory
// 4-byte ObjectFlags field between the access mask and the SID (MS-DTYP
// 2.4.4.2/2.4.4.4), set here to 0 (no GUIDs present) so the SID immediately
// follows it. Reusing the standard builder for an object-type byte would
// misalign every field after the mask - exactly the shape bug the first
// version of this test file carried.
func buildSecurityDescriptorWithTypedObjectACE(t *testing.T, aceType byte) []byte {
	t.Helper()

	sid := []byte{
		0x01,
		0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	}

	ace := make([]byte, 12+len(sid)) // header(8) + ObjectFlags(4) + SID
	ace[0] = aceType
	ace[1] = 0x00
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace)))
	binary.LittleEndian.PutUint32(ace[4:8], 0x00000001)
	binary.LittleEndian.PutUint32(ace[8:12], 0x00000000) // ObjectFlags: no GUIDs present
	copy(ace[12:], sid)

	dacl := make([]byte, 8+len(ace))
	dacl[0] = 0x04
	dacl[1] = 0x00
	binary.LittleEndian.PutUint16(dacl[2:4], uint16(len(dacl)))
	binary.LittleEndian.PutUint16(dacl[4:6], 1)
	copy(dacl[8:], ace)

	const sdHeaderSize = 20
	sd := make([]byte, sdHeaderSize+len(dacl))
	sd[0] = 0x01
	sd[1] = 0x00
	binary.LittleEndian.PutUint16(sd[2:4], 0x0004)
	binary.LittleEndian.PutUint32(sd[16:20], sdHeaderSize)
	copy(sd[sdHeaderSize:], dacl)

	return sd
}

// TestParseSecurityDescriptor_DenyObjectACEKept pins the fix collecting deny
// ACEs: parseACE must no longer drop ACCESS_DENIED_OBJECT (0x06) ACEs. Before the
// fix, parseACE's type gate only let aceTypeAccessAllowed/aceTypeAccessAllowedObject
// through and returned nil for every other type, so a deny object ACE never
// reached data.ACLEntries - the real-world symptom VERDICT.md for
// USER_CANNOT_CHANGE_PASSWORD documents (Count=0 against a live planted Deny
// ACE). Breaking this test (restoring the single-condition gate) reproduces
// exactly that: entries comes back empty instead of length 1.
func TestParseSecurityDescriptor_DenyObjectACEKept(t *testing.T) {
	const aceTypeAccessDeniedObjectLiteral = 0x06 // distinct literal, not the package const under test
	sd := buildSecurityDescriptorWithTypedObjectACE(t, aceTypeAccessDeniedObjectLiteral)

	entries := ParseSecurityDescriptor(sd, "CN=locked-out,DC=example,DC=com")
	if !assert.Len(t, entries, 1, "an ACCESS_DENIED_OBJECT ACE must now produce an ACL entry") {
		return
	}
	assert.Equal(t, "ACCESS_DENIED_OBJECT", entries[0].AceType, "AceType must be reported as ACCESS_DENIED_OBJECT, not dropped or mislabeled")
	// Pins the object-ACE layout branch specifically: ACCESS_DENIED_OBJECT
	// must take the SAME field layout (ObjectFlags before the SID) as
	// ACCESS_ALLOWED_OBJECT. If that branch's condition only checked
	// aceTypeAccessAllowedObject, the SID would be read 4 bytes too early
	// (into the tail of ObjectFlags + the start of the real SID), producing
	// a wrong or sanity-clamped "S-1-0-0" Trustee instead of the real one.
	assert.Equal(t, "S-1-1-0", entries[0].Trustee, "Trustee must be read from the correct offset past ObjectFlags, not misaligned")
}

// TestParseSecurityDescriptor_DenyACEKept is the standard (non-object) sibling
// of the above: ACCESS_DENIED (0x01), no GUIDs.
func TestParseSecurityDescriptor_DenyACEKept(t *testing.T) {
	const aceTypeAccessDeniedLiteral = 0x01
	sd := buildSecurityDescriptorWithTypedACE(t, aceTypeAccessDeniedLiteral)

	entries := ParseSecurityDescriptor(sd, "CN=locked-out,DC=example,DC=com")
	if !assert.Len(t, entries, 1, "an ACCESS_DENIED ACE must now produce an ACL entry") {
		return
	}
	assert.Equal(t, "ACCESS_DENIED", entries[0].AceType)
}

// TestParseSecurityDescriptor_AuditACEStillDiscarded guards the other half of
// the gate: SYSTEM_AUDIT (0x02) must stay excluded even after denies are let
// through - the fix widens the gate to grants+denies, not to every type.
func TestParseSecurityDescriptor_AuditACEStillDiscarded(t *testing.T) {
	const aceTypeSystemAuditLiteral = 0x02
	sd := buildSecurityDescriptorWithTypedACE(t, aceTypeSystemAuditLiteral)

	entries := ParseSecurityDescriptor(sd, "CN=locked-out,DC=example,DC=com")
	assert.Len(t, entries, 0, "a SYSTEM_AUDIT ACE must remain discarded")
}

// TestParseSecurityDescriptor_InheritOnlyFlag pins the fix: an ACE with
// AceFlags 0x0a (ACE_INHERIT_ONLY 0x08 | ACE_CONTAINER_INHERIT 0x02, the
// shape produced by "dsacls /I:S") must come out with InheritOnly=true, while
// a plain explicit ACE (AceFlags 0x00) must come out with InheritOnly=false.
// Before this fix, ParseSecurityDescriptor dropped bit 0x08 entirely and both
// ACEs were structurally identical - the root cause of REPLICA_DIRECTORY_CHANGES
// counting an inherit-only ACE as if it applied to the root itself.
func TestParseSecurityDescriptor_InheritOnlyFlag(t *testing.T) {
	const aceFlagsExplicit = 0x00
	const aceFlagsContainerInheritOnly = 0x0a // CONTAINER_INHERIT (0x02) | INHERIT_ONLY (0x08)

	sd := buildSecurityDescriptorWithTwoACEs(t, aceFlagsExplicit, aceFlagsContainerInheritOnly)

	entries := ParseSecurityDescriptor(sd, "DC=test,DC=local")
	if !assert.Len(t, entries, 2, "expected exactly two ACL entries") {
		return
	}

	explicit := entries[0]
	assert.False(t, explicit.InheritOnly, "AceFlags 0x00 must not set InheritOnly")
	assert.False(t, explicit.IsInherited, "AceFlags 0x00 must not set IsInherited")

	inheritOnly := entries[1]
	assert.True(t, inheritOnly.InheritOnly, "AceFlags 0x0a (CI|IO) must set InheritOnly")
	assert.False(t, inheritOnly.IsInherited, "AceFlags 0x0a does not carry INHERITED_ACE (0x10)")
}

// TestParseSecurityDescriptor_InheritOnlyFlag_BitIsolation pins the exact bit
// read for InheritOnly (0x08) against its two closest neighbors: 0x02
// (CONTAINER_INHERIT) and 0x10 (INHERITED_ACE, already covered combined with
// 0x08 above but never alone). TestParseSecurityDescriptor_InheritOnlyFlag
// only exercises AceFlags 0x00 and 0x0a (CI|IO together), so a parser that
// reads the wrong single bit - 0x02 instead of 0x08 - or the wrong mask -
// 0x0a instead of 0x08 alone - still passes it: 0x00 has neither bit, and
// 0x0a carries both, so a parser reading either wrong shape is never exposed
// to a case where 0x02 and 0x08 disagree. This test supplies that case
// directly.
func TestParseSecurityDescriptor_InheritOnlyFlag_BitIsolation(t *testing.T) {
	const (
		aceFlagsContainerInheritAlone = 0x02 // CONTAINER_INHERIT alone - must NOT set InheritOnly
		aceFlagsInheritOnlyAlone      = 0x08 // INHERIT_ONLY alone - must set InheritOnly
		aceFlagsInheritedAlone        = 0x10 // INHERITED_ACE alone - must NOT set InheritOnly
	)

	sd := buildSecurityDescriptorWithACEs(t, aceFlagsContainerInheritAlone, aceFlagsInheritOnlyAlone, aceFlagsInheritedAlone)

	entries := ParseSecurityDescriptor(sd, "DC=test,DC=local")
	if !assert.Len(t, entries, 3, "expected exactly three ACL entries") {
		return
	}

	containerInherit := entries[0]
	assert.False(t, containerInherit.InheritOnly, "AceFlags 0x02 (CONTAINER_INHERIT alone) must NOT set InheritOnly - confusing it with 0x08 would silently ignore every ACE using the default 'this object and descendants' delegation shape")

	inheritOnlyAlone := entries[1]
	assert.True(t, inheritOnlyAlone.InheritOnly, "AceFlags 0x08 (INHERIT_ONLY alone, no CONTAINER_INHERIT) must set InheritOnly")

	inheritedAlone := entries[2]
	assert.False(t, inheritedAlone.InheritOnly, "AceFlags 0x10 (INHERITED_ACE alone) must NOT set InheritOnly - it is an unrelated bit")
}
