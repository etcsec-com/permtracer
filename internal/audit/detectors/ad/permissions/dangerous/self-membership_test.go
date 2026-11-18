package dangerous

import (
	"testing"

	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestSelfMembership_SelfOnRealMemberGUID_IsCounted is the positive control:
// the real DS_SELF bit, scoped to the real member GUID, must still fire.
func TestSelfMembership_SelfOnRealMemberGUID_IsCounted(t *testing.T) {
	f := detectOne(t, NewSelfMembershipDetector(), aclData(
		types.ACLEntry{ObjectDN: aclGroupDN, Trustee: sidOrdinary, AccessMask: maskWriteSelf, AceType: "ACCESS_ALLOWED_OBJECT", ObjectType: guidSelfMembership},
	))
	if f.Count != 1 {
		t.Fatalf("Self (0x8) on the real member GUID must fire, got count=%d", f.Count)
	}
}

// TestSelfMembership_ReadPropertyAlone_IsNotCounted covers mutation M1: the
// mask test removed from the member-GUID branch. ReadProperty (0x10) is
// merely reading the member list, not a self-add right.
func TestSelfMembership_ReadPropertyAlone_IsNotCounted(t *testing.T) {
	f := detectOne(t, NewSelfMembershipDetector(), aclData(
		types.ACLEntry{ObjectDN: aclGroupDN, Trustee: sidOrdinary, AccessMask: 0x10, AceType: "ACCESS_ALLOWED_OBJECT", ObjectType: guidSelfMembership},
	))
	if f.Count != 0 {
		t.Fatalf("ReadProperty alone on member must not fire, got count=%d", f.Count)
	}
}

// TestSelfMembership_WritePropertyAlone_IsNotCounted: WriteProperty (0x20) on
// member is ACL_ADD_MEMBER's role, not self-membership - adding it here would
// duplicate that detector's entity set.
func TestSelfMembership_WritePropertyAlone_IsNotCounted(t *testing.T) {
	f := detectOne(t, NewSelfMembershipDetector(), aclData(
		types.ACLEntry{ObjectDN: aclGroupDN, Trustee: sidOrdinary, AccessMask: 0x20, AceType: "ACCESS_ALLOWED_OBJECT", ObjectType: guidSelfMembership},
	))
	if f.Count != 0 {
		t.Fatalf("WriteProperty alone on member must not fire (that is ACL_ADD_MEMBER), got count=%d", f.Count)
	}
}

// TestSelfMembership_SelfWithoutObjectType_IsCounted: an unscoped validated
// write (ObjectType empty) carrying DS_SELF is still a self-add right.
func TestSelfMembership_SelfWithoutObjectType_IsCounted(t *testing.T) {
	f := detectOne(t, NewSelfMembershipDetector(), aclData(
		types.ACLEntry{ObjectDN: aclGroupDN, Trustee: sidOrdinary, AccessMask: maskWriteSelf, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 1 {
		t.Fatalf("Self (0x8) with no ObjectType must fire, got count=%d", f.Count)
	}
}

// TestSelfMembership_FullControlWithoutObjectType_IsNotCounted covers
// mutation M2: the full-control exclusion removed. Full control carries the
// DS_SELF bit too (it is a superset), but it is already reported by
// ACL_GENERICALL and must not be double-counted here.
func TestSelfMembership_FullControlWithoutObjectType_IsNotCounted(t *testing.T) {
	f := detectOne(t, NewSelfMembershipDetector(), aclData(
		types.ACLEntry{ObjectDN: aclGroupDN, Trustee: sidOrdinary, AccessMask: maskFullControl, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 0 {
		t.Fatalf("full control must not fire here (reported by ACL_GENERICALL instead), got count=%d", f.Count)
	}
}

// TestSelfMembership_BuiltinAdminTrustee_IsNotCounted covers mutation M3:
// the IsBuiltinAdminTrustee guard removed. Built-in admins can obviously add
// members to any group.
func TestSelfMembership_BuiltinAdminTrustee_IsNotCounted(t *testing.T) {
	f := detectOne(t, NewSelfMembershipDetector(), aclData(
		types.ACLEntry{ObjectDN: aclGroupDN, Trustee: sidBuiltinAdmin, AccessMask: maskWriteSelf, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 0 {
		t.Fatalf("a builtin admin trustee must not fire, got count=%d", f.Count)
	}
}

// TestSelfMembership_TwoTrusteesOnSameGroup_CountOnce covers mutation M4:
// Count switched from len(uniqueObjects) to totalInstances. Two distinct
// trustees holding the right on the SAME group must still count as 1 object.
func TestSelfMembership_TwoTrusteesOnSameGroup_CountOnce(t *testing.T) {
	f := detectOne(t, NewSelfMembershipDetector(), aclData(
		types.ACLEntry{ObjectDN: aclGroupDN, Trustee: sidOrdinary, AccessMask: maskWriteSelf, AceType: "ACCESS_ALLOWED"},
		types.ACLEntry{ObjectDN: aclGroupDN, Trustee: sidOrdinary2, AccessMask: maskWriteSelf, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 1 {
		t.Fatalf("two trustees on one group must count as 1 unique object, got count=%d", f.Count)
	}
}
