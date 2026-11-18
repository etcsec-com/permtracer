package dangerous

import (
	"testing"

	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestWriteOwner_CountsUniqueObjects guards against counting ACEs instead of
// unique objects.
func TestWriteOwner_CountsUniqueObjects(t *testing.T) {
	t.Run("two qualifying ACEs from two trustees on the SAME object count once", func(t *testing.T) {
		f := detectOne(t, NewWriteOwnerDetector(), aclData(
			types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary, AccessMask: maskWriteOwner, AceType: "ACCESS_ALLOWED"},
			types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary2, AccessMask: maskWriteOwner, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 1 {
			t.Fatalf("two ACEs on one object must count as 1 unique object, got count=%d", f.Count)
		}
	})

	t.Run("two qualifying ACEs on two DISTINCT objects count twice", func(t *testing.T) {
		f := detectOne(t, NewWriteOwnerDetector(), aclData(
			types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary, AccessMask: maskWriteOwner, AceType: "ACCESS_ALLOWED"},
			types.ACLEntry{ObjectDN: aclGroupDN, Trustee: sidOrdinary, AccessMask: maskWriteOwner, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 2 {
			t.Fatalf("two distinct objects must count as 2, got count=%d", f.Count)
		}
	})
}

// TestWriteOwner_CombinedMaskFires is the positive control: WriteOwner
// combined with another bit (here READ_CONTROL, 0x00020000, giving 0xA0000)
// must still be recognised as holding WriteOwner.
func TestWriteOwner_CombinedMaskFires(t *testing.T) {
	f := detectOne(t, NewWriteOwnerDetector(), aclData(
		types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary, AccessMask: 0x000A0000, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 1 {
		t.Fatalf("a combined mask carrying the WriteOwner bit must fire, got count=%d", f.Count)
	}
}

// TestWriteOwner_WriteDACLAloneDoesNotFire proves WriteDACL alone is not
// mistaken for WriteOwner.
func TestWriteOwner_WriteDACLAloneDoesNotFire(t *testing.T) {
	f := detectOne(t, NewWriteOwnerDetector(), aclData(
		types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary, AccessMask: maskWriteDACL, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 0 {
		t.Fatalf("WriteDACL alone must not fire as WriteOwner, got count=%d", f.Count)
	}
}
