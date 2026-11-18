package dangerous

import (
	"testing"

	"github.com/etcsec-com/permtracer/pkg/types"
)

// maskReadControl (READ_CONTROL, 0x00020000) grants nothing but reading the
// security descriptor itself - it must never be mistaken for WriteDACL.
const maskReadControl = 0x00020000

// TestWriteDACL_CountsUniqueObjects guards against counting ACEs instead of
// unique objects.
func TestWriteDACL_CountsUniqueObjects(t *testing.T) {
	t.Run("two qualifying ACEs from two trustees on the SAME object count once", func(t *testing.T) {
		f := detectOne(t, NewWriteDACLDetector(), aclData(
			types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary, AccessMask: maskWriteDACL, AceType: "ACCESS_ALLOWED"},
			types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary2, AccessMask: maskWriteDACL, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 1 {
			t.Fatalf("two ACEs on one object must count as 1 unique object, got count=%d", f.Count)
		}
	})

	t.Run("two qualifying ACEs on two DISTINCT objects count twice", func(t *testing.T) {
		f := detectOne(t, NewWriteDACLDetector(), aclData(
			types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary, AccessMask: maskWriteDACL, AceType: "ACCESS_ALLOWED"},
			types.ACLEntry{ObjectDN: aclGroupDN, Trustee: sidOrdinary, AccessMask: maskWriteDACL, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 2 {
			t.Fatalf("two distinct objects must count as 2, got count=%d", f.Count)
		}
	})
}

// TestWriteDACL_CombinedMaskFires is the positive control: WriteDACL combined
// with another bit (here WriteProperty, 0x40020) must still be recognised as
// holding WriteDACL.
func TestWriteDACL_CombinedMaskFires(t *testing.T) {
	f := detectOne(t, NewWriteDACLDetector(), aclData(
		types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary, AccessMask: 0x00040020, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 1 {
		t.Fatalf("a combined mask carrying the WriteDACL bit must fire, got count=%d", f.Count)
	}
}

// TestWriteDACL_ReadControlAloneDoesNotFire proves READ_CONTROL alone is not
// mistaken for WriteDACL.
func TestWriteDACL_ReadControlAloneDoesNotFire(t *testing.T) {
	f := detectOne(t, NewWriteDACLDetector(), aclData(
		types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary, AccessMask: maskReadControl, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 0 {
		t.Fatalf("READ_CONTROL alone must not fire as WriteDACL, got count=%d", f.Count)
	}
}
