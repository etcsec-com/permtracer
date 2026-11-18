package dangerous

import (
	"testing"

	"github.com/etcsec-com/permtracer/pkg/types"
)

// Second ordinary trustee, distinct from sidOrdinary (dangerous_acl_test.go),
// needed to prove Count counts unique OBJECTS, not ACEs.
const sidOrdinary2 = aclDomain + "-93802"

// TestGenericAll_RawBitAlone covers mutation (c): removing the raw
// GENERIC_ALL term. 0x10000000 alone does not overlap adFullControl
// (0x000F01FF) at all, so only the raw-bit check can catch it.
func TestGenericAll_RawBitAlone(t *testing.T) {
	f := detectOne(t, NewGenericAllDetector(), aclData(
		types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary, AccessMask: 0x10000000, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 1 {
		t.Fatalf("raw GENERIC_ALL bit alone must fire, got count=%d", f.Count)
	}
}

// TestGenericAll_PartialRightsDoNotFire covers mutation (e): `== adFullControl`
// weakened to `!= 0`. Both masks overlap adFullControl without equaling it,
// so a `!= 0` comparison would wrongly fire on them.
func TestGenericAll_PartialRightsDoNotFire(t *testing.T) {
	cases := []struct {
		name string
		mask int
	}{
		{"WriteProperty alone", 0x00000020},
		{"Full Control minus one bit", 0x000B01FF},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := detectOne(t, NewGenericAllDetector(), aclData(
				types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary, AccessMask: tc.mask, AceType: "ACCESS_ALLOWED"},
			))
			if f.Count != 0 {
				t.Fatalf("a partial right must not fire as GenericAll, got count=%d", f.Count)
			}
		})
	}
}

// TestGenericAll_ExactFullControlFires is the positive control for the
// equality check: the exact mapped full-control mask must still fire.
func TestGenericAll_ExactFullControlFires(t *testing.T) {
	f := detectOne(t, NewGenericAllDetector(), aclData(
		types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary, AccessMask: maskFullControl, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 1 {
		t.Fatalf("the exact mapped full-control mask must fire, got count=%d", f.Count)
	}
}

// TestGenericAll_CountsUniqueObjects covers mutation (f): Count set to the
// number of ACEs instead of the number of unique objects.
func TestGenericAll_CountsUniqueObjects(t *testing.T) {
	t.Run("two qualifying ACEs from two trustees on the SAME object count once", func(t *testing.T) {
		f := detectOne(t, NewGenericAllDetector(), aclData(
			types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary, AccessMask: maskFullControl, AceType: "ACCESS_ALLOWED"},
			types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary2, AccessMask: maskFullControl, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 1 {
			t.Fatalf("two ACEs on one object must count as 1 unique object, got count=%d", f.Count)
		}
	})

	t.Run("two qualifying ACEs on two DISTINCT objects count twice", func(t *testing.T) {
		f := detectOne(t, NewGenericAllDetector(), aclData(
			types.ACLEntry{ObjectDN: aclUserDN, Trustee: sidOrdinary, AccessMask: maskFullControl, AceType: "ACCESS_ALLOWED"},
			types.ACLEntry{ObjectDN: aclGroupDN, Trustee: sidOrdinary, AccessMask: maskFullControl, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 2 {
			t.Fatalf("two distinct objects must count as 2, got count=%d", f.Count)
		}
	})
}
