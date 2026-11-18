package anssi

import (
	"testing"

	"github.com/etcsec-com/permtracer/pkg/types"
)

const (
	r12RestrictGUID = "4c164200-20c0-11d0-a768-00aa006e0529" // User-Account-Restrictions property set

	sidDomainAdmins = "S-1-5-21-1234567890-1111111111-2222222222-512"

	maskWriteProp = 0x00000020
)

// TestANSSIR12_2_IgnoresReadOnlyACE covers acceptance §2.
func TestANSSIR12_2_IgnoresReadOnlyACE(t *testing.T) {
	t.Run("AD's default READ_PROP ACE does NOT fire", func(t *testing.T) {
		// The exact DC01 shape: mask 0x10 held by S-1-5-32-554, ×1130.
		f := r12Detect(t, NewR122UserRestrictionsDetector(), r12Data(types.ACLEntry{
			ObjectDN:   r12TargetDN,
			Trustee:    sidPreWin2000,
			AccessMask: maskReadProp,
			AceType:    "ACCESS_ALLOWED_OBJECT",
			ObjectType: r12RestrictGUID,
		}))
		if f.Count != 0 {
			t.Fatalf("a READ_PROP ACE conveys no privilege, got count=%d", f.Count)
		}
	})

	t.Run("WRITE_PROP granted to a domain principal DOES fire, with entities", func(t *testing.T) {
		// The TRUE positive: a non-Tier-0 domain group can flip
		// userAccountControl bits on a user.
		f := r12Detect(t, NewR122UserRestrictionsDetector(), r12Data(types.ACLEntry{
			ObjectDN:   r12TargetDN,
			Trustee:    sidHelpdesk,
			AccessMask: maskWriteProp,
			AceType:    "ACCESS_ALLOWED_OBJECT",
			ObjectType: r12RestrictGUID,
		}))
		if f.Count != 1 {
			t.Fatalf("WRITE_PROP on User-Account-Restrictions must fire, got count=%d", f.Count)
		}
		if len(f.AffectedEntities) != 1 {
			t.Fatalf("a finding a customer cannot action is not a finding: got %d entities", len(f.AffectedEntities))
		}
		ent := f.AffectedEntities[0]
		if ent.Type != types.EntityTypeACLEntry {
			t.Errorf("entity type = %q, want aclEntry", ent.Type)
		}
		if ent.Trustee == nil || ent.Trustee.SID != sidHelpdesk {
			t.Errorf("entity must name the trustee to revoke, got %+v", ent.Trustee)
		}
		if ent.Target == nil || ent.Target.DN != r12TargetDN {
			t.Errorf("entity must name the target object, got %+v", ent.Target)
		}
	})

	t.Run("a Deny ACE on the property set does NOT fire", func(t *testing.T) {
		// R12.2 tested ObjectType/AccessMask/Trustee but never AceType, so
		// once acl_parser.go starts collecting deny ACEs this detector would
		// count a Deny on User-Account-Restrictions as if it were a grant.
		f := r12Detect(t, NewR122UserRestrictionsDetector(), r12Data(types.ACLEntry{
			ObjectDN:   r12TargetDN,
			Trustee:    sidHelpdesk,
			AccessMask: maskWriteProp,
			AceType:    "ACCESS_DENIED_OBJECT",
			ObjectType: r12RestrictGUID,
		}))
		if f.Count != 0 {
			t.Fatalf("a Deny ACE must not fire, got count=%d", f.Count)
		}
	})

	t.Run("Domain Admins is still skipped as a legitimate holder", func(t *testing.T) {
		f := r12Detect(t, NewR122UserRestrictionsDetector(), r12Data(types.ACLEntry{
			ObjectDN:   r12TargetDN,
			Trustee:    sidDomainAdmins,
			AccessMask: maskWriteProp,
			AceType:    "ACCESS_ALLOWED_OBJECT",
			ObjectType: r12RestrictGUID,
		}))
		if f.Count != 0 {
			t.Fatalf("Domain Admins holding the right is expected, got count=%d", f.Count)
		}
	})
}
