package moderate

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

const (
	fcpUserDN         = "CN=Akira Jackson,OU=IT,DC=example,DC=com"
	fcpGroupDN        = "CN=Help Desk,OU=Groups,DC=example,DC=com"
	fcpGUID           = "00299570-246d-11d0-a768-00aa006e0529"
	fcpOrdinaryUser   = "S-1-5-21-1234567890-1111111111-2222222222-1105"
	fcpOrdinaryUser2  = "S-1-5-21-1234567890-1111111111-2222222222-1106"
	fcpBuiltinAdmin   = "S-1-5-32-544"
	fcpSystem         = "S-1-5-18"
	fcpDomainAdmins   = "S-1-5-21-1234567890-1111111111-2222222222-512"
)

func fcpData(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		ObjectByDN: map[string]*audit.ObjectMeta{
			fcpUserDN:  {DN: fcpUserDN, Name: "Akira Jackson", EntityType: types.EntityTypeUser},
			fcpGroupDN: {DN: fcpGroupDN, Name: "Help Desk", EntityType: types.EntityTypeGroup},
		},
	}
}

func fcpDetect(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewUserForceChangePasswordDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

func TestUserForceChangePassword_FiltersDenyAndBuiltinAdmins(t *testing.T) {
	t.Run("DENY ace does NOT fire", func(t *testing.T) {
		f := fcpDetect(t, fcpData(
			types.ACLEntry{ObjectDN: fcpUserDN, Trustee: fcpOrdinaryUser, ObjectType: fcpGUID, AceType: "ACCESS_DENIED"},
		))
		if f.Count != 0 {
			t.Fatalf("a DENY ace grants nothing, got count=%d", f.Count)
		}
	})

	t.Run("builtin admin trustee does NOT fire", func(t *testing.T) {
		f := fcpDetect(t, fcpData(
			types.ACLEntry{ObjectDN: fcpUserDN, Trustee: fcpBuiltinAdmin, ObjectType: fcpGUID, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 0 {
			t.Fatalf("built-in admins hold this right by construction, got count=%d", f.Count)
		}
	})

	t.Run("ordinary user grant DOES fire", func(t *testing.T) {
		f := fcpDetect(t, fcpData(
			types.ACLEntry{ObjectDN: fcpUserDN, Trustee: fcpOrdinaryUser, ObjectType: fcpGUID, AceType: "ACCESS_ALLOWED", AccessMask: types.MaskControlAccess},
		))
		if f.Count != 1 {
			t.Fatalf("a real delegation to a non-admin must fire, got count=%d", f.Count)
		}
		if len(f.AffectedEntities) != 1 {
			t.Fatalf("finding must be actionable, got %d entities", len(f.AffectedEntities))
		}
	})
}

// TestUserForceChangePassword_ChecksAccessMask proves the previously
// unchecked mask (an ACE at the right GUID counted regardless of its mask)
// is closed, and that GenericAll and an ObjectType-less CONTROL_ACCESS ACE -
// both of which grant the right without naming it - are still counted.
func TestUserForceChangePassword_ChecksAccessMask(t *testing.T) {
	t.Run("ReadProperty alone at the GUID is NOT counted", func(t *testing.T) {
		f := fcpDetect(t, fcpData(
			types.ACLEntry{ObjectDN: fcpUserDN, Trustee: fcpOrdinaryUser, ObjectType: fcpGUID, AceType: "ACCESS_ALLOWED", AccessMask: types.MaskReadProperty},
		))
		if f.Count != 0 {
			t.Fatalf("a ReadProperty ACE reads the attribute, it does not invoke the right, got count=%d", f.Count)
		}
	})

	t.Run("CONTROL_ACCESS at the GUID is counted", func(t *testing.T) {
		f := fcpDetect(t, fcpData(
			types.ACLEntry{ObjectDN: fcpUserDN, Trustee: fcpOrdinaryUser, ObjectType: fcpGUID, AceType: "ACCESS_ALLOWED", AccessMask: types.MaskControlAccess},
		))
		if f.Count != 1 {
			t.Fatalf("a CONTROL_ACCESS ACE at the GUID must fire, got count=%d", f.Count)
		}
	})

	t.Run("GenericAll without ObjectType is counted", func(t *testing.T) {
		f := fcpDetect(t, fcpData(
			types.ACLEntry{ObjectDN: fcpUserDN, Trustee: fcpOrdinaryUser, AceType: "ACCESS_ALLOWED", AccessMask: types.MaskGenericAll},
		))
		if f.Count != 1 {
			t.Fatalf("GenericAll subsumes every right including this one, got count=%d", f.Count)
		}
	})

	t.Run("CONTROL_ACCESS without ObjectType is counted", func(t *testing.T) {
		f := fcpDetect(t, fcpData(
			types.ACLEntry{ObjectDN: fcpUserDN, Trustee: fcpOrdinaryUser, AceType: "ACCESS_ALLOWED", AccessMask: types.MaskControlAccess},
		))
		if f.Count != 1 {
			t.Fatalf("CONTROL_ACCESS with no ObjectType grants every extended right, got count=%d", f.Count)
		}
	})
}

// TestUserForceChangePassword_RestrictsToUserTargets proves GenericAll (and
// the other equivalence paths) only fire when the ACE's target object is a
// user account, not a group/OU/GPO - that overlap belongs to ACL_GENERICALL.
func TestUserForceChangePassword_RestrictsToUserTargets(t *testing.T) {
	t.Run("GenericAll on a group is NOT counted", func(t *testing.T) {
		f := fcpDetect(t, fcpData(
			types.ACLEntry{ObjectDN: fcpGroupDN, Trustee: fcpOrdinaryUser, AceType: "ACCESS_ALLOWED", AccessMask: types.MaskGenericAll},
		))
		if f.Count != 0 {
			t.Fatalf("GenericAll on a non-account target must not fire, got count=%d", f.Count)
		}
	})

	t.Run("GenericAll on a user IS counted", func(t *testing.T) {
		f := fcpDetect(t, fcpData(
			types.ACLEntry{ObjectDN: fcpUserDN, Trustee: fcpOrdinaryUser, AceType: "ACCESS_ALLOWED", AccessMask: types.MaskGenericAll},
		))
		if f.Count != 1 {
			t.Fatalf("GenericAll on a user account must fire, got count=%d", f.Count)
		}
	})
}

// TestForceChangePassword_BuiltinAdminTrusteeNotCounted proves a triggering
// ACE (Allow, ExtendedRight at the User-Force-Change-Password GUID) is still
// excluded when the trustee is a built-in administrative principal: SYSTEM by
// exact SID, and a domain's own privileged group by RID suffix.
func TestForceChangePassword_BuiltinAdminTrusteeNotCounted(t *testing.T) {
	t.Run("SYSTEM trustee does NOT fire", func(t *testing.T) {
		f := fcpDetect(t, fcpData(
			types.ACLEntry{ObjectDN: fcpUserDN, Trustee: fcpSystem, ObjectType: fcpGUID, AceType: "ACCESS_ALLOWED", AccessMask: types.MaskControlAccess},
		))
		if f.Count != 0 {
			t.Fatalf("SYSTEM is a built-in admin trustee, got count=%d", f.Count)
		}
	})

	t.Run("domain -512 trustee does NOT fire", func(t *testing.T) {
		f := fcpDetect(t, fcpData(
			types.ACLEntry{ObjectDN: fcpUserDN, Trustee: fcpDomainAdmins, ObjectType: fcpGUID, AceType: "ACCESS_ALLOWED", AccessMask: types.MaskControlAccess},
		))
		if f.Count != 0 {
			t.Fatalf("a domain's own Domain Admins (-512) is a built-in admin trustee, got count=%d", f.Count)
		}
	})
}

// TestForceChangePassword_TwoACEsOneUserCountsOnce proves two triggering ACEs
// from two different non-privileged trustees on the SAME user object count as
// one finding (deduplicated by object, not by ACE instance).
func TestForceChangePassword_TwoACEsOneUserCountsOnce(t *testing.T) {
	f := fcpDetect(t, fcpData(
		types.ACLEntry{ObjectDN: fcpUserDN, Trustee: fcpOrdinaryUser, ObjectType: fcpGUID, AceType: "ACCESS_ALLOWED", AccessMask: types.MaskControlAccess},
		types.ACLEntry{ObjectDN: fcpUserDN, Trustee: fcpOrdinaryUser2, ObjectType: fcpGUID, AceType: "ACCESS_ALLOWED", AccessMask: types.MaskControlAccess},
	))
	if f.Count != 1 {
		t.Fatalf("two triggering ACEs on the same user must dedupe to one finding, got count=%d", f.Count)
	}
}
