package moderate

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

const (
	wsaComputerDN  = "CN=WS-02,OU=Workstations,DC=example,DC=com"
	wsaUserDN      = "CN=Jane Doe,OU=Users,DC=example,DC=com"
	wsaGroupDN     = "CN=Some Group,OU=Groups,DC=example,DC=com"
	wsaGUID        = "f3a64788-5306-11d1-a9c5-0000f80367c1"
	wsaOrdinary    = "S-1-5-21-1234567890-1111111111-2222222222-1106"
	wsaOrdinary2   = "S-1-5-21-1234567890-1111111111-2222222222-1107"
	wsaBuiltinSelf = "S-1-5-10"

	wsaWriteProp    = 0x00000020
	wsaReadProp     = 0x00000010
	wsaGenericWrite = 0x40000000
	wsaGenericAll   = 0x10000000
	wsaSelfRight    = 0x00000008
)

func wsaData(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		ObjectByDN: map[string]*audit.ObjectMeta{
			wsaComputerDN: {DN: wsaComputerDN, Name: "WS-02", EntityType: types.EntityTypeComputer},
			wsaUserDN:     {DN: wsaUserDN, Name: "Jane Doe", EntityType: types.EntityTypeUser},
			wsaGroupDN:    {DN: wsaGroupDN, Name: "Some Group", EntityType: types.EntityTypeGroup},
		},
	}
}

func wsaDetect(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewWriteSPNAbuseDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

func TestWriteSPNAbuse_RequiresGrantAndWriteBit(t *testing.T) {
	t.Run("DENY ace with the SPN GUID does NOT fire", func(t *testing.T) {
		f := wsaDetect(t, wsaData(
			types.ACLEntry{ObjectDN: wsaComputerDN, Trustee: wsaOrdinary, ObjectType: wsaGUID, AccessMask: wsaWriteProp, AceType: "ACCESS_DENIED"},
		))
		if f.Count != 0 {
			t.Fatalf("a DENY ace grants nothing, got count=%d", f.Count)
		}
	})

	t.Run("ALLOW ace without the write bit does NOT fire", func(t *testing.T) {
		f := wsaDetect(t, wsaData(
			types.ACLEntry{ObjectDN: wsaComputerDN, Trustee: wsaOrdinary, ObjectType: wsaGUID, AccessMask: wsaReadProp, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 0 {
			t.Fatalf("read-only access to the SPN property is not an abuse, got count=%d", f.Count)
		}
	})

	t.Run("builtin trustee (SELF) does NOT fire", func(t *testing.T) {
		f := wsaDetect(t, wsaData(
			types.ACLEntry{ObjectDN: wsaComputerDN, Trustee: wsaBuiltinSelf, ObjectType: wsaGUID, AccessMask: wsaWriteProp, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 0 {
			t.Fatalf("SELF writing its own SPN is expected, got count=%d", f.Count)
		}
	})

	t.Run("ALLOW ace with the write bit for an ordinary trustee DOES fire", func(t *testing.T) {
		f := wsaDetect(t, wsaData(
			types.ACLEntry{ObjectDN: wsaComputerDN, Trustee: wsaOrdinary, ObjectType: wsaGUID, AccessMask: wsaWriteProp, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 1 {
			t.Fatalf("a real SPN-write delegation must fire, got count=%d", f.Count)
		}
		if len(f.AffectedEntities) != 1 {
			t.Fatalf("finding must be actionable, got %d entities", len(f.AffectedEntities))
		}
	})
}

// TestWriteSPNAbuse_WritePropertyWithoutObjectTypeOnUserCounts proves a
// WriteProperty ACE with no ObjectType covers every property,
// servicePrincipalName included, even though the pre-fix code required
// strict equality with the SPN GUID and missed it.
func TestWriteSPNAbuse_WritePropertyWithoutObjectTypeOnUserCounts(t *testing.T) {
	f := wsaDetect(t, wsaData(
		types.ACLEntry{ObjectDN: wsaUserDN, Trustee: wsaOrdinary, ObjectType: "", AccessMask: wsaWriteProp, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 1 {
		t.Fatalf("a WriteProperty ACE with no ObjectType grants writing every property including the SPN, got count=%d", f.Count)
	}
}

// TestWriteSPNAbuse_GenericWriteOnComputerCounts proves GenericWrite, which
// subsumes WriteProperty on every attribute, was not recognized at all by
// the pre-fix code (it only tested the WriteProperty bit).
func TestWriteSPNAbuse_GenericWriteOnComputerCounts(t *testing.T) {
	f := wsaDetect(t, wsaData(
		types.ACLEntry{ObjectDN: wsaComputerDN, Trustee: wsaOrdinary, ObjectType: "", AccessMask: wsaGenericWrite, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 1 {
		t.Fatalf("GenericWrite subsumes WriteProperty on the SPN attribute, got count=%d", f.Count)
	}
}

// TestWriteSPNAbuse_GenericAllOnGroupDoesNotCount proves the new
// user-or-computer target restriction: an ACE that would have been counted
// by the pre-fix code purely from its GUID and WriteProperty bit (ignored
// entity type entirely) must not count once it lands on a group, since
// servicePrincipalName is not a meaningful attribute there.
func TestWriteSPNAbuse_GenericAllOnGroupDoesNotCount(t *testing.T) {
	f := wsaDetect(t, wsaData(
		types.ACLEntry{ObjectDN: wsaGroupDN, Trustee: wsaOrdinary, ObjectType: wsaGUID, AccessMask: wsaGenericAll | wsaWriteProp, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 0 {
		t.Fatalf("a group target must not count, servicePrincipalName is not meaningful there, got count=%d", f.Count)
	}
}

// TestWriteSPNAbuse_SelfRightAtSPNGUIDDoesNotCount is a non-regression check:
// the Validated-SPN self-write right (mask 0x8), the default ACE AD grants
// on computer accounts, stays out of this detector's scope.
func TestWriteSPNAbuse_SelfRightAtSPNGUIDDoesNotCount(t *testing.T) {
	f := wsaDetect(t, wsaData(
		types.ACLEntry{ObjectDN: wsaComputerDN, Trustee: wsaOrdinary, ObjectType: wsaGUID, AccessMask: wsaSelfRight, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 0 {
		t.Fatalf("the Self (validated write) right is out of scope for this detector, got count=%d", f.Count)
	}
}

// TestWriteSPNAbuse_WritePropertyAtSPNGUIDOnUserCounts is a non-regression
// check: the original, already-correct case (WriteProperty scoped exactly to
// the SPN GUID) must keep firing after the fix.
func TestWriteSPNAbuse_WritePropertyAtSPNGUIDOnUserCounts(t *testing.T) {
	f := wsaDetect(t, wsaData(
		types.ACLEntry{ObjectDN: wsaUserDN, Trustee: wsaOrdinary, ObjectType: wsaGUID, AccessMask: wsaWriteProp, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 1 {
		t.Fatalf("non-regression: WriteProperty scoped to the SPN GUID must still fire, got count=%d", f.Count)
	}
}

// TestWriteSPNAbuse_GenericAllBitAloneOnUserCounts proves the GenericAll case
// is tested independently of WriteProperty/GenericWrite: GenericAll alone
// (no WriteProperty, no GenericWrite bit set) on a user must still fire.
func TestWriteSPNAbuse_GenericAllBitAloneOnUserCounts(t *testing.T) {
	f := wsaDetect(t, wsaData(
		types.ACLEntry{ObjectDN: wsaUserDN, Trustee: wsaOrdinary, ObjectType: "", AccessMask: wsaGenericAll, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 1 {
		t.Fatalf("GenericAll alone subsumes WriteProperty on the SPN attribute, got count=%d", f.Count)
	}
}

// TestWriteSPNAbuse_TwoACEsOneObjectCountsOnce proves deduplication by
// object: two distinct triggering ACEs from two distinct trustees on the
// same user must count the object once (Count 1) while still reporting the
// two underlying instances (TotalInstances 2).
func TestWriteSPNAbuse_TwoACEsOneObjectCountsOnce(t *testing.T) {
	f := wsaDetect(t, wsaData(
		types.ACLEntry{ObjectDN: wsaUserDN, Trustee: wsaOrdinary, ObjectType: "", AccessMask: wsaWriteProp, AceType: "ACCESS_ALLOWED"},
		types.ACLEntry{ObjectDN: wsaUserDN, Trustee: wsaOrdinary2, ObjectType: "", AccessMask: wsaWriteProp, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 1 {
		t.Fatalf("two ACEs on the same object must still count the object once, got count=%d", f.Count)
	}
	if f.TotalInstances != 2 {
		t.Fatalf("the two underlying ACE instances must still be reported, got totalInstances=%d", f.TotalInstances)
	}
}
