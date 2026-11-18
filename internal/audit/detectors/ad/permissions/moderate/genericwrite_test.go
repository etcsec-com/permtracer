package moderate

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// ACL_GENERICWRITE tested only the raw GENERIC_WRITE bit
// (0x40000000), which Windows almost never writes to an ACE: it maps generic
// bits to specific rights at write time, so the detector was structurally
// mute (0 findings on DC01, 1128 objects / 41269 ACEs, confirmed live
// 2026-09-08). Fixing the mask alone would have flipped it the other way -
// genericall.go's note documents 1134/1167 objects without the grant +
// builtin-admin filters - so both land in this one change.

const (
	gwDomainDN = "DC=example,DC=com"
	gwDomain   = "S-1-5-21-1234567890-1111111111-2222222222"
	gwUserDN   = "CN=Akira Jackson,OU=IT," + gwDomainDN
	gwUserDN2  = "CN=Blake Carter,OU=IT," + gwDomainDN

	gwSidSystem       = "S-1-5-18"
	gwSidBuiltinAdmin = "S-1-5-32-544"
	gwSidDomainAdmins = gwDomain + "-512"
	gwSidOrdinary     = gwDomain + "-93801"
	gwSidOrdinary2    = gwDomain + "-93802"

	// GenericWrite mapped to AD-specific rights (READ_CONTROL | ACTRL_DS_WRITE_PROP
	// | ACTRL_DS_SELF) - what dsacls/.NET actually write. See genericwrite.go.
	gwMaskMapped = 0x00020028
	gwMaskRaw    = 0x40000000

	// Partial masks: present on real ACEs but neither the full mapped mask nor
	// the raw bit, so neither detection branch must fire on them.
	gwMaskSelfOnly        = 0x00000008 // ACTRL_DS_SELF alone
	gwMaskReadWriteNoSelf = 0x00020020 // READ_CONTROL | ACTRL_DS_WRITE_PROP, missing ACTRL_DS_SELF
)

func gwData(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		ObjectByDN: map[string]*audit.ObjectMeta{
			gwUserDN:   {DN: gwUserDN, Name: "Akira Jackson", EntityType: types.EntityTypeUser},
			gwUserDN2:  {DN: gwUserDN2, Name: "Blake Carter", EntityType: types.EntityTypeUser},
			gwDomainDN: {DN: gwDomainDN, Name: "example", EntityType: types.EntityTypeDomain},
		},
	}
}

func gwDetect(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	d := NewGenericWriteDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

// TestGenericWrite_MappedMaskFires is the RED->GREEN case: before the fix the
// detector tested only the raw 0x40000000 bit, which this ACE does not carry,
// so it never fired even though the trustee genuinely holds GenericWrite.
func TestGenericWrite_MappedMaskFires(t *testing.T) {
	f := gwDetect(t, gwData(
		types.ACLEntry{ObjectDN: gwUserDN, Trustee: gwSidOrdinary, AccessMask: gwMaskMapped, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 1 {
		t.Fatalf("a trustee holding the AD-mapped GenericWrite mask must fire, got count=%d", f.Count)
	}
	if len(f.AffectedEntities) != 1 {
		t.Fatalf("finding must be actionable, got %d entities", len(f.AffectedEntities))
	}
}

// TestGenericWrite_RawBitStillFires guards the pre-existing (if rare) raw-bit path.
func TestGenericWrite_RawBitStillFires(t *testing.T) {
	f := gwDetect(t, gwData(
		types.ACLEntry{ObjectDN: gwUserDN, Trustee: gwSidOrdinary, AccessMask: gwMaskRaw, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 1 {
		t.Fatalf("the raw GENERIC_WRITE bit must still fire, got count=%d", f.Count)
	}
}

// TestGenericWrite_DenyDoesNotFire covers DET_10: a DENY ace grants nothing.
func TestGenericWrite_DenyDoesNotFire(t *testing.T) {
	f := gwDetect(t, gwData(
		types.ACLEntry{ObjectDN: gwUserDN, Trustee: gwSidOrdinary, AccessMask: gwMaskMapped, AceType: "ACCESS_DENIED"},
	))
	if f.Count != 0 {
		t.Fatalf("a DENY ace must not fire, got count=%d", f.Count)
	}
}

// TestGenericWrite_BuiltinAdminTrusteesDoNotFire is the trap this warns
// against: mapping the mask without this filter turns a mute detector into an
// always-on one (measured live: 100%% of 1128 DC01 objects without it).
func TestGenericWrite_BuiltinAdminTrusteesDoNotFire(t *testing.T) {
	f := gwDetect(t, gwData(
		types.ACLEntry{ObjectDN: gwUserDN, Trustee: gwSidSystem, AccessMask: gwMaskMapped, AceType: "ACCESS_ALLOWED"},
		types.ACLEntry{ObjectDN: gwUserDN, Trustee: gwSidDomainAdmins, AccessMask: gwMaskMapped, AceType: "ACCESS_ALLOWED"},
		types.ACLEntry{ObjectDN: gwUserDN, Trustee: gwSidBuiltinAdmin, AccessMask: gwMaskMapped, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 0 {
		t.Fatalf("AD's own baseline ACEs must not be findings, got count=%d", f.Count)
	}
}

// TestGenericWrite_PartialMaskSelfOnlyDoesNotFire kills mutation (e): if the
// equality check `(mask & adMappedGenericWrite) == adMappedGenericWrite` were
// weakened to `(mask & adMappedGenericWrite) != 0`, this lone ACTRL_DS_SELF
// bit alone would already satisfy it and wrongly fire.
func TestGenericWrite_PartialMaskSelfOnlyDoesNotFire(t *testing.T) {
	f := gwDetect(t, gwData(
		types.ACLEntry{ObjectDN: gwUserDN, Trustee: gwSidOrdinary, AccessMask: gwMaskSelfOnly, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 0 {
		t.Fatalf("a bare ACTRL_DS_SELF bit must not satisfy the full mapped GenericWrite mask, got count=%d", f.Count)
	}
}

// TestGenericWrite_PartialMaskWithoutSelfDoesNotFire is the second witness for
// mutation (e): READ_CONTROL|ACTRL_DS_WRITE_PROP without ACTRL_DS_SELF is also
// non-zero against the mapped mask, so an `!= 0` check would fire on it too.
func TestGenericWrite_PartialMaskWithoutSelfDoesNotFire(t *testing.T) {
	f := gwDetect(t, gwData(
		types.ACLEntry{ObjectDN: gwUserDN, Trustee: gwSidOrdinary, AccessMask: gwMaskReadWriteNoSelf, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 0 {
		t.Fatalf("READ_CONTROL|ACTRL_DS_WRITE_PROP without ACTRL_DS_SELF must not satisfy the full mapped mask, got count=%d", f.Count)
	}
}

// TestGenericWrite_TwoTrusteesSameObjectCountsOnce kills mutation (f): if
// Count were the number of qualifying ACE instances instead of the number of
// unique objects, two trustees qualifying on the same object would report 2.
func TestGenericWrite_TwoTrusteesSameObjectCountsOnce(t *testing.T) {
	f := gwDetect(t, gwData(
		types.ACLEntry{ObjectDN: gwUserDN, Trustee: gwSidOrdinary, AccessMask: gwMaskMapped, AceType: "ACCESS_ALLOWED"},
		types.ACLEntry{ObjectDN: gwUserDN, Trustee: gwSidOrdinary2, AccessMask: gwMaskMapped, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 1 {
		t.Fatalf("two qualifying trustees on the same object must count as one object, got count=%d", f.Count)
	}
}

// TestGenericWrite_TwoDistinctObjectsCountTwo is the converse witness for
// mutation (f): two qualifying ACEs on two distinct objects must count as 2,
// which an instance-based count would also happen to report, but together
// with TestGenericWrite_TwoTrusteesSameObjectCountsOnce this pins down
// per-unique-object counting specifically.
func TestGenericWrite_TwoDistinctObjectsCountTwo(t *testing.T) {
	f := gwDetect(t, gwData(
		types.ACLEntry{ObjectDN: gwUserDN, Trustee: gwSidOrdinary, AccessMask: gwMaskMapped, AceType: "ACCESS_ALLOWED"},
		types.ACLEntry{ObjectDN: gwUserDN2, Trustee: gwSidOrdinary, AccessMask: gwMaskMapped, AceType: "ACCESS_ALLOWED"},
	))
	if f.Count != 2 {
		t.Fatalf("two qualifying ACEs on two distinct objects must count as two objects, got count=%d", f.Count)
	}
}
