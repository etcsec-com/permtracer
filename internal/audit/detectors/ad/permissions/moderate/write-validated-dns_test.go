package moderate

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

const (
	wvdOUComputerDN  = "CN=WS-03,OU=Workstations,DC=example,DC=com"
	wvdDefaultCompDN = "CN=WS-04,CN=Computers,DC=example,DC=com"
	wvdUserDN        = "CN=Akira Jackson,OU=IT,DC=example,DC=com"
	wvdGUID          = "72e39547-7b18-11d1-adef-00c04fd8d5cd"
	wvdTrustee       = "S-1-5-21-1234567890-1111111111-2222222222-1107"
	wvdTrustee2      = "S-1-5-21-1234567890-1111111111-2222222222-1108"
	// Validated-SPN, a different extended right GUID than wvdGUID.
	wvdOtherGUID = "f3a64788-5306-11d1-a9c5-0000f80367c1"
)

func wvdData(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		Computers: []types.Computer{
			{DN: wvdOUComputerDN, SAMAccountName: "WS-03$"},
			{DN: wvdDefaultCompDN, SAMAccountName: "WS-04$"},
		},
		ObjectByDN: map[string]*audit.ObjectMeta{
			wvdOUComputerDN:  {DN: wvdOUComputerDN, Name: "WS-03", EntityType: types.EntityTypeComputer},
			wvdDefaultCompDN: {DN: wvdDefaultCompDN, Name: "WS-04", EntityType: types.EntityTypeComputer},
		},
	}
}

func wvdDetect(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewWriteValidatedDNSDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

// TestWriteValidatedDNS_DenyACENotCounted pins the fix for this reader:
// ACL_COMPUTER_WRITE_VALIDATED_DNS tested ObjectType/ObjectDN
// but never AceType, so once acl_parser.go starts collecting deny ACEs this
// detector would count a Deny on Validated-Write-DNS as if it were a grant -
// the exact inverse of the finding's meaning. Before the fix (no
// audit.IsGrantACE guard), this ACE counted; after, it must not.
func TestWriteValidatedDNS_DenyACENotCounted(t *testing.T) {
	f := wvdDetect(t, wvdData(
		types.ACLEntry{ObjectDN: wvdOUComputerDN, Trustee: wvdTrustee, ObjectType: wvdGUID, AceType: "ACCESS_DENIED_OBJECT"},
	))
	if f.Count != 0 {
		t.Fatalf("a Deny ACE on Validated-Write-DNS must not be counted as a grant, got count=%d", f.Count)
	}
}

// TestWriteValidatedDNS_SelfDefaultACENotCounted pins the fix for this
// reader: the Computer class's Default-Security-Descriptor grants this same
// GUID to SELF (S-1-5-10) on every computer object by construction
// (Microsoft Learn, "Computer class"). Before the fix (no
// audit.IsBuiltinAdminTrustee guard), this baseline ACE counted on every
// single computer; after, it must not.
func TestWriteValidatedDNS_SelfDefaultACENotCounted(t *testing.T) {
	f := wvdDetect(t, wvdData(
		types.ACLEntry{ObjectDN: wvdOUComputerDN, Trustee: "S-1-5-10", ObjectType: wvdGUID, AceType: "ACCESS_ALLOWED_OBJECT", AccessMask: types.MaskSelf},
	))
	if f.Count != 0 {
		t.Fatalf("the Computer class's default SELF ACE must not be counted, got count=%d", f.Count)
	}
}

// TestWriteValidatedDNS_CreatorOwnerDefaultACENotCounted is the mirror case
// for CREATOR OWNER (S-1-3-0), the other trustee in the same
// Default-Security-Descriptor entry.
func TestWriteValidatedDNS_CreatorOwnerDefaultACENotCounted(t *testing.T) {
	f := wvdDetect(t, wvdData(
		types.ACLEntry{ObjectDN: wvdOUComputerDN, Trustee: "S-1-3-0", ObjectType: wvdGUID, AceType: "ACCESS_ALLOWED_OBJECT", AccessMask: types.MaskSelf},
	))
	if f.Count != 0 {
		t.Fatalf("the Computer class's default CREATOR OWNER ACE must not be counted, got count=%d", f.Count)
	}
}

// TestWriteValidatedDNS_ReadOnlyBitNotCounted proves the detector now tests
// the access mask, not just the GUID: an ACE naming this ObjectType but
// granting only ReadProperty (0x10), for a non-administrative trustee, is
// not a write and must not be counted. Before the fix (no AccessMask check
// at all), this ACE counted regardless of what it actually granted.
func TestWriteValidatedDNS_ReadOnlyBitNotCounted(t *testing.T) {
	f := wvdDetect(t, wvdData(
		types.ACLEntry{ObjectDN: wvdOUComputerDN, Trustee: wvdTrustee, ObjectType: wvdGUID, AceType: "ACCESS_ALLOWED_OBJECT", AccessMask: 0x10},
	))
	if f.Count != 0 {
		t.Fatalf("a ReadProperty-only ACE on Validated-Write-DNS must not be counted, got count=%d", f.Count)
	}
}

// TestWriteValidatedDNS_SelfBitForNonAdminTrusteeCounted proves the positive
// case survives the fix: a non-administrative trustee holding the validated
// write bit (MaskSelf, 0x8) on this GUID is exactly the population this
// detector exists to catch.
func TestWriteValidatedDNS_SelfBitForNonAdminTrusteeCounted(t *testing.T) {
	f := wvdDetect(t, wvdData(
		types.ACLEntry{ObjectDN: wvdOUComputerDN, Trustee: wvdTrustee, ObjectType: wvdGUID, AceType: "ACCESS_ALLOWED_OBJECT", AccessMask: types.MaskSelf},
	))
	if f.Count != 1 {
		t.Fatalf("a non-admin trustee with MaskSelf on Validated-Write-DNS must be counted, got count=%d", f.Count)
	}
}

// TestWriteValidatedDNS_WritePropertyBitForNonAdminTrusteeCounted is the
// second positive case: direct WriteProperty (0x20) on the same GUID -
// writespn-abuse.go's own bit for the same ObjectType reuse pattern - must
// also be counted for a non-administrative trustee.
func TestWriteValidatedDNS_WritePropertyBitForNonAdminTrusteeCounted(t *testing.T) {
	f := wvdDetect(t, wvdData(
		types.ACLEntry{ObjectDN: wvdOUComputerDN, Trustee: wvdTrustee, ObjectType: wvdGUID, AceType: "ACCESS_ALLOWED_OBJECT", AccessMask: types.MaskWriteProperty},
	))
	if f.Count != 1 {
		t.Fatalf("a non-admin trustee with MaskWriteProperty on Validated-Write-DNS must be counted, got count=%d", f.Count)
	}
}

// TestWriteValidatedDNS_DenySelfOnDNSGUIDNotCounted proves the audit.IsGrantACE
// guard matters on its own: the existing TestWriteValidatedDNS_DenyACENotCounted
// carries AccessMask 0x0, so it is already excluded by the access-mask check
// even without the AceType guard. This ACE instead carries the validated-write
// bit (MaskSelf) on the DNS GUID, so only the AceType guard keeps it out.
func TestWriteValidatedDNS_DenySelfOnDNSGUIDNotCounted(t *testing.T) {
	f := wvdDetect(t, wvdData(
		types.ACLEntry{ObjectDN: wvdOUComputerDN, Trustee: wvdTrustee, ObjectType: wvdGUID, AceType: "ACCESS_DENIED_OBJECT", AccessMask: types.MaskSelf},
	))
	if f.Count != 0 {
		t.Fatalf("a Deny ACE carrying MaskSelf on Validated-Write-DNS must not be counted, got count=%d", f.Count)
	}
}

// TestWriteValidatedDNS_OtherGUIDNotCounted proves the ObjectType guard
// matters on its own: an ACE with a grant AceType and the validated-write
// bit, but naming a different extended right (Validated-SPN), must not be
// counted as Validated-Write-DNS.
func TestWriteValidatedDNS_OtherGUIDNotCounted(t *testing.T) {
	f := wvdDetect(t, wvdData(
		types.ACLEntry{ObjectDN: wvdOUComputerDN, Trustee: wvdTrustee, ObjectType: wvdOtherGUID, AceType: "ACCESS_ALLOWED_OBJECT", AccessMask: types.MaskSelf},
	))
	if f.Count != 0 {
		t.Fatalf("an ACE on a different extended right (Validated-SPN) must not be counted, got count=%d", f.Count)
	}
}

// TestWriteValidatedDNS_TwoACEsOneComputerCountsOnce proves Count reports
// unique objects, not raw ACE instances: two ordinary trustees each holding
// Validated-Write-DNS on the SAME computer is one affected object
// (Count 1) carried across two ACE instances (TotalInstances 2).
func TestWriteValidatedDNS_TwoACEsOneComputerCountsOnce(t *testing.T) {
	f := wvdDetect(t, wvdData(
		types.ACLEntry{ObjectDN: wvdOUComputerDN, Trustee: wvdTrustee, ObjectType: wvdGUID, AceType: "ACCESS_ALLOWED_OBJECT", AccessMask: types.MaskSelf},
		types.ACLEntry{ObjectDN: wvdOUComputerDN, Trustee: wvdTrustee2, ObjectType: wvdGUID, AceType: "ACCESS_ALLOWED_OBJECT", AccessMask: types.MaskSelf},
	))
	if f.Count != 1 {
		t.Fatalf("two ACEs on the same computer must count as one affected object, got count=%d", f.Count)
	}
	if f.TotalInstances != 2 {
		t.Fatalf("two ACEs on the same computer must report TotalInstances=2, got %d", f.TotalInstances)
	}
}

func TestWriteValidatedDNS_NotRestrictedToDefaultContainer(t *testing.T) {
	t.Run("a computer in a custom OU DOES fire", func(t *testing.T) {
		f := wvdDetect(t, wvdData(
			types.ACLEntry{ObjectDN: wvdOUComputerDN, Trustee: wvdTrustee, ObjectType: wvdGUID, AceType: "ACCESS_ALLOWED", AccessMask: types.MaskSelf},
		))
		if f.Count != 1 {
			t.Fatalf("a computer outside CN=Computers is still a computer, got count=%d", f.Count)
		}
	})

	t.Run("a computer in the default container still fires", func(t *testing.T) {
		f := wvdDetect(t, wvdData(
			types.ACLEntry{ObjectDN: wvdDefaultCompDN, Trustee: wvdTrustee, ObjectType: wvdGUID, AceType: "ACCESS_ALLOWED", AccessMask: types.MaskSelf},
		))
		if f.Count != 1 {
			t.Fatalf("the default container must remain covered, got count=%d", f.Count)
		}
	})

	t.Run("a non-computer object does NOT fire", func(t *testing.T) {
		f := wvdDetect(t, wvdData(
			types.ACLEntry{ObjectDN: wvdUserDN, Trustee: wvdTrustee, ObjectType: wvdGUID, AceType: "ACCESS_ALLOWED", AccessMask: types.MaskSelf},
		))
		if f.Count != 0 {
			t.Fatalf("a user object is not this detector's business, got count=%d", f.Count)
		}
	})
}
