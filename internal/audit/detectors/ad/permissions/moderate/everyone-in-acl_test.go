package moderate

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// EVERYONE_IN_ACL fired on 1167 of 1167 objects on DC01 because its
// "write" constant was 0x00020000, which is READ_CONTROL: Authenticated Users
// holds the right to READ the security descriptor on essentially every object.

const (
	evUserDN = "CN=Akira Jackson,OU=IT,DC=example,DC=com"

	sidEveryone           = "S-1-1-0"
	sidAuthenticatedUsers = "S-1-5-11"
	sidOrdinaryUser       = "S-1-5-21-1234567890-1111111111-2222222222-1105"

	maskReadControl  = 0x00020000 // the constant that was mislabelled WRITE_PROP
	maskWriteProp    = 0x00000020 // the real ADS_RIGHT_DS_WRITE_PROP
	maskWriteDACL    = 0x00040000
	maskReadProperty = 0x00000010

	maskWriteOwnerOnly = 0x00080000 // WRITE_OWNER alone, no other write-class bit set
	maskGenericAllRaw  = 0x10000000 // raw GENERIC_ALL, no other write-class bit set
)

func evData(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		ObjectByDN: map[string]*audit.ObjectMeta{
			evUserDN: {DN: evUserDN, Name: "Akira Jackson", EntityType: types.EntityTypeUser},
		},
	}
}

func evDetect(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewEveryoneInACLDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

// TestEveryoneInACL_UsesWriteProp covers acceptance §1.
func TestEveryoneInACL_UsesWriteProp(t *testing.T) {
	t.Run("READ_CONTROL alone does NOT fire", func(t *testing.T) {
		// The DC01 shape: Authenticated Users can read the security descriptor
		// of every object. That is not write access.
		f := evDetect(t, evData(
			types.ACLEntry{ObjectDN: evUserDN, Trustee: sidAuthenticatedUsers, AccessMask: maskReadControl, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 0 {
			t.Fatalf("READ_CONTROL (0x20000) is not write access, got count=%d", f.Count)
		}
	})

	t.Run("READ_PROP alone does NOT fire", func(t *testing.T) {
		f := evDetect(t, evData(
			types.ACLEntry{ObjectDN: evUserDN, Trustee: sidEveryone, AccessMask: maskReadProperty, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 0 {
			t.Fatalf("READ_PROP is not write access, got count=%d", f.Count)
		}
	})

	t.Run("WRITE_PROP DOES fire", func(t *testing.T) {
		f := evDetect(t, evData(
			types.ACLEntry{ObjectDN: evUserDN, Trustee: sidAuthenticatedUsers, AccessMask: maskWriteProp, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 1 {
			t.Fatalf("Authenticated Users with WRITE_PROP is the real finding, got count=%d", f.Count)
		}
		if len(f.AffectedEntities) != 1 {
			t.Fatalf("finding must be actionable, got %d entities", len(f.AffectedEntities))
		}
		if f.Severity != types.SeverityMedium {
			t.Errorf("severity = %q, want medium", f.Severity)
		}
	})

	t.Run("Everyone with WriteDACL DOES fire", func(t *testing.T) {
		// Any write-class right counts, not only WRITE_PROP.
		f := evDetect(t, evData(
			types.ACLEntry{ObjectDN: evUserDN, Trustee: sidEveryone, AccessMask: maskWriteDACL, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 1 {
			t.Fatalf("Everyone with WriteDACL must fire, got count=%d", f.Count)
		}
	})

	t.Run("an ordinary user with WRITE_PROP is not this detector's business", func(t *testing.T) {
		f := evDetect(t, evData(
			types.ACLEntry{ObjectDN: evUserDN, Trustee: sidOrdinaryUser, AccessMask: maskWriteProp, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 0 {
			t.Fatalf("EVERYONE_IN_ACL only covers Everyone / Authenticated Users, got count=%d", f.Count)
		}
	})

	t.Run("DENY write to Everyone does NOT fire", func(t *testing.T) {
		f := evDetect(t, evData(
			types.ACLEntry{ObjectDN: evUserDN, Trustee: sidEveryone, AccessMask: maskWriteProp, AceType: "ACCESS_DENIED"},
		))
		if f.Count != 0 {
			t.Fatalf("a DENY ace grants nothing, got count=%d", f.Count)
		}
	})

	t.Run("WriteOwner_only_DOES_fire", func(t *testing.T) {
		// WRITE_OWNER alone (no WRITE_PROP/WRITE_DACL/GENERIC_* bit) must still count.
		f := evDetect(t, evData(
			types.ACLEntry{ObjectDN: evUserDN, Trustee: sidAuthenticatedUsers, AccessMask: maskWriteOwnerOnly, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 1 {
			t.Fatalf("Authenticated Users with WRITE_OWNER alone must fire, got count=%d", f.Count)
		}
	})

	t.Run("Raw_GenericAll_DOES_fire", func(t *testing.T) {
		// Raw GENERIC_ALL (no WRITE_PROP/WRITE_DACL/WRITE_OWNER bit) must still count.
		f := evDetect(t, evData(
			types.ACLEntry{ObjectDN: evUserDN, Trustee: sidEveryone, AccessMask: maskGenericAllRaw, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 1 {
			t.Fatalf("Everyone with raw GENERIC_ALL must fire, got count=%d", f.Count)
		}
	})

	t.Run("Two_ACEs_one_object_counts_once", func(t *testing.T) {
		// Two write-class ACEs on the SAME object (Everyone, then Authenticated
		// Users) must dedupe to Count 1 while still reporting TotalInstances 2.
		f := evDetect(t, evData(
			types.ACLEntry{ObjectDN: evUserDN, Trustee: sidEveryone, AccessMask: maskWriteProp, AceType: "ACCESS_ALLOWED"},
			types.ACLEntry{ObjectDN: evUserDN, Trustee: sidAuthenticatedUsers, AccessMask: maskWriteDACL, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 1 {
			t.Fatalf("two write ACEs on one object must dedupe to count=1, got count=%d", f.Count)
		}
		if f.TotalInstances != 2 {
			t.Fatalf("two write ACEs on one object must report TotalInstances=2, got %d", f.TotalInstances)
		}
	})
}
