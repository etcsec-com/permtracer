package computer

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// COMPUTER_ACL_GENERICALL carried the same defect as the ACL_* family:
// no trustee filter and no AceType test, so AD's own full-control ACEs made it
// report 74 of 74 computers.

const (
	cgComputerDN = "CN=WS-01,OU=Workstations,DC=example,DC=com"
	cgDomain     = "S-1-5-21-1234567890-1111111111-2222222222"

	cgFullControl = 0x000F01FF
)

func cgData(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		Computers:      []types.Computer{{DN: cgComputerDN, SAMAccountName: "WS-01$"}},
		ObjectByDN: map[string]*audit.ObjectMeta{
			cgComputerDN: {DN: cgComputerDN, Name: "WS-01", EntityType: types.EntityTypeComputer},
		},
	}
}

func cgDetect(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewGenericAllDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

func TestComputerGenericAll_SkipsBuiltinAdminTrustees(t *testing.T) {
	t.Run("AD's own full-control ACEs do NOT fire", func(t *testing.T) {
		f := cgDetect(t, cgData(
			types.ACLEntry{ObjectDN: cgComputerDN, Trustee: "S-1-5-18", AccessMask: cgFullControl, AceType: "ACCESS_ALLOWED"},
			types.ACLEntry{ObjectDN: cgComputerDN, Trustee: cgDomain + "-512", AccessMask: cgFullControl, AceType: "ACCESS_ALLOWED"},
			types.ACLEntry{ObjectDN: cgComputerDN, Trustee: "S-1-5-32-544", AccessMask: cgFullControl, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 0 {
			t.Fatalf("baseline ACEs on a computer are not a takeover risk, got count=%d", f.Count)
		}
	})

	t.Run("ordinary domain principal with full control DOES fire", func(t *testing.T) {
		// The real RBCD / credential-theft exposure.
		f := cgDetect(t, cgData(
			types.ACLEntry{ObjectDN: cgComputerDN, Trustee: cgDomain + "-93801", AccessMask: cgFullControl, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 1 {
			t.Fatalf("a domain principal owning a computer must fire, got count=%d", f.Count)
		}
		if len(f.AffectedEntities) != 1 {
			t.Fatalf("finding must be actionable, got %d entities", len(f.AffectedEntities))
		}
	})

	t.Run("DENY full control does NOT fire", func(t *testing.T) {
		f := cgDetect(t, cgData(
			types.ACLEntry{ObjectDN: cgComputerDN, Trustee: cgDomain + "-93801", AccessMask: cgFullControl, AceType: "ACCESS_DENIED"},
		))
		if f.Count != 0 {
			t.Fatalf("a DENY ace grants nothing, got count=%d", f.Count)
		}
	})
}

// cgUserDN is a non-computer object DN, distinct from cgComputerDN, used to
// prove the computer-object filter is load-bearing.
const cgUserDN = "CN=bob,OU=Users,DC=example,DC=com"

func TestComputerGenericAll_MutationCoverage(t *testing.T) {
	t.Run("Raw_GenericAll_bit_alone_DOES_fire", func(t *testing.T) {
		f := cgDetect(t, cgData(
			types.ACLEntry{ObjectDN: cgComputerDN, Trustee: cgDomain + "-93802", AccessMask: 0x10000000, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 1 {
			t.Fatalf("raw GENERIC_ALL bit alone must fire, got count=%d", f.Count)
		}
	})

	t.Run("Partial_rights_do_NOT_fire", func(t *testing.T) {
		f := cgDetect(t, cgData(
			types.ACLEntry{ObjectDN: cgComputerDN, Trustee: cgDomain + "-93803", AccessMask: 0x00020028, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 0 {
			t.Fatalf("partial rights (neither raw GENERIC_ALL nor full control) must not fire, got count=%d", f.Count)
		}
	})

	t.Run("Full_control_on_non_computer_does_NOT_fire", func(t *testing.T) {
		data := &audit.DetectorData{
			IncludeDetails: true,
			ACLEntries: []types.ACLEntry{
				{ObjectDN: cgUserDN, Trustee: cgDomain + "-93804", AccessMask: cgFullControl, AceType: "ACCESS_ALLOWED"},
			},
			Computers: []types.Computer{{DN: cgComputerDN, SAMAccountName: "WS-01$"}},
		}
		f := cgDetect(t, data)
		if f.Count != 0 {
			t.Fatalf("full control on a non-computer object must not fire, got count=%d", f.Count)
		}
	})

	t.Run("Two_ACEs_one_computer_counts_once", func(t *testing.T) {
		f := cgDetect(t, cgData(
			types.ACLEntry{ObjectDN: cgComputerDN, Trustee: cgDomain + "-93805", AccessMask: cgFullControl, AceType: "ACCESS_ALLOWED"},
			types.ACLEntry{ObjectDN: cgComputerDN, Trustee: cgDomain + "-93806", AccessMask: cgFullControl, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 1 {
			t.Fatalf("two ACEs on the same computer must dedupe to count=1, got count=%d", f.Count)
		}
		if f.TotalInstances != 2 {
			t.Fatalf("two ACEs on the same computer must report TotalInstances=2, got %d", f.TotalInstances)
		}
	})
}
