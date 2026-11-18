package advanced

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func TestAdminNoSmartcard_AdminEnabledNoSmartcardBit_Counted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=admin1,OU=Admins,DC=contoso,DC=com", AdminCount: true, Disabled: false, UserAccountControl: 0x0200},
		},
	}
	f := NewAdminNoSmartcardDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("a privileged enabled account without the smartcard bit must be flagged, got Count=%d", f.Count)
	}
}

func TestAdminNoSmartcard_NonAdminEnabledNoSmartcardBit_NotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=user1,OU=Users,DC=contoso,DC=com", AdminCount: false, Disabled: false, UserAccountControl: 0x0200},
		},
	}
	f := NewAdminNoSmartcardDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("a non-privileged account must NOT be flagged regardless of the smartcard bit, got Count=%d", f.Count)
	}
}

func TestAdminNoSmartcard_AdminDisabled_NotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=admin2,OU=Admins,DC=contoso,DC=com", AdminCount: true, Disabled: true, UserAccountControl: 0x0200},
		},
	}
	f := NewAdminNoSmartcardDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("a disabled privileged account must NOT be flagged, got Count=%d", f.Count)
	}
}

func TestAdminNoSmartcard_AdminEnabledWithSmartcardBit_NotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=admin3,OU=Admins,DC=contoso,DC=com", AdminCount: true, Disabled: false, UserAccountControl: 0x40000},
		},
	}
	f := NewAdminNoSmartcardDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("a privileged enabled account with the 0x40000 smartcard bit set must NOT be flagged, got Count=%d", f.Count)
	}
}

func TestAdminNoSmartcard_AdminEnabledWithNeighborBitOnly_Counted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=admin4,OU=Admins,DC=contoso,DC=com", AdminCount: true, Disabled: false, UserAccountControl: 0x20000},
		},
	}
	f := NewAdminNoSmartcardDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("the neighbor bit 0x20000 alone must NOT be mistaken for the smartcard requirement, got Count=%d", f.Count)
	}
}

func TestAdminNoSmartcard_AdminEnabledWithSmartcardBitAndOtherBits_NotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=admin5,OU=Admins,DC=contoso,DC=com", AdminCount: true, Disabled: false, UserAccountControl: 0x10200 | 0x40000},
		},
	}
	f := NewAdminNoSmartcardDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("the smartcard bit combined with unrelated bits must still NOT be flagged, got Count=%d", f.Count)
	}
}

// TestAdminNoSmartcard_MixedUsers_ExactCount mixes a flagged admin, a
// non-admin, a disabled admin and a protected admin so an inverted or
// dropped guard changes the total rather than coincidentally matching it.
func TestAdminNoSmartcard_MixedUsers_ExactCount(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{DN: "CN=admin6,OU=Admins,DC=contoso,DC=com", AdminCount: true, Disabled: false, UserAccountControl: 0x0200},
			{DN: "CN=user2,OU=Users,DC=contoso,DC=com", AdminCount: false, Disabled: false, UserAccountControl: 0x0200},
			{DN: "CN=admin7,OU=Admins,DC=contoso,DC=com", AdminCount: true, Disabled: true, UserAccountControl: 0x0200},
			{DN: "CN=admin8,OU=Admins,DC=contoso,DC=com", AdminCount: true, Disabled: false, UserAccountControl: 0x40000},
		},
	}
	f := NewAdminNoSmartcardDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected exactly 1 admin without smartcard requirement in the mix, got Count=%d", f.Count)
	}
	if len(f.AffectedEntities) != f.Count {
		t.Fatalf("AffectedEntities length %d must match Count %d", len(f.AffectedEntities), f.Count)
	}
}
