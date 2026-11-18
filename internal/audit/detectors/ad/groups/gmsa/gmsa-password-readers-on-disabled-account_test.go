package gmsa

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestGMSAPasswordReadersOnDisabledAccount_DisabledGMSAFires is the mirror
// positive of TestGMSAPasswordReaders_DisabledGMSANotCounted: a disabled
// gMSA with a non-privileged reader must be counted here.
func TestGMSAPasswordReadersOnDisabledAccount_DisabledGMSAFires(t *testing.T) {
	d := NewGMSAPasswordReadersOnDisabledAccountDetector()
	sd := buildSDWithTrustee(7001)
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{DN: "CN=svc,DC=contoso,DC=com", SAMAccountName: "svc$", IsGMSA: true, GMSAMembership: sd, Disabled: true},
		},
	}
	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("expected count 1 for disabled gMSA with non-privileged reader, got %d", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityMedium {
		t.Fatalf("expected severity medium, got %s", findings[0].Severity)
	}
}

// TestGMSAPasswordReadersOnDisabledAccount_ActiveGMSADoesNotFire is the
// mirror negative: an active (non-disabled) gMSA with a non-privileged
// reader must not be counted here - it is covered instead by
// GMSAPasswordReadersDetector (gmsa-password-readers.go).
func TestGMSAPasswordReadersOnDisabledAccount_ActiveGMSADoesNotFire(t *testing.T) {
	d := NewGMSAPasswordReadersOnDisabledAccountDetector()
	sd := buildSDWithTrustee(7002)
	users := []types.User{
		{SAMAccountName: "svc$", IsGMSA: true, GMSAMembership: sd, Disabled: false},
	}
	findings := d.Detect(context.Background(), newData(users))
	if findings[0].Count != 0 {
		t.Fatalf("expected count 0 for active gMSA, got %d (active gMSA must not fire here, covered by the active detector instead)", findings[0].Count)
	}
}

// TestGMSAPasswordReadersOnDisabledAccount_DisabledGMSAWithoutNonPrivReaderDoesNotFire
// proves the reader condition still applies: a disabled gMSA whose only
// reader is privileged must not be counted.
func TestGMSAPasswordReadersOnDisabledAccount_DisabledGMSAWithoutNonPrivReaderDoesNotFire(t *testing.T) {
	d := NewGMSAPasswordReadersOnDisabledAccountDetector()
	// SID ending in -512 (Domain Admins) is well-known privileged.
	sd := buildSDWithTrustee(512)
	users := []types.User{
		{SAMAccountName: "svc$", IsGMSA: true, GMSAMembership: sd, Disabled: true},
	}
	findings := d.Detect(context.Background(), newData(users))
	if findings[0].Count != 0 {
		t.Fatalf("expected count 0 for disabled gMSA with only a privileged reader, got %d", findings[0].Count)
	}
}

// TestGMSAPasswordReadersOnDisabledAccount_TypeAndSeverity locks the
// finding's identifying fields, in particular the Medium severity mandated
// by the split severity grid (D1) for a secret exposed regardless of
// account state.
func TestGMSAPasswordReadersOnDisabledAccount_TypeAndSeverity(t *testing.T) {
	data := &audit.DetectorData{}
	f := NewGMSAPasswordReadersOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Type != "GMSA_PASSWORD_READERS_ON_DISABLED_ACCOUNT" {
		t.Fatalf("Type = %q, want %q", f.Type, "GMSA_PASSWORD_READERS_ON_DISABLED_ACCOUNT")
	}
	if f.Severity != types.SeverityMedium {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityMedium)
	}
}

// TestGMSAPasswordReadersPartition_ExhaustiveAndDisjoint proves the
// acceptance criterion that both halves of the split share exactly the
// same non-privileged-reader condition and partition the same gMSA
// population without overlap: for a fixed set of gMSAs each carrying a
// non-privileged reader, every gMSA lands in exactly one of the two
// detectors, split only on Disabled, and the two AffectedEntities sets are
// disjoint.
func TestGMSAPasswordReadersPartition_ExhaustiveAndDisjoint(t *testing.T) {
	sd1 := buildSDWithTrustee(8001)
	sd2 := buildSDWithTrustee(8002)
	sd3 := buildSDWithTrustee(8003)
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{DN: "CN=svc1,DC=contoso,DC=com", SAMAccountName: "svc1$", IsGMSA: true, GMSAMembership: sd1, Disabled: false},
			{DN: "CN=svc2,DC=contoso,DC=com", SAMAccountName: "svc2$", IsGMSA: true, GMSAMembership: sd2, Disabled: false},
			{DN: "CN=svc3,DC=contoso,DC=com", SAMAccountName: "svc3$", IsGMSA: true, GMSAMembership: sd3, Disabled: true},
		},
	}

	active := NewGMSAPasswordReadersDetector().Detect(context.Background(), data)
	disabled := NewGMSAPasswordReadersOnDisabledAccountDetector().Detect(context.Background(), data)

	if len(active) != 1 || active[0].Count != 2 {
		t.Fatalf("active findings = %+v, want 1 finding with count 2", active)
	}
	if len(disabled) != 1 || disabled[0].Count != 1 {
		t.Fatalf("disabled findings = %+v, want 1 finding with count 1", disabled)
	}
	if active[0].Count+disabled[0].Count != len(data.Users) {
		t.Fatalf("partition not exhaustive: active=%d + disabled=%d != total=%d", active[0].Count, disabled[0].Count, len(data.Users))
	}

	seen := map[string]bool{}
	for _, e := range active[0].AffectedEntities {
		seen[e.SAMAccountName] = true
	}
	for _, e := range disabled[0].AffectedEntities {
		if seen[e.SAMAccountName] {
			t.Fatalf("%s appears in both the active and disabled-account finding: partition is not disjoint", e.SAMAccountName)
		}
	}
}
