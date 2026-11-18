package kerberos

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func TestKerberosRc4FallbackOnDisabledAccount(t *testing.T) {
	userDN := "CN=svc,OU=Services,DC=test,DC=local"

	t.Run("disabled account with RC4+AES128+AES256 fires here", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, SupportedEncryptionTypes: 28},
			},
			IncludeDetails: true,
		}
		findings := NewKerberosRc4FallbackOnDisabledAccountDetector().Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Count != 1 {
			t.Fatalf("disabled account with RC4+AES must fire here, got %+v", findings)
		}
		if findings[0].Severity != types.SeverityLow {
			t.Fatalf("disabled half must be Low, got %s", findings[0].Severity)
		}
	})

	t.Run("active account with RC4+AES128+AES256 does NOT fire here", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 28},
			},
		}
		findings := NewKerberosRc4FallbackOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("an active account must not be counted by the disabled-account detector, got count=%d", findings[0].Count)
		}
	})

	t.Run("disabled account with RC4 only, no AES, does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, SupportedEncryptionTypes: 4},
			},
		}
		findings := NewKerberosRc4FallbackOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("a disabled account with RC4 only (no AES bit) must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("disabled account with attribute never set (0) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, SupportedEncryptionTypes: 0},
			},
		}
		findings := NewKerberosRc4FallbackOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("a disabled account with the attribute never set must not fire, got count=%d", findings[0].Count)
		}
	})
}

// TestKerberosRc4FallbackPartition_ExhaustiveAndDisjoint proves the
// acceptance criterion that both halves of the split share exactly the same
// RC4-fallback condition and partition the same population without overlap:
// for a fixed set of accounts carrying the RC4+AES configuration, every
// account lands in exactly one of the two detectors, split only on Disabled,
// and the two AffectedEntities sets are disjoint.
func TestKerberosRc4FallbackPartition_ExhaustiveAndDisjoint(t *testing.T) {
	users := []types.User{
		{DN: "CN=active-1,OU=Services,DC=test,DC=local", SAMAccountName: "active-1", SupportedEncryptionTypes: 28},
		{DN: "CN=active-2,OU=Services,DC=test,DC=local", SAMAccountName: "active-2", SupportedEncryptionTypes: 12},
		{DN: "CN=disabled-1,OU=Services,DC=test,DC=local", SAMAccountName: "disabled-1", Disabled: true, SupportedEncryptionTypes: 28},
		{DN: "CN=neither,OU=Services,DC=test,DC=local", SAMAccountName: "neither", SupportedEncryptionTypes: 24},
	}
	data := &audit.DetectorData{Users: users, IncludeDetails: true}

	active := NewKerberosRc4FallbackDetector().Detect(context.Background(), data)
	disabled := NewKerberosRc4FallbackOnDisabledAccountDetector().Detect(context.Background(), data)

	if active[0].Count != 2 {
		t.Fatalf("active half: want 2 (active-1, active-2), got %d", active[0].Count)
	}
	if disabled[0].Count != 1 {
		t.Fatalf("disabled half: want 1 (disabled-1), got %d", disabled[0].Count)
	}
	if active[0].Count+disabled[0].Count != 3 {
		t.Fatalf("partition must total 3 accounts with RC4+AES (4 users minus 1 with neither signal), got %d", active[0].Count+disabled[0].Count)
	}

	seen := make(map[string]bool)
	for _, e := range active[0].AffectedEntities {
		seen[e.SAMAccountName] = true
	}
	for _, e := range disabled[0].AffectedEntities {
		if seen[e.SAMAccountName] {
			t.Fatalf("%s appears in both the active and disabled-account finding: partition is not disjoint", e.SAMAccountName)
		}
	}
}
