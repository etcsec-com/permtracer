package kerberos

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func TestDelegationUnknownTargetOnDisabledAccount(t *testing.T) {
	t.Run("disabled user with unknown SPN target fires here", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: "CN=svc,OU=Services,DC=test,DC=local", SAMAccountName: "svc", Disabled: true, AllowedToDelegateTo: []string{"cifs/ghost.test.local"}},
			},
			IncludeDetails: true,
		}
		findings := NewDelegationUnknownTargetOnDisabledAccountDetector().Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Count != 1 {
			t.Fatalf("disabled user with an unknown SPN target must fire here, got %+v", findings)
		}
		if findings[0].Severity != types.SeverityLow {
			t.Fatalf("disabled half must be Low, got %s", findings[0].Severity)
		}
	})

	t.Run("disabled computer with unknown SPN target fires here", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{
				{DN: "CN=SRV01,OU=Computers,DC=test,DC=local", SAMAccountName: "SRV01$", Disabled: true, AllowedToDelegateTo: []string{"cifs/ghost.test.local"}},
			},
			IncludeDetails: true,
		}
		findings := NewDelegationUnknownTargetOnDisabledAccountDetector().Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Count != 1 {
			t.Fatalf("disabled computer with an unknown SPN target must fire here, got %+v", findings)
		}
	})

	t.Run("active user with unknown SPN target does NOT fire here", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: "CN=svc,OU=Services,DC=test,DC=local", SAMAccountName: "svc", AllowedToDelegateTo: []string{"cifs/ghost.test.local"}},
			},
		}
		findings := NewDelegationUnknownTargetOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("an active user must not be counted by the disabled-account detector, got count=%d", findings[0].Count)
		}
	})

	t.Run("active computer with unknown SPN target does NOT fire here", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{
				{DN: "CN=SRV01,OU=Computers,DC=test,DC=local", SAMAccountName: "SRV01$", AllowedToDelegateTo: []string{"cifs/ghost.test.local"}},
			},
		}
		findings := NewDelegationUnknownTargetOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("an active computer must not be counted by the disabled-account detector, got count=%d", findings[0].Count)
		}
	})

	t.Run("disabled user with no delegation target does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{{DN: "CN=svc,OU=Services,DC=test,DC=local", SAMAccountName: "svc", Disabled: true}},
		}
		findings := NewDelegationUnknownTargetOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("a disabled user with no delegation target must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("disabled user whose delegation target resolves to a known computer does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{
				{DN: "CN=SRV01,OU=Computers,DC=test,DC=local", SAMAccountName: "SRV01$", DNSHostName: "srv01.test.local"},
			},
			Users: []types.User{
				{DN: "CN=svc,OU=Services,DC=test,DC=local", SAMAccountName: "svc", Disabled: true, AllowedToDelegateTo: []string{"cifs/srv01.test.local"}},
			},
		}
		findings := NewDelegationUnknownTargetOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("a disabled user whose delegation target resolves to a known computer must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("disabled computer with no delegation target does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{{DN: "CN=SRV01,OU=Computers,DC=test,DC=local", SAMAccountName: "SRV01$", Disabled: true}},
		}
		findings := NewDelegationUnknownTargetOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("a disabled computer with no delegation target must not fire, got count=%d", findings[0].Count)
		}
	})
}

// TestDelegationUnknownTargetPartition_ExhaustiveAndDisjoint covers both
// branches (Users and Computers), active and disabled, ensuring the two
// detectors classify every account with an unknown delegation target exactly
// once - no account counted twice, no account dropped.
func TestDelegationUnknownTargetPartition_ExhaustiveAndDisjoint(t *testing.T) {
	users := []types.User{
		{DN: "CN=active-unknown,OU=Services,DC=test,DC=local", SAMAccountName: "active-unknown", AllowedToDelegateTo: []string{"cifs/ghost.test.local"}},
		{DN: "CN=disabled-unknown,OU=Services,DC=test,DC=local", SAMAccountName: "disabled-unknown", Disabled: true, AllowedToDelegateTo: []string{"cifs/ghost.test.local"}},
		{DN: "CN=active-known,OU=Services,DC=test,DC=local", SAMAccountName: "active-known", AllowedToDelegateTo: []string{"cifs/srv01.test.local"}},
		{DN: "CN=disabled-known,OU=Services,DC=test,DC=local", SAMAccountName: "disabled-known", Disabled: true, AllowedToDelegateTo: []string{"cifs/srv01.test.local"}},
		{DN: "CN=neither,OU=Services,DC=test,DC=local", SAMAccountName: "neither"},
	}
	computers := []types.Computer{
		{DN: "CN=SRV01,OU=Computers,DC=test,DC=local", SAMAccountName: "SRV01$", DNSHostName: "srv01.test.local"},
		{DN: "CN=active-comp-unknown,OU=Computers,DC=test,DC=local", SAMAccountName: "active-comp-unknown$", AllowedToDelegateTo: []string{"cifs/ghost.test.local"}},
		{DN: "CN=disabled-comp-unknown,OU=Computers,DC=test,DC=local", SAMAccountName: "disabled-comp-unknown$", Disabled: true, AllowedToDelegateTo: []string{"cifs/ghost.test.local"}},
	}
	data := &audit.DetectorData{Users: users, Computers: computers, IncludeDetails: true}

	active := NewDelegationUnknownTargetDetector().Detect(context.Background(), data)
	disabled := NewDelegationUnknownTargetOnDisabledAccountDetector().Detect(context.Background(), data)

	if active[0].Count != 2 {
		t.Fatalf("active half: want 2 (active-unknown, active-comp-unknown), got %d", active[0].Count)
	}
	if disabled[0].Count != 2 {
		t.Fatalf("disabled half: want 2 (disabled-unknown, disabled-comp-unknown), got %d", disabled[0].Count)
	}
	if active[0].Count+disabled[0].Count != 4 {
		t.Fatalf("partition must total 4 accounts with an unknown delegation target, got %d", active[0].Count+disabled[0].Count)
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
