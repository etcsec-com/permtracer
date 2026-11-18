package security

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

const testServerTrustAccount = 0x2000

// TestNoLapsOnDisabledAccount_Fires confirms the twin counts a disabled
// computer with neither legacy nor Windows LAPS configured.
func TestNoLapsOnDisabledAccount_Fires(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WKS01,DC=example,DC=com", SAMAccountName: "WKS01$", Disabled: true},
		},
	}
	findings := NewNoLapsOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityLow {
		t.Fatalf("Severity = %s, want low", findings[0].Severity)
	}
}

// TestNoLapsOnDisabledAccount_EnabledNotCounted confirms an enabled
// computer without LAPS is not counted by the twin.
func TestNoLapsOnDisabledAccount_EnabledNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WKS02,DC=example,DC=com", SAMAccountName: "WKS02$", Disabled: false},
		},
	}
	findings := NewNoLapsOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 for an enabled computer", findings[0].Count)
	}
}

// TestNoLapsOnDisabledAccount_DisabledWithLapsNotCounted confirms a
// disabled computer that has LAPS configured is not counted.
func TestNoLapsOnDisabledAccount_DisabledWithLapsNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WKS03,DC=example,DC=com", SAMAccountName: "WKS03$", Disabled: true, HasWindowsLAPS: true},
		},
	}
	findings := NewNoLapsOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 for a disabled computer with Windows LAPS configured", findings[0].Count)
	}
}

// TestNoLapsOnDisabledAccount_DisabledDomainControllerNotCounted confirms
// the same Domain Controller exclusion as the active detector applies to
// the twin: a disabled DC without LAPS is not counted, since DCs never use
// LAPS regardless of account state.
func TestNoLapsOnDisabledAccount_DisabledDomainControllerNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=DC01,DC=example,DC=com", SAMAccountName: "DC01$", Disabled: true, UserAccountControl: testServerTrustAccount},
		},
	}
	findings := NewNoLapsOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 for a disabled Domain Controller", findings[0].Count)
	}
}

// TestComputerNoLapsPartition checks that the active and disabled-account
// detectors partition the same population: every non-DC computer without
// LAPS lands in exactly one of them, or neither, never both.
func TestComputerNoLapsPartition(t *testing.T) {
	cases := []struct {
		name         string
		computer     types.Computer
		wantActive   int
		wantDisabled int
	}{
		{
			name:       "active computer without LAPS fires the active detector only",
			computer:   types.Computer{DN: "CN=WKS01,DC=example,DC=com", Disabled: false},
			wantActive: 1, wantDisabled: 0,
		},
		{
			name:       "disabled computer without LAPS fires the disabled-account detector only",
			computer:   types.Computer{DN: "CN=WKS02,DC=example,DC=com", Disabled: true},
			wantActive: 0, wantDisabled: 1,
		},
		{
			name:       "active computer with LAPS fires neither",
			computer:   types.Computer{DN: "CN=WKS03,DC=example,DC=com", Disabled: false, HasLegacyLAPS: true},
			wantActive: 0, wantDisabled: 0,
		},
		{
			name:       "disabled computer with LAPS fires neither",
			computer:   types.Computer{DN: "CN=WKS04,DC=example,DC=com", Disabled: true, HasLegacyLAPS: true},
			wantActive: 0, wantDisabled: 0,
		},
		{
			name:       "enabled Domain Controller without LAPS fires neither",
			computer:   types.Computer{DN: "CN=DC01,DC=example,DC=com", Disabled: false, UserAccountControl: testServerTrustAccount},
			wantActive: 0, wantDisabled: 0,
		},
		{
			name:       "disabled Domain Controller without LAPS fires neither",
			computer:   types.Computer{DN: "CN=DC02,DC=example,DC=com", Disabled: true, UserAccountControl: testServerTrustAccount},
			wantActive: 0, wantDisabled: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{Computers: []types.Computer{tc.computer}}

			active := NewNoLapsDetector().Detect(context.Background(), data)
			if active[0].Count != tc.wantActive {
				t.Fatalf("COMPUTER_NO_LAPS Count = %d, want %d", active[0].Count, tc.wantActive)
			}

			disabled := NewNoLapsOnDisabledAccountDetector().Detect(context.Background(), data)
			if disabled[0].Count != tc.wantDisabled {
				t.Fatalf("COMPUTER_NO_LAPS_ON_DISABLED_ACCOUNT Count = %d, want %d", disabled[0].Count, tc.wantDisabled)
			}
		})
	}
}

// TestComputerNoLapsPartitionSumsToTotal checks, on a mixed population,
// that active count + disabled-account count equals the total that would
// match the condition (no LAPS, not a Domain Controller) with no
// account-state guard at all.
func TestComputerNoLapsPartitionSumsToTotal(t *testing.T) {
	computers := []types.Computer{
		{DN: "CN=A,DC=example,DC=com", Disabled: false},
		{DN: "CN=B,DC=example,DC=com", Disabled: true},
		{DN: "CN=C,DC=example,DC=com", Disabled: false, HasWindowsLAPS: true},
		{DN: "CN=D,DC=example,DC=com", Disabled: true, HasLegacyLAPS: true},
		{DN: "CN=E,DC=example,DC=com", Disabled: false, UserAccountControl: testServerTrustAccount},
		{DN: "CN=F,DC=example,DC=com", Disabled: true, UserAccountControl: testServerTrustAccount},
	}

	wantTotal := 0
	for _, c := range computers {
		if (c.UserAccountControl & testServerTrustAccount) != 0 {
			continue
		}
		if !c.HasLegacyLAPS && !c.HasWindowsLAPS {
			wantTotal++
		}
	}

	data := &audit.DetectorData{Computers: computers}
	active := NewNoLapsDetector().Detect(context.Background(), data)
	disabled := NewNoLapsOnDisabledAccountDetector().Detect(context.Background(), data)

	if got := active[0].Count + disabled[0].Count; got != wantTotal {
		t.Fatalf("active.Count + disabled.Count = %d, want %d (unguarded total)", got, wantTotal)
	}
}
