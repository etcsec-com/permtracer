package security

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestLegacyProtocolOnDisabledAccount_Fires confirms the twin counts a
// disabled computer running a legacy OS.
func TestLegacyProtocolOnDisabledAccount_FiresOnLegacyOS(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WKS01,DC=example,DC=com", SAMAccountName: "WKS01$", Disabled: true, OperatingSystem: "Windows XP Professional"},
		},
	}
	findings := NewLegacyProtocolOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityLow {
		t.Fatalf("Severity = %s, want low", findings[0].Severity)
	}
}

// TestLegacyProtocolOnDisabledAccount_FiresOnWeakEncryption confirms the
// twin counts a disabled computer with no AES encryption type.
func TestLegacyProtocolOnDisabledAccount_FiresOnWeakEncryption(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WKS02,DC=example,DC=com", SAMAccountName: "WKS02$", Disabled: true, OperatingSystem: "Windows 10 Enterprise", SupportedEncryptionTypes: 4},
		},
	}
	findings := NewLegacyProtocolOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
}

// TestLegacyProtocolOnDisabledAccount_EnabledNotCounted confirms an enabled
// computer matching the condition is not counted by the twin.
func TestLegacyProtocolOnDisabledAccount_EnabledNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WKS03,DC=example,DC=com", SAMAccountName: "WKS03$", Disabled: false, OperatingSystem: "Windows XP Professional"},
		},
	}
	findings := NewLegacyProtocolOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 for an enabled computer", findings[0].Count)
	}
}

// TestLegacyProtocolOnDisabledAccount_DisabledNotMatchingNotCounted
// confirms a disabled computer that matches neither branch is not counted.
func TestLegacyProtocolOnDisabledAccount_DisabledNotMatchingNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WKS04,DC=example,DC=com", SAMAccountName: "WKS04$", Disabled: true, OperatingSystem: "Windows 10 Enterprise"},
		},
	}
	findings := NewLegacyProtocolOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 for a disabled computer matching neither branch", findings[0].Count)
	}
}

// TestLegacyProtocolOnDisabledAccount_AES128AloneNotCounted confirms a
// disabled computer with AES128 alone (bit 0x08 set, 0x10 clear) is not
// counted. Kills a mask drift from 0x18 to 0x10, which would treat AES128
// alone as "no AES" and wrongly count it.
func TestLegacyProtocolOnDisabledAccount_AES128AloneNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WKS07,DC=example,DC=com", SAMAccountName: "WKS07$", Disabled: true, OperatingSystem: "Windows Server 2019", SupportedEncryptionTypes: 8},
		},
	}
	findings := NewLegacyProtocolOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 for a disabled computer with AES128 alone", findings[0].Count)
	}
}

// TestLegacyProtocolOnDisabledAccount_AES256AloneNotCounted confirms a
// disabled computer with AES256 alone (bit 0x10 set, 0x08 clear) is not
// counted. Kills a mask drift from 0x18 to 0x08, which would treat AES256
// alone as "no AES" and wrongly count it.
func TestLegacyProtocolOnDisabledAccount_AES256AloneNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WKS08,DC=example,DC=com", SAMAccountName: "WKS08$", Disabled: true, OperatingSystem: "Windows Server 2019", SupportedEncryptionTypes: 16},
		},
	}
	findings := NewLegacyProtocolOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 for a disabled computer with AES256 alone", findings[0].Count)
	}
}

// TestLegacyProtocolOnDisabledAccount_LegacyOSAndWeakEncryptionCountsOnce
// confirms a disabled computer matching both branches (legacy OS and weak
// encryption) is counted exactly once. Kills a missing continue after the
// OS-match branch, which would append the same computer a second time.
func TestLegacyProtocolOnDisabledAccount_LegacyOSAndWeakEncryptionCountsOnce(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WKS09,DC=example,DC=com", SAMAccountName: "WKS09$", Disabled: true, OperatingSystem: "Windows XP Professional", SupportedEncryptionTypes: 4},
		},
	}
	findings := NewLegacyProtocolOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 for a disabled computer matching both branches", findings[0].Count)
	}
}

// TestComputerLegacyProtocolPartition checks that the active (Medium) and
// disabled-account (Low) detectors partition the same population: every
// computer matching either branch of the condition lands in exactly one of
// them, or neither, never both.
func TestComputerLegacyProtocolPartition(t *testing.T) {
	cases := []struct {
		name         string
		computer     types.Computer
		wantActive   int
		wantDisabled int
	}{
		{
			name:       "active computer with legacy OS fires the active detector only",
			computer:   types.Computer{DN: "CN=WKS01,DC=example,DC=com", OperatingSystem: "Windows XP Professional", Disabled: false},
			wantActive: 1, wantDisabled: 0,
		},
		{
			name:       "disabled computer with legacy OS fires the disabled-account detector only",
			computer:   types.Computer{DN: "CN=WKS02,DC=example,DC=com", OperatingSystem: "Windows XP Professional", Disabled: true},
			wantActive: 0, wantDisabled: 1,
		},
		{
			name:       "active computer with weak encryption fires the active detector only",
			computer:   types.Computer{DN: "CN=WKS03,DC=example,DC=com", OperatingSystem: "Windows 10 Enterprise", SupportedEncryptionTypes: 4, Disabled: false},
			wantActive: 1, wantDisabled: 0,
		},
		{
			name:       "disabled computer with weak encryption fires the disabled-account detector only",
			computer:   types.Computer{DN: "CN=WKS04,DC=example,DC=com", OperatingSystem: "Windows 10 Enterprise", SupportedEncryptionTypes: 4, Disabled: true},
			wantActive: 0, wantDisabled: 1,
		},
		{
			name:       "active computer matching neither branch fires neither",
			computer:   types.Computer{DN: "CN=WKS05,DC=example,DC=com", OperatingSystem: "Windows 10 Enterprise", Disabled: false},
			wantActive: 0, wantDisabled: 0,
		},
		{
			name:       "disabled computer matching neither branch fires neither",
			computer:   types.Computer{DN: "CN=WKS06,DC=example,DC=com", OperatingSystem: "Windows 10 Enterprise", Disabled: true},
			wantActive: 0, wantDisabled: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{Computers: []types.Computer{tc.computer}}

			active := NewLegacyProtocolDetector().Detect(context.Background(), data)
			if active[0].Count != tc.wantActive {
				t.Fatalf("COMPUTER_LEGACY_PROTOCOL Count = %d, want %d", active[0].Count, tc.wantActive)
			}

			disabled := NewLegacyProtocolOnDisabledAccountDetector().Detect(context.Background(), data)
			if disabled[0].Count != tc.wantDisabled {
				t.Fatalf("COMPUTER_LEGACY_PROTOCOL_ON_DISABLED_ACCOUNT Count = %d, want %d", disabled[0].Count, tc.wantDisabled)
			}
		})
	}
}

// TestComputerLegacyProtocolPartitionSumsToTotal checks, on a mixed
// population, that active count + disabled-account count equals the total
// that would match the condition with no account-state guard at all.
func TestComputerLegacyProtocolPartitionSumsToTotal(t *testing.T) {
	computers := []types.Computer{
		{DN: "CN=A,DC=example,DC=com", OperatingSystem: "Windows XP Professional", Disabled: false},
		{DN: "CN=B,DC=example,DC=com", OperatingSystem: "Windows XP Professional", Disabled: true},
		{DN: "CN=C,DC=example,DC=com", OperatingSystem: "Windows 10 Enterprise", SupportedEncryptionTypes: 4, Disabled: false},
		{DN: "CN=D,DC=example,DC=com", OperatingSystem: "Windows 10 Enterprise", SupportedEncryptionTypes: 4, Disabled: true},
		{DN: "CN=E,DC=example,DC=com", OperatingSystem: "Windows 10 Enterprise", Disabled: false},
		{DN: "CN=F,DC=example,DC=com", OperatingSystem: "Windows 10 Enterprise", Disabled: true},
	}

	wantTotal := 0
	for _, c := range computers {
		hasLegacyOS := false
		for _, pattern := range legacyOSPatterns {
			if pattern.MatchString(c.OperatingSystem) {
				hasLegacyOS = true
				break
			}
		}
		if hasLegacyOS {
			wantTotal++
			continue
		}
		if c.SupportedEncryptionTypes != 0 && (c.SupportedEncryptionTypes&0x18) == 0 {
			wantTotal++
		}
	}

	data := &audit.DetectorData{Computers: computers}
	active := NewLegacyProtocolDetector().Detect(context.Background(), data)
	disabled := NewLegacyProtocolOnDisabledAccountDetector().Detect(context.Background(), data)

	if got := active[0].Count + disabled[0].Count; got != wantTotal {
		t.Fatalf("active.Count + disabled.Count = %d, want %d (unguarded total)", got, wantTotal)
	}
}
