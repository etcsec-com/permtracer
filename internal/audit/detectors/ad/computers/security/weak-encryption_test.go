package security

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

const (
	weakEncRC4Only = 0x4  // RC4_HMAC only
	weakEncAES256  = 0x10 // AES256 only
)

// TestWeakEncryption_Fires confirms the detector counts an active computer
// configured with RC4 only (no AES).
func TestWeakEncryption_Fires(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=SVR01,DC=example,DC=com", SAMAccountName: "SVR01$", SupportedEncryptionTypes: weakEncRC4Only},
		},
	}
	findings := NewWeakEncryptionDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityMedium {
		t.Fatalf("Severity = %s, want medium", findings[0].Severity)
	}
}

// TestWeakEncryption_AESSupportNotCounted confirms a computer that also
// supports AES is not counted as weak.
func TestWeakEncryption_AESSupportNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=SVR02,DC=example,DC=com", SupportedEncryptionTypes: weakEncAES256},
		},
	}
	findings := NewWeakEncryptionDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestComputerWeakEncryptionPartition checks that the active (Medium) and
// disabled-account (Low) detectors partition the same population: every
// computer with weak encryption configured lands in exactly one of them, or
// neither, never both.
func TestComputerWeakEncryptionPartition(t *testing.T) {
	cases := []struct {
		name         string
		computer     types.Computer
		wantActive   int
		wantDisabled int
	}{
		{
			name:       "active computer with RC4 only fires the active detector only",
			computer:   types.Computer{DN: "CN=SVR01,DC=example,DC=com", SupportedEncryptionTypes: weakEncRC4Only, Disabled: false},
			wantActive: 1, wantDisabled: 0,
		},
		{
			name:       "disabled computer with RC4 only fires the disabled-account detector only",
			computer:   types.Computer{DN: "CN=SVR02,DC=example,DC=com", SupportedEncryptionTypes: weakEncRC4Only, Disabled: true},
			wantActive: 0, wantDisabled: 1,
		},
		{
			name:       "active computer with AES support fires neither",
			computer:   types.Computer{DN: "CN=SVR03,DC=example,DC=com", SupportedEncryptionTypes: weakEncAES256, Disabled: false},
			wantActive: 0, wantDisabled: 0,
		},
		{
			name:       "disabled computer with AES support fires neither",
			computer:   types.Computer{DN: "CN=SVR04,DC=example,DC=com", SupportedEncryptionTypes: weakEncAES256, Disabled: true},
			wantActive: 0, wantDisabled: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{Computers: []types.Computer{tc.computer}}

			active := NewWeakEncryptionDetector().Detect(context.Background(), data)
			if active[0].Count != tc.wantActive {
				t.Fatalf("COMPUTER_WEAK_ENCRYPTION Count = %d, want %d", active[0].Count, tc.wantActive)
			}

			disabled := NewWeakEncryptionOnDisabledAccountDetector().Detect(context.Background(), data)
			if disabled[0].Count != tc.wantDisabled {
				t.Fatalf("COMPUTER_WEAK_ENCRYPTION_ON_DISABLED_ACCOUNT Count = %d, want %d", disabled[0].Count, tc.wantDisabled)
			}
		})
	}
}

func TestWeakEncryptionOnDisabledAccount_SeverityIsLow(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=SVR02,DC=example,DC=com", SAMAccountName: "SVR02$", SupportedEncryptionTypes: weakEncRC4Only, Disabled: true},
		},
	}
	findings := NewWeakEncryptionOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Severity != types.SeverityLow {
		t.Fatalf("Severity = %s, want low", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "SVR02$" {
		t.Fatalf("AffectedEntities = %+v, want only SVR02$", findings[0].AffectedEntities)
	}
}
