package organization

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestDCNotInDCOUOnDisabledAccount_DisabledMisplacedDCFires covers the
// nominal case: a disabled DC object outside the Domain Controllers OU
// must be flagged here.
func TestDCNotInDCOUOnDisabledAccount_DisabledMisplacedDCFires(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:                 "CN=DC01,OU=Servers,DC=contoso,DC=com",
				SAMAccountName:     "DC01$",
				Disabled:           true,
				UserAccountControl: uacServerTrustAccount,
			},
		},
	}

	findings := NewDCNotInDCOUOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: a disabled DC outside the DC OU must fire", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityMedium {
		t.Errorf("severity = %q, want medium", findings[0].Severity)
	}
}

// TestDCNotInDCOUOnDisabledAccount_ExcludesActiveDC is the guard's mutation
// kill: an enabled DC carrying the exact same misplaced DN a disabled true
// positive would must not fire here - it is reported instead, at High, by
// DCNotInDCOUDetector.
func TestDCNotInDCOUOnDisabledAccount_ExcludesActiveDC(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:             "CN=DC02,OU=Servers,DC=contoso,DC=com",
				SAMAccountName: "DC02$",
			},
		},
	}

	findings := NewDCNotInDCOUOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: an enabled DC with the exact same misplaced DN must not fire in the disabled-account detector", findings[0].Count)
	}
}

// TestDCNotInDCOUOnDisabledAccount_DisabledDCInOUNotFlagged covers the
// negative case: a disabled DC object correctly placed in the Domain
// Controllers OU must not fire.
func TestDCNotInDCOUOnDisabledAccount_DisabledDCInOUNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:                 "CN=DC04,OU=Domain Controllers,DC=contoso,DC=com",
				SAMAccountName:     "DC04$",
				Disabled:           true,
				UserAccountControl: uacServerTrustAccount,
			},
		},
	}

	findings := NewDCNotInDCOUOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a disabled DC correctly placed in the DC OU must not fire", findings[0].Count)
	}
}

// TestDCNotInDCOUOnDisabledAccount_DisabledNonDCNotFlagged covers the
// non-DC negative case: a disabled computer that matches none of isDC's
// three branches must not fire, even outside any OU.
func TestDCNotInDCOUOnDisabledAccount_DisabledNonDCNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:             "CN=PC05,OU=Workstations,DC=contoso,DC=com",
				SAMAccountName: "PC05$",
				Disabled:       true,
			},
		},
	}

	findings := NewDCNotInDCOUOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a disabled non-DC computer must not fire", findings[0].Count)
	}
}

// TestDCNotInDCOUOnDisabledAccount_NamedLikeDCWithoutUACBitNotCounted proves
// isDC no longer relies on sAMAccountName: a disabled regular computer named
// like a DC, outside the Domain Controllers OU, without the
// SERVER_TRUST_ACCOUNT bit, must not be counted.
func TestDCNotInDCOUOnDisabledAccount_NamedLikeDCWithoutUACBitNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:             "CN=DCIMPC01,OU=Workstations,DC=contoso,DC=com",
				SAMAccountName: "DCIMPC01$",
				Disabled:       true,
			},
		},
	}

	findings := NewDCNotInDCOUOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a disabled computer named like a DC without the UAC bit must not be counted", findings[0].Count)
	}
}

// TestDCNotInDCOUOnDisabledAccount_HostContainingDCWithoutUACBitNotCounted
// proves isDC no longer relies on dNSHostName: a disabled regular computer
// whose hostname contains "dc", outside the Domain Controllers OU, without
// the SERVER_TRUST_ACCOUNT bit, must not be counted.
func TestDCNotInDCOUOnDisabledAccount_HostContainingDCWithoutUACBitNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:             "CN=SRV01,OU=Workstations,DC=contoso,DC=com",
				SAMAccountName: "SRV01$",
				DNSHostName:    "srv-adc01.example.test",
				Disabled:       true,
			},
		},
	}

	findings := NewDCNotInDCOUOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a disabled computer whose hostname contains \"dc\" without the UAC bit must not be counted", findings[0].Count)
	}
}

// TestDCNotInDCOU_PartitionIsExhaustive covers both detectors together,
// against the condition evaluated with no Disabled guard at all: a
// matching object (isDC and outside the DC OU) is counted by exactly one
// of the two - active or disabled - never both, never neither.
func TestDCNotInDCOU_PartitionIsExhaustive(t *testing.T) {
	computers := []types.Computer{
		{DN: "CN=DC10,OU=Servers,DC=contoso,DC=com", SAMAccountName: "DC10$", UserAccountControl: uacServerTrustAccount},
		{DN: "CN=DC11,OU=Servers,DC=contoso,DC=com", SAMAccountName: "DC11$", Disabled: true, UserAccountControl: uacServerTrustAccount},
		{DN: "CN=DC12,OU=Domain Controllers,DC=contoso,DC=com", SAMAccountName: "DC12$", UserAccountControl: uacServerTrustAccount},
		{DN: "CN=DC13,OU=Domain Controllers,DC=contoso,DC=com", SAMAccountName: "DC13$", Disabled: true, UserAccountControl: uacServerTrustAccount},
		{DN: "CN=PC14,OU=Workstations,DC=contoso,DC=com", SAMAccountName: "PC14$"},
	}
	data := &audit.DetectorData{Computers: computers, IncludeDetails: true}

	// Total matching the condition (isDC and outside the DC OU) with no
	// Disabled guard applied, computed independently of either detector.
	wantTotal := 2 // DC10 (active, misplaced), DC11 (disabled, misplaced)

	active := NewDCNotInDCOUDetector().Detect(context.Background(), data)
	disabled := NewDCNotInDCOUOnDisabledAccountDetector().Detect(context.Background(), data)

	if active[0].Count != 1 {
		t.Fatalf("active half: want 1 (DC10), got %d", active[0].Count)
	}
	if disabled[0].Count != 1 {
		t.Fatalf("disabled half: want 1 (DC11), got %d", disabled[0].Count)
	}
	if got := active[0].Count + disabled[0].Count; got != wantTotal {
		t.Fatalf("active + disabled = %d, want %d (exact partition of the ungated condition)", got, wantTotal)
	}
}
