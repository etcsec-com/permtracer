package organization

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestDCNotInDCOU_RealDCInDCOUIsNotFlagged covers a false positive
// (allume_a_tort=true): the detector read c.DistinguishedName, an "alias
// for DN" field parseComputer never assigns - only DN is populated. On
// real pipeline data DistinguishedName is always "", so isInDCOU was always
// false and every real DC (correctly placed in the Domain Controllers OU)
// was wrongly flagged High.
func TestDCNotInDCOU_RealDCInDCOUIsNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				// Only DN set, matching what parseComputer actually
				// produces - DistinguishedName is deliberately left empty.
				DN:                 "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com",
				SAMAccountName:     "DC01$",
				UserAccountControl: uacServerTrustAccount,
			},
		},
	}

	findings := NewDCNotInDCOUDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 (real DC correctly placed in the DC OU), got %d", findings[0].Count)
	}
}

// TestDCNotInDCOU_FiresOnRealMisplacedDC guards against over-filtering: a
// DC genuinely outside the Domain Controllers OU must still fire.
func TestDCNotInDCOU_FiresOnRealMisplacedDC(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:                 "CN=DC02,OU=Servers,DC=contoso,DC=com",
				SAMAccountName:     "DC02$",
				UserAccountControl: uacServerTrustAccount,
			},
		},
	}

	findings := NewDCNotInDCOUDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 (DC outside the DC OU), got %d", findings[0].Count)
	}
}

// TestDCNotInDCOU_NamedLikeDCWithoutUACBitNotCounted proves isDC no longer
// relies on sAMAccountName: a regular computer named like a DC, outside the
// Domain Controllers OU, without the SERVER_TRUST_ACCOUNT bit, must not be
// counted.
func TestDCNotInDCOU_NamedLikeDCWithoutUACBitNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:             "CN=DCIMPC01,OU=Workstations,DC=contoso,DC=com",
				SAMAccountName: "DCIMPC01$",
			},
		},
	}

	findings := NewDCNotInDCOUDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a computer named like a DC without the UAC bit must not be counted", findings[0].Count)
	}
}

// TestDCNotInDCOU_HostContainingDCWithoutUACBitNotCounted proves isDC no
// longer relies on dNSHostName: a regular computer whose hostname contains
// "dc", outside the Domain Controllers OU, without the SERVER_TRUST_ACCOUNT
// bit, must not be counted.
func TestDCNotInDCOU_HostContainingDCWithoutUACBitNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:             "CN=SRV01,OU=Workstations,DC=contoso,DC=com",
				SAMAccountName: "SRV01$",
				DNSHostName:    "srv-adc01.example.test",
			},
		},
	}

	findings := NewDCNotInDCOUDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a computer whose hostname contains \"dc\" without the UAC bit must not be counted", findings[0].Count)
	}
}

// TestDCNotInDCOU_ExcludesDisabledMisplacedDC covers the split guard: a
// disabled DC object outside the Domain Controllers OU must not be counted
// here - it is reported instead, at Medium, by
// DCNotInDCOUOnDisabledAccountDetector.
func TestDCNotInDCOU_ExcludesDisabledMisplacedDC(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:             "CN=DC03,OU=Servers,DC=contoso,DC=com",
				SAMAccountName: "DC03$",
				Disabled:       true,
			},
		},
	}

	findings := NewDCNotInDCOUDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a disabled misplaced DC must not fire in the active detector", findings[0].Count)
	}
}
