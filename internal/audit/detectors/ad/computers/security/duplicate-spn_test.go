package security

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestDuplicateSpn_EntityOrderIsDeterministic exists because
// duplicateComputers is a map keyed by DN, so ranging it directly to build
// the affected slice would give a randomized order per process. With several
// duplicated computers, an unsorted range would very rarely land in DN order
// by chance across repeated calls - asserting the exact expected order pins
// the sort.
func TestDuplicateSpn_EntityOrderIsDeterministic(t *testing.T) {
	const domainDN = "DC=example,DC=com"
	names := []string{"WKS-ZULU", "WKS-ALPHA", "WKS-MIKE", "WKS-BRAVO"}
	spn := "HOST/shared-spn.example.com"

	var computers []types.Computer
	for _, n := range names {
		computers = append(computers, types.Computer{
			DN:                    "CN=" + n + ",OU=Computers," + domainDN,
			SAMAccountName:        n + "$",
			ServicePrincipalNames: []string{spn},
		})
	}

	want := []string{
		"CN=WKS-ALPHA,OU=Computers," + domainDN,
		"CN=WKS-BRAVO,OU=Computers," + domainDN,
		"CN=WKS-MIKE,OU=Computers," + domainDN,
		"CN=WKS-ZULU,OU=Computers," + domainDN,
	}

	data := &audit.DetectorData{IncludeDetails: true, Computers: computers}

	for i := 0; i < 5; i++ {
		findings := NewDuplicateSpnDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("run %d: expected exactly 1 finding, got %d", i, len(findings))
		}
		ents := findings[0].AffectedEntities
		if len(ents) != len(want) {
			t.Fatalf("run %d: expected %d entities, got %d (%v)", i, len(want), len(ents), ents)
		}
		for j, ent := range ents {
			if ent.DN != want[j] {
				t.Fatalf("run %d: entity order not deterministic - position %d = %q, want %q", i, j, ent.DN, want[j])
			}
		}
	}
}

// TestDuplicateSpn_CaseInsensitiveMatch exists because SPNs that differ only
// in case still collide at the KDC; the detector must normalize before
// grouping, or two case variants of the same SPN would be treated as
// distinct and never flagged.
func TestDuplicateSpn_CaseInsensitiveMatch(t *testing.T) {
	const domainDN = "DC=example,DC=com"
	computers := []types.Computer{
		{
			DN:                    "CN=WKS-CASE-A,OU=Computers," + domainDN,
			SAMAccountName:        "WKS-CASE-A$",
			ServicePrincipalNames: []string{"HTTP/web.example.test"},
		},
		{
			DN:                    "CN=WKS-CASE-B,OU=Computers," + domainDN,
			SAMAccountName:        "WKS-CASE-B$",
			ServicePrincipalNames: []string{"http/WEB.example.test"},
		},
		{
			DN:                    "CN=WKS-CASE-OTHER,OU=Computers," + domainDN,
			SAMAccountName:        "WKS-CASE-OTHER$",
			ServicePrincipalNames: []string{"HTTP/other.example.test"},
		},
	}

	data := &audit.DetectorData{IncludeDetails: true, Computers: computers}
	findings := NewDuplicateSpnDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 2 {
		t.Fatalf("expected Count=2 for case-differing duplicate SPNs, got %d", findings[0].Count)
	}

	want := []string{
		"CN=WKS-CASE-A,OU=Computers," + domainDN,
		"CN=WKS-CASE-B,OU=Computers," + domainDN,
	}
	ents := findings[0].AffectedEntities
	if len(ents) != len(want) {
		t.Fatalf("expected %d affected entities, got %d (%v)", len(want), len(ents), ents)
	}
	for i, ent := range ents {
		if ent.DN != want[i] {
			t.Fatalf("entity %d = %q, want %q", i, ent.DN, want[i])
		}
	}
}

// TestDuplicateSpn_ExactlyTwoCarriersThreshold exists because the detector
// must flag a SPN shared by exactly two computers while leaving a
// single-carrier SPN uncounted.
func TestDuplicateSpn_ExactlyTwoCarriersThreshold(t *testing.T) {
	const domainDN = "DC=example,DC=com"
	computers := []types.Computer{
		{
			DN:                    "CN=WKS-THR-A,OU=Computers," + domainDN,
			SAMAccountName:        "WKS-THR-A$",
			ServicePrincipalNames: []string{"HOST/shared-two.example.test"},
		},
		{
			DN:                    "CN=WKS-THR-B,OU=Computers," + domainDN,
			SAMAccountName:        "WKS-THR-B$",
			ServicePrincipalNames: []string{"HOST/shared-two.example.test"},
		},
		{
			DN:                    "CN=WKS-THR-SOLO,OU=Computers," + domainDN,
			SAMAccountName:        "WKS-THR-SOLO$",
			ServicePrincipalNames: []string{"HOST/solo.example.test"},
		},
	}

	data := &audit.DetectorData{IncludeDetails: true, Computers: computers}
	findings := NewDuplicateSpnDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 2 {
		t.Fatalf("expected Count=2 for exactly-two-carrier SPN, got %d", findings[0].Count)
	}

	want := []string{
		"CN=WKS-THR-A,OU=Computers," + domainDN,
		"CN=WKS-THR-B,OU=Computers," + domainDN,
	}
	ents := findings[0].AffectedEntities
	if len(ents) != len(want) {
		t.Fatalf("expected %d affected entities, got %d (%v)", len(want), len(ents), ents)
	}
	for i, ent := range ents {
		if ent.DN != want[i] {
			t.Fatalf("entity %d = %q, want %q", i, ent.DN, want[i])
		}
	}
}
