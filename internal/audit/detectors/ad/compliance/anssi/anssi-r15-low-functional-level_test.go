package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestR15FunctionalLevel_LowDomainLevel_DescriptionHasNoEmptyFragment proves
// the catalog-vs-runtime text fix: the previous "Current state: "+strings.Join(parts,
// "; ")+"." concatenation lost the dynamic parts entirely once cataloggen
// extracted the static literal for the catalog, leaving "Current state: ."
// there - but the fix must not regress the runtime Description either, which
// has to keep reporting the actual functional level values and must never
// start with "." or contain the empty "Current state: ." fragment.
func TestR15FunctionalLevel_LowDomainLevel_DescriptionHasNoEmptyFragment(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{
			DomainDN:                 "DC=example,DC=com",
			FunctionalLevelInt:       3,
			FunctionalLevel:          "Windows2008Domain",
			ForestFunctionalLevelInt: 7,
			ForestFunctionalLevel:    "Windows2016Forest",
		},
	}
	findings := NewR15FunctionalLevelDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	desc := findings[0].Description
	if strings.HasPrefix(desc, ".") {
		t.Errorf("Description starts with a leading '.': %q", desc)
	}
	if strings.Contains(desc, ": .") {
		t.Errorf("Description contains the empty-fragment pattern ': .': %q", desc)
	}
	if !strings.Contains(desc, "domain functional level = 3") {
		t.Errorf("Description dropped the dynamic domain level detail: %q", desc)
	}
}
