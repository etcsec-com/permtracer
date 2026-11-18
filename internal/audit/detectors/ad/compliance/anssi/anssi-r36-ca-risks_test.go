package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestR36CARisks_WeakSigAlgCA_DescriptionHasNoEmptyFragment proves the
// catalog-vs-runtime text fix: the previous strings.Join(parts, ". ")+". ANSSI
// R36 requires..." concatenation lost the dynamic parts entirely once
// cataloggen extracted the static literal for the catalog, leaving ". ANSSI
// R36 requires..." there - but the fix must not regress the runtime
// Description either, which has to keep reporting the actual CA finding and
// must never start with a leading ".".
func TestR36CARisks_WeakSigAlgCA_DescriptionHasNoEmptyFragment(t *testing.T) {
	data := &audit.DetectorData{
		CertAuthorities: []types.CertAuthority{
			{
				DN:           "CN=CA01,CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com",
				Name:         "CA01",
				CACertSigAlg: "SHA1-RSA",
			},
		},
	}
	findings := NewR36CARisksDetector().Detect(context.Background(), data)
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
	if !strings.Contains(desc, "CA cert signed with SHA1-RSA") {
		t.Errorf("Description dropped the dynamic CA finding detail: %q", desc)
	}
}
