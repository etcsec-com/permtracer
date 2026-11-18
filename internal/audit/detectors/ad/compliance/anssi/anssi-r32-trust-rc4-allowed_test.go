package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestR32TrustRC4Allowed_NoFabricatedANSSICitation verifies that Title and
// Description no longer cite "ANSSI R32": the real PA-099 R32 (p.49) is
// about passwords stored in GPP, unrelated to trust encryption, and
// mappings.go does not attach R32 to this detector either (it attaches the
// generic, unrelated R52). This test would have FAILED against the old
// title/description and passes now that the fabricated citation is gone.
func TestR32TrustRC4Allowed_NoFabricatedANSSICitation(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{
			{TargetDomain: "example.com", AESEnabled: false, RC4Enabled: true},
		},
	}
	findings := NewR32TrustRC4Detector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected a trust with RC4 enabled and AES disabled to be flagged, got %+v", findings)
	}
	title, desc := findings[0].Title, findings[0].Description
	if strings.Contains(title, "R32") || strings.Contains(desc, "R32") {
		t.Errorf("finding must not cite ANSSI R32 (the real R32 is about GPP passwords, unrelated), got title=%q desc=%q", title, desc)
	}
}
