package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestR22GuestEnabled_NoFabricatedANSSICitation verifies that Title and
// Description no longer cite "ANSSI R2.2" or "PA-022": PA-099's full text
// contains no mention of the Guest account and no decimal
// sub-recommendation numbering, so no "R2.2" control exists in that
// catalogue, and PA-022 is the superseded guide name. This test would have
// FAILED against the old title/description and passes now that the
// fabricated citation is gone.
func TestR22GuestEnabled_NoFabricatedANSSICitation(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{ObjectSID: "S-1-5-21-1-2-3-501", Disabled: false},
		},
	}
	findings := NewR22GuestEnabledDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected an enabled Guest account (RID -501) to be flagged, got %+v", findings)
	}
	title, desc := findings[0].Title, findings[0].Description
	if strings.Contains(title, "R2.2") || strings.Contains(desc, "R2.2") {
		t.Errorf("finding must not cite ANSSI R2.2 (no such sub-recommendation exists in PA-099), got title=%q desc=%q", title, desc)
	}
	if strings.Contains(title, "PA-022") || strings.Contains(desc, "PA-022") {
		t.Errorf("finding must not cite PA-022 (superseded by PA-099), got title=%q desc=%q", title, desc)
	}
}
