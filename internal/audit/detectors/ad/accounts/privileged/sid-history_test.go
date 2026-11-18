package privileged

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestSidHistory_PresentAttributeFlagged is a coverage test, not a
// red/green regression test: no code defect was found in this detector
// (see the Detect doc comment) - the open item was empirical confirmation,
// not correctness. This pins that a non-empty sIDHistory is read and
// surfaced correctly.
func TestSidHistory_PresentAttributeFlagged(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "migrated-user", SIDHistory: []string{"S-1-5-21-9-9-9-512"}},
		},
	}

	findings := NewSidHistoryDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
}

// TestSidHistory_EmptyNotFlagged guards the negative case.
func TestSidHistory_EmptyNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "ordinary"}},
	}

	findings := NewSidHistoryDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestSidHistory_DisabledNotFlagged is the partition guard: a disabled
// account carrying sIDHistory must not be counted here - it belongs to
// SidHistoryOnDisabledAccountDetector instead.
func TestSidHistory_DisabledNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "migrated-user", Disabled: true, SIDHistory: []string{"S-1-5-21-9-9-9-512"}}},
	}

	findings := NewSidHistoryDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (disabled account must not be counted as an active SID history risk)", findings[0].Count)
	}
}
