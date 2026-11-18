package privileged

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestSidHistoryOnDisabledAccount_DisabledPresentFlagged is the baseline
// positive: a disabled account with a non-empty sIDHistory must be counted
// here.
func TestSidHistoryOnDisabledAccount_DisabledPresentFlagged(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "migrated-user", Disabled: true, SIDHistory: []string{"S-1-5-21-9-9-9-512"}},
		},
	}

	findings := NewSidHistoryOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
	if findings[0].Type != "SID_HISTORY_ON_DISABLED_ACCOUNT" {
		t.Fatalf("Type = %q, want SID_HISTORY_ON_DISABLED_ACCOUNT", findings[0].Type)
	}
	if findings[0].Severity != types.SeverityLow {
		t.Fatalf("Severity = %q, want Low", findings[0].Severity)
	}
}

// TestSidHistoryOnDisabledAccount_ActivePresentNotFlagged is the partition
// guard: the same sIDHistory presence must be split strictly between the
// two detectors by account state - an active account belongs to
// SidHistoryDetector only, never to this twin.
func TestSidHistoryOnDisabledAccount_ActivePresentNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "migrated-user", Disabled: false, SIDHistory: []string{"S-1-5-21-9-9-9-512"}},
		},
	}

	twin := NewSidHistoryOnDisabledAccountDetector().Detect(context.Background(), data)
	if twin[0].Count != 0 {
		t.Fatalf("twin Count = %d, want 0 (active account must not be counted by the disabled-account twin)", twin[0].Count)
	}

	active := NewSidHistoryDetector().Detect(context.Background(), data)
	if active[0].Count != 1 {
		t.Fatalf("active Count = %d, want 1 (active account belongs to SidHistoryDetector)", active[0].Count)
	}
}

// TestSidHistoryOnDisabledAccount_EmptyNotFlagged guards the negative case.
func TestSidHistoryOnDisabledAccount_EmptyNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "ordinary", Disabled: true}},
	}

	findings := NewSidHistoryOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}
