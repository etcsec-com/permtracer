package status

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

var disabledNotDeletedTestNow = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

func TestDisabledNotDeleted_Disabled30DaysAndOneMinute_Counted(t *testing.T) {
	data := &audit.DetectorData{
		Now: disabledNotDeletedTestNow,
		Computers: []types.Computer{
			{
				DN:          "CN=WS-30,OU=Workstations,DC=contoso,DC=com",
				Disabled:    true,
				WhenChanged: disabledNotDeletedTestNow.AddDate(0, 0, -30).Add(-1 * time.Minute),
			},
		},
	}
	f := NewDisabledNotDeletedDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("disabled computer changed 30 days + 1 minute ago must be flagged, got Count=%d", f.Count)
	}
}

func TestDisabledNotDeleted_DisabledExactly30Days_NotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Now: disabledNotDeletedTestNow,
		Computers: []types.Computer{
			{
				DN:          "CN=WS-31,OU=Workstations,DC=contoso,DC=com",
				Disabled:    true,
				WhenChanged: disabledNotDeletedTestNow.AddDate(0, 0, -30),
			},
		},
	}
	f := NewDisabledNotDeletedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("disabled computer changed exactly 30 days ago must NOT be flagged (Before is strict), got Count=%d", f.Count)
	}
}

func TestDisabledNotDeleted_Disabled29Days_NotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Now: disabledNotDeletedTestNow,
		Computers: []types.Computer{
			{
				DN:          "CN=WS-32,OU=Workstations,DC=contoso,DC=com",
				Disabled:    true,
				WhenChanged: disabledNotDeletedTestNow.AddDate(0, 0, -29),
			},
		},
	}
	f := NewDisabledNotDeletedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("disabled computer changed only 29 days ago must NOT be flagged, got Count=%d", f.Count)
	}
}

func TestDisabledNotDeleted_EnabledOld_NotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Now: disabledNotDeletedTestNow,
		Computers: []types.Computer{
			{
				DN:          "CN=WS-33,OU=Workstations,DC=contoso,DC=com",
				Disabled:    false,
				WhenChanged: disabledNotDeletedTestNow.AddDate(0, 0, -400),
			},
		},
	}
	f := NewDisabledNotDeletedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("enabled computer must NOT be flagged regardless of WhenChanged age, got Count=%d", f.Count)
	}
}

func TestDisabledNotDeleted_DisabledZeroWhenChanged_NotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Now: disabledNotDeletedTestNow,
		Computers: []types.Computer{
			{
				DN:       "CN=WS-34,OU=Workstations,DC=contoso,DC=com",
				Disabled: true,
			},
		},
	}
	f := NewDisabledNotDeletedDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("disabled computer with a zero WhenChanged must NOT be flagged, got Count=%d", f.Count)
	}
}

func TestDisabledNotDeleted_TwoOldDisabledComputers_Count2(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Now:            disabledNotDeletedTestNow,
		Computers: []types.Computer{
			{
				DN:          "CN=WS-35,OU=Workstations,DC=contoso,DC=com",
				Disabled:    true,
				WhenChanged: disabledNotDeletedTestNow.AddDate(0, 0, -100),
			},
			{
				DN:          "CN=WS-36,OU=Workstations,DC=contoso,DC=com",
				Disabled:    true,
				WhenChanged: disabledNotDeletedTestNow.AddDate(0, 0, -200),
			},
		},
	}
	f := NewDisabledNotDeletedDetector().Detect(context.Background(), data)[0]
	if f.Count != 2 {
		t.Fatalf("expected exactly 2 disabled old computers, got Count=%d", f.Count)
	}
	if len(f.AffectedEntities) != f.Count {
		t.Fatalf("AffectedEntities length %d must match Count %d", len(f.AffectedEntities), f.Count)
	}
}
