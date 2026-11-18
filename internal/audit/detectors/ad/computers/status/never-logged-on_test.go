package status

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func TestNeverLoggedOn_EnabledNoLogonDates_Counted(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WS-01,OU=Workstations,DC=contoso,DC=com", Disabled: false},
		},
	}
	f := NewNeverLoggedOnDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("enabled computer with no logon date of any kind must be flagged, got Count=%d", f.Count)
	}
}

func TestNeverLoggedOn_DisabledNoLogonDates_NotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WS-02,OU=Workstations,DC=contoso,DC=com", Disabled: true},
		},
	}
	f := NewNeverLoggedOnDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("disabled computer must NOT be flagged regardless of logon dates, got Count=%d", f.Count)
	}
}

func TestNeverLoggedOn_EnabledWithLastLogonOnly_NotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:        "CN=WS-03,OU=Workstations,DC=contoso,DC=com",
				Disabled:  false,
				LastLogon: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
	}
	f := NewNeverLoggedOnDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("a non-zero LastLogon alone must count as a logon and NOT be flagged, got Count=%d", f.Count)
	}
}

func TestNeverLoggedOn_EnabledWithLastLogonTimestampOnly_NotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:                 "CN=WS-04,OU=Workstations,DC=contoso,DC=com",
				Disabled:           false,
				LastLogonTimestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
	}
	f := NewNeverLoggedOnDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("a non-zero LastLogonTimestamp alone must count as a logon (fallback) and NOT be flagged, got Count=%d", f.Count)
	}
}

func TestNeverLoggedOn_EnabledWithBothLogonDates_NotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:                 "CN=WS-05,OU=Workstations,DC=contoso,DC=com",
				Disabled:           false,
				LastLogon:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				LastLogonTimestamp: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
			},
		},
	}
	f := NewNeverLoggedOnDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("a computer with both logon dates set must NOT be flagged, got Count=%d", f.Count)
	}
}

// TestNeverLoggedOn_MixedComputers_ExactCount uses three never-logged-on
// enabled computers against one enabled computer with a logon date and one
// disabled computer with none, so an inverted final zero-check (which would
// flag the dated computer instead of the three undated ones) changes the
// total rather than coincidentally matching it.
func TestNeverLoggedOn_MixedComputers_ExactCount(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=WS-06,OU=Workstations,DC=contoso,DC=com", Disabled: false},
			{DN: "CN=WS-07,OU=Workstations,DC=contoso,DC=com", Disabled: false},
			{DN: "CN=WS-08,OU=Workstations,DC=contoso,DC=com", Disabled: false},
			{
				DN:        "CN=WS-09,OU=Workstations,DC=contoso,DC=com",
				Disabled:  false,
				LastLogon: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			{DN: "CN=WS-10,OU=Workstations,DC=contoso,DC=com", Disabled: true},
		},
	}
	f := NewNeverLoggedOnDetector().Detect(context.Background(), data)[0]
	if f.Count != 3 {
		t.Fatalf("expected exactly 3 never-logged-on enabled computers in the mix, got Count=%d", f.Count)
	}
	if len(f.AffectedEntities) != f.Count {
		t.Fatalf("AffectedEntities length %d must match Count %d", len(f.AffectedEntities), f.Count)
	}
}
