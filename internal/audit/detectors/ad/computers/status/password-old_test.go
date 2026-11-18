package status

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

var passwordOldTestNow = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

func TestPasswordOld_Enabled90DaysAndOneMinute_Counted(t *testing.T) {
	data := &audit.DetectorData{
		Now: passwordOldTestNow,
		Computers: []types.Computer{
			{
				DN:              "CN=WS-20,OU=Workstations,DC=contoso,DC=com",
				Disabled:        false,
				PasswordLastSet: passwordOldTestNow.AddDate(0, 0, -90).Add(-1 * time.Minute),
			},
		},
	}
	f := NewPasswordOldDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("enabled computer whose password is 90 days + 1 minute old must be flagged, got Count=%d", f.Count)
	}
}

func TestPasswordOld_EnabledExactly90Days_NotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Now: passwordOldTestNow,
		Computers: []types.Computer{
			{
				DN:              "CN=WS-21,OU=Workstations,DC=contoso,DC=com",
				Disabled:        false,
				PasswordLastSet: passwordOldTestNow.AddDate(0, 0, -90),
			},
		},
	}
	f := NewPasswordOldDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("enabled computer whose password is exactly 90 days old must NOT be flagged (Before is strict), got Count=%d", f.Count)
	}
}

func TestPasswordOld_Enabled89Days_NotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Now: passwordOldTestNow,
		Computers: []types.Computer{
			{
				DN:              "CN=WS-22,OU=Workstations,DC=contoso,DC=com",
				Disabled:        false,
				PasswordLastSet: passwordOldTestNow.AddDate(0, 0, -89),
			},
		},
	}
	f := NewPasswordOldDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("enabled computer whose password is only 89 days old must NOT be flagged, got Count=%d", f.Count)
	}
}

func TestPasswordOld_DisabledOld_NotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Now: passwordOldTestNow,
		Computers: []types.Computer{
			{
				DN:              "CN=WS-23,OU=Workstations,DC=contoso,DC=com",
				Disabled:        true,
				PasswordLastSet: passwordOldTestNow.AddDate(0, 0, -400),
			},
		},
	}
	f := NewPasswordOldDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("disabled computer must NOT be flagged regardless of password age, got Count=%d", f.Count)
	}
}

func TestPasswordOld_EnabledZeroPasswordLastSet_NotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Now: passwordOldTestNow,
		Computers: []types.Computer{
			{
				DN:       "CN=WS-24,OU=Workstations,DC=contoso,DC=com",
				Disabled: false,
			},
		},
	}
	f := NewPasswordOldDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("enabled computer with a zero PasswordLastSet must NOT be flagged, got Count=%d", f.Count)
	}
}

func TestPasswordOld_TwoOldEnabledComputers_Count2(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Now:            passwordOldTestNow,
		Computers: []types.Computer{
			{
				DN:              "CN=WS-25,OU=Workstations,DC=contoso,DC=com",
				Disabled:        false,
				PasswordLastSet: passwordOldTestNow.AddDate(0, 0, -100),
			},
			{
				DN:              "CN=WS-26,OU=Workstations,DC=contoso,DC=com",
				Disabled:        false,
				PasswordLastSet: passwordOldTestNow.AddDate(0, 0, -200),
			},
		},
	}
	f := NewPasswordOldDetector().Detect(context.Background(), data)[0]
	if f.Count != 2 {
		t.Fatalf("expected exactly 2 enabled computers with old passwords, got Count=%d", f.Count)
	}
	if len(f.AffectedEntities) != f.Count {
		t.Fatalf("AffectedEntities length %d must match Count %d", len(f.AffectedEntities), f.Count)
	}
}
