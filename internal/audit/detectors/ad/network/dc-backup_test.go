package network

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func detectDcBackup(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewDcBackupDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

// TestDcBackup_DescriptionDoesNotClaimARealBackupDate is RED on the pre-fix
// detector: its description ("Active Directory should be backed up
// regularly. Tombstone lifetime is 180 days.") and its Details key
// ("lastBackup") both presented an NTDS-metadata whenChanged heuristic as if
// it were an actual backup timestamp - the code comment in the LDAP
// collector already admits it's a heuristic, but the detector's output
// never said so.
func TestDcBackup_DescriptionDoesNotClaimARealBackupDate(t *testing.T) {
	now := time.Now()
	old := now.AddDate(0, 0, -90)
	f := detectDcBackup(t, &audit.DetectorData{
		Now: now,
		DomainInfo: &types.DomainInfo{
			LastADBackupDate: &old,
		},
	})

	lower := strings.ToLower(f.Description)
	if !strings.Contains(lower, "indirect") && !strings.Contains(lower, "heuristic") {
		t.Errorf("description must disclose this is an indirect/heuristic indicator, got %q", f.Description)
	}
	if _, ok := f.Details["lastBackup"]; ok {
		t.Error("Details must not use the misleading key \"lastBackup\" for a non-backup timestamp")
	}
	if _, ok := f.Details["lastNtdsMetadataChange"]; !ok {
		t.Error("Details must expose the metadata timestamp under an honestly named key")
	}
}

func TestDcBackup_RecentActivityDoesNotFire(t *testing.T) {
	now := time.Now()
	recent := now.AddDate(0, 0, -10)
	f := detectDcBackup(t, &audit.DetectorData{
		Now: now,
		DomainInfo: &types.DomainInfo{
			LastADBackupDate: &recent,
		},
	})
	if f.Count != 0 {
		t.Fatalf("recent NTDS metadata activity must not fire, count=%d", f.Count)
	}
}

func TestDcBackup_NoDataFires(t *testing.T) {
	f := detectDcBackup(t, &audit.DetectorData{DomainInfo: nil})
	if f.Count != 1 {
		t.Fatalf("missing data must fire so operators verify backups directly, count=%d", f.Count)
	}
}

// TestDcBackup_DomainInfoPresentButDateNilDoesNotPanic guards against
// narrowing the nil guard to `data.DomainInfo == nil` alone, which would
// dereference a nil *LastADBackupDate when DomainInfo is non-nil but the
// date itself is nil (e.g. unreadable nTDSDSA whenChanged).
func TestDcBackup_DomainInfoPresentButDateNilDoesNotPanic(t *testing.T) {
	f := detectDcBackup(t, &audit.DetectorData{
		Now:        time.Now(),
		DomainInfo: &types.DomainInfo{LastADBackupDate: nil},
	})
	if f.Count != 1 {
		t.Fatalf("DomainInfo set but LastADBackupDate nil must still fire as unknown, count=%d", f.Count)
	}
}

// TestDcBackup_ExactlySixtyDaysDoesNotFire kills mutation #7 (seuil 60→59)
// and mutation #9 (`>` → `>=`): at exactly 60 days the original does not fire.
func TestDcBackup_ExactlySixtyDaysDoesNotFire(t *testing.T) {
	now := time.Now()
	wc := now.AddDate(0, 0, -60)
	f := detectDcBackup(t, &audit.DetectorData{
		Now:        now,
		DomainInfo: &types.DomainInfo{LastADBackupDate: &wc},
	})
	if f.Count != 0 {
		t.Fatalf("exactly 60 days must not fire, count=%d", f.Count)
	}
}

// TestDcBackup_SixtyOneDaysFires kills mutation #8 (seuil 60→61): at 61 days
// the original fires (Count 1) but a threshold raised to 61 would not.
func TestDcBackup_SixtyOneDaysFires(t *testing.T) {
	now := time.Now()
	wc := now.AddDate(0, 0, -61)
	f := detectDcBackup(t, &audit.DetectorData{
		Now:        now,
		DomainInfo: &types.DomainInfo{LastADBackupDate: &wc},
	})
	if f.Count != 1 {
		t.Fatalf("61 days must fire, count=%d", f.Count)
	}
}

// TestDcBackup_DaysSinceChangeAndCountAndSeverityOnOldBranch pins the exact
// arithmetic and output of the >60 branch. It kills mutation #11
// (days computed via /25 instead of /24: 311 would become 298), mutation #12
// (Count 1→2 on this branch), and mutation #14 (Severity Info→High).
func TestDcBackup_DaysSinceChangeAndCountAndSeverityOnOldBranch(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	wc := time.Date(2025, 11, 17, 13, 9, 8, 0, time.UTC)
	f := detectDcBackup(t, &audit.DetectorData{
		Now:        now,
		DomainInfo: &types.DomainInfo{LastADBackupDate: &wc},
	})
	if f.Count != 1 {
		t.Fatalf("expected Count 1 on the >60 days branch, got %d", f.Count)
	}
	if f.Severity != types.SeverityInfo {
		t.Fatalf("expected Severity info, got %q", f.Severity)
	}
	days, ok := f.Details["daysSinceChange"]
	if !ok {
		t.Fatal("Details must expose daysSinceChange")
	}
	if days != 311 {
		t.Fatalf("expected daysSinceChange=311 (whenChanged 2025-11-17, now 2026-09-25), got %v", days)
	}
	lastChange, ok := f.Details["lastNtdsMetadataChange"]
	if !ok {
		t.Fatal("Details must expose lastNtdsMetadataChange")
	}
	if lastChange != "2025-11-17" {
		t.Fatalf("expected lastNtdsMetadataChange=2025-11-17, got %v", lastChange)
	}
}

// TestDcBackup_RecentActivitySeverityIsInfo kills the <=60 branch half of
// mutation #14 (Severity Info→High) - the old-branch test above already
// covers the >60 branch half.
func TestDcBackup_RecentActivitySeverityIsInfo(t *testing.T) {
	now := time.Now()
	recent := now.AddDate(0, 0, -10)
	f := detectDcBackup(t, &audit.DetectorData{
		Now:        now,
		DomainInfo: &types.DomainInfo{LastADBackupDate: &recent},
	})
	if f.Severity != types.SeverityInfo {
		t.Fatalf("expected Severity info, got %q", f.Severity)
	}
}

// TestDcBackup_DaysSinceChangeKeyIsNamedDaysSinceChange kills mutation #16
// (Details key "daysSinceChange" renamed).
func TestDcBackup_DaysSinceChangeKeyIsNamedDaysSinceChange(t *testing.T) {
	now := time.Now()
	old := now.AddDate(0, 0, -90)
	f := detectDcBackup(t, &audit.DetectorData{
		Now:        now,
		DomainInfo: &types.DomainInfo{LastADBackupDate: &old},
	})
	if _, ok := f.Details["daysSinceChange"]; !ok {
		t.Fatalf("Details must contain the key \"daysSinceChange\", got keys %v", f.Details)
	}
}
