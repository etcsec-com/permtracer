package status

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func TestInactive365Split_ActiveVsDisabledVsNeither(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	oldTimestamp := now.AddDate(-2, 0, 0)
	recentTimestamp := now.AddDate(0, 0, -5)

	cases := []struct {
		name           string
		user           types.User
		wantActive     int
		wantOnDisabled int
	}{
		{
			name:           "enabled account inactive 365+ days triggers only the active detector",
			user:           types.User{Disabled: false, LastLogonTimestamp: oldTimestamp},
			wantActive:     1,
			wantOnDisabled: 0,
		},
		{
			name:           "disabled account inactive 365+ days triggers only the twin",
			user:           types.User{Disabled: true, LastLogonTimestamp: oldTimestamp},
			wantActive:     0,
			wantOnDisabled: 1,
		},
		{
			name:           "never logged on (zero LastLogonTimestamp) triggers neither, enabled",
			user:           types.User{Disabled: false, LastLogonTimestamp: time.Time{}},
			wantActive:     0,
			wantOnDisabled: 0,
		},
		{
			name:           "never logged on (zero LastLogonTimestamp) triggers neither, disabled",
			user:           types.User{Disabled: true, LastLogonTimestamp: time.Time{}},
			wantActive:     0,
			wantOnDisabled: 0,
		},
		{
			name:           "recently active enabled account triggers neither",
			user:           types.User{Disabled: false, LastLogonTimestamp: recentTimestamp},
			wantActive:     0,
			wantOnDisabled: 0,
		},
		{
			name:           "recently active disabled account triggers neither",
			user:           types.User{Disabled: true, LastLogonTimestamp: recentTimestamp},
			wantActive:     0,
			wantOnDisabled: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{Now: now, Users: []types.User{tc.user}}

			activeFinding := NewInactive365Detector().Detect(context.Background(), data)[0]
			if activeFinding.Count != tc.wantActive {
				t.Errorf("Inactive365Detector: got Count=%d, want %d", activeFinding.Count, tc.wantActive)
			}

			onDisabledFinding := NewInactive365OnDisabledAccountDetector().Detect(context.Background(), data)[0]
			if onDisabledFinding.Count != tc.wantOnDisabled {
				t.Errorf("Inactive365OnDisabledAccountDetector: got Count=%d, want %d", onDisabledFinding.Count, tc.wantOnDisabled)
			}
		})
	}
}

func TestInactive365OnDisabledAccount_Severity(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	u := types.User{Disabled: true, LastLogonTimestamp: now.AddDate(-2, 0, 0)}
	data := &audit.DetectorData{Now: now, Users: []types.User{u}}

	f := NewInactive365OnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Severity != types.SeverityLow {
		t.Fatalf("expected Severity=Low, got %v", f.Severity)
	}
}

func TestInactive365OnDisabledAccount_ReplicationToleranceBoundary(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	oneYearAgo := now.AddDate(-1, 0, 0)

	cases := []struct {
		name      string
		timestamp time.Time
		wantCount int
	}{
		{"exactly at 365 days - within the 14-day replication tolerance, not flagged", oneYearAgo, 0},
		{"365 days + 13 days - still within tolerance, not flagged", oneYearAgo.AddDate(0, 0, -13), 0},
		{"365 days + 15 days - past tolerance, flagged", oneYearAgo.AddDate(0, 0, -15), 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := types.User{Disabled: true, LastLogonTimestamp: tc.timestamp}
			data := &audit.DetectorData{Now: now, Users: []types.User{u}}
			f := NewInactive365OnDisabledAccountDetector().Detect(context.Background(), data)[0]
			if f.Count != tc.wantCount {
				t.Fatalf("expected Count=%d, got %d", tc.wantCount, f.Count)
			}
		})
	}
}

func TestInactive365OnDisabledAccount_ActiveAccountPastTolerance_NotCounted(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	u := types.User{Disabled: false, LastLogonTimestamp: now.AddDate(-1, 0, -15)}
	data := &audit.DetectorData{Now: now, Users: []types.User{u}}

	f := NewInactive365OnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("enabled account past the threshold must not be counted by the disabled-account twin, got Count=%d", f.Count)
	}
}
