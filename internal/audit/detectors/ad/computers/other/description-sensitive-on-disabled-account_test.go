package other

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestDescriptionSensitivePair_ActiveDisabledNeutral is the partition guard
// for this pair: an active computer with a sensitive description fires only
// the active detector, a disabled computer with the same kind of
// description fires only its twin, and a neutral description fires neither
// - active or disabled.
func TestDescriptionSensitivePair_ActiveDisabledNeutral(t *testing.T) {
	cases := []struct {
		name           string
		description    string
		disabled       bool
		wantActive     bool
		wantOnDisabled bool
	}{
		{"active computer with sensitive description fires only the active detector", "password=hunter2", false, true, false},
		{"disabled computer with sensitive description fires only the twin", "password=hunter2", true, false, true},
		{"neutral description on an active computer fires neither", "clean deployment note", false, false, false},
		{"neutral description on a disabled computer fires neither", "clean deployment note", true, false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := types.Computer{DN: "CN=WKS,DC=example,DC=com", Description: tc.description, Disabled: tc.disabled}
			data := &audit.DetectorData{Computers: []types.Computer{c}}

			activeFindings := NewDescriptionSensitiveDetector().Detect(context.Background(), data)
			onDisabledFindings := NewDescriptionSensitiveOnDisabledAccountDetector().Detect(context.Background(), data)

			gotActive := activeFindings[0].Count > 0
			gotOnDisabled := onDisabledFindings[0].Count > 0

			if gotActive != tc.wantActive {
				t.Errorf("active detector: flagged=%v, want %v", gotActive, tc.wantActive)
			}
			if gotOnDisabled != tc.wantOnDisabled {
				t.Errorf("on-disabled-account detector: flagged=%v, want %v", gotOnDisabled, tc.wantOnDisabled)
			}
		})
	}
}

// TestDescriptionSensitiveOnDisabledAccount_Severity pins the twin's
// severity at Medium: the description stays readable regardless of the
// disabled state, so this twin is not downgraded relative to the active
// detector.
func TestDescriptionSensitiveOnDisabledAccount_Severity(t *testing.T) {
	c := types.Computer{DN: "CN=WKS,DC=example,DC=com", Description: "admin workstation", Disabled: true}
	data := &audit.DetectorData{Computers: []types.Computer{c}}
	findings := NewDescriptionSensitiveOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Severity != types.SeverityMedium {
		t.Fatalf("severity = %q, want medium", findings[0].Severity)
	}
}

// TestDescriptionSensitiveOnDisabledAccount_IPv4PatternOnly mirrors the
// active detector's IPv4-only gap: no case in this file had a description
// containing only an IPv4 address and no other sensitive keyword, so
// neutralizing the IPv4 pattern in sensitivePatterns left every test here
// green.
func TestDescriptionSensitiveOnDisabledAccount_IPv4PatternOnly(t *testing.T) {
	cases := []struct {
		name        string
		description string
		wantFlagged bool
	}{
		{"description containing only an IPv4 address fires", "rack 3 mgmt 192.0.2.40", true},
		{"description with an incomplete IPv4-like address does not fire", "rack 3 mgmt 192.0.2", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := types.Computer{DN: "CN=WKS,DC=example,DC=com", Description: tc.description, Disabled: true}
			data := &audit.DetectorData{Computers: []types.Computer{c}}
			findings := NewDescriptionSensitiveOnDisabledAccountDetector().Detect(context.Background(), data)
			gotFlagged := findings[0].Count > 0
			if gotFlagged != tc.wantFlagged {
				t.Fatalf("description %q: flagged=%v, want %v", tc.description, gotFlagged, tc.wantFlagged)
			}
		})
	}
}

// TestDescriptionSensitiveOnDisabledAccount_BreakPreventsDoubleCounting
// mirrors the active detector's guard: a description matching two of the
// three patterns still counts its computer once.
func TestDescriptionSensitiveOnDisabledAccount_BreakPreventsDoubleCounting(t *testing.T) {
	c := types.Computer{DN: "CN=WKS,DC=example,DC=com", Description: "admin password reset pending", Disabled: true}
	data := &audit.DetectorData{Computers: []types.Computer{c}}
	findings := NewDescriptionSensitiveOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("single computer matching two patterns: Count=%d, want 1", findings[0].Count)
	}
}
