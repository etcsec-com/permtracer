package patterns

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestSharedAccountOnDisabledAccount_DisabledMatchFlagged is the baseline
// positive: a disabled account matching a shared/generic naming pattern
// must be counted here.
func TestSharedAccountOnDisabledAccount_DisabledMatchFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users:          []types.User{{SAMAccountName: "shared-printer", Disabled: true}},
		IncludeDetails: true,
	}
	f := NewSharedAccountOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled shared-named account)", f.Count)
	}
	if f.Type != "SHARED_ACCOUNT_ON_DISABLED_ACCOUNT" {
		t.Fatalf("Type = %q, want SHARED_ACCOUNT_ON_DISABLED_ACCOUNT", f.Type)
	}
}

// TestSharedAccountOnDisabledAccount_ActiveMatchNotFlagged is the
// partition guard from this detector's side: an enabled account matching
// the same pattern must not be counted here - it belongs to
// SharedAccountDetector instead.
func TestSharedAccountOnDisabledAccount_ActiveMatchNotFlagged(t *testing.T) {
	data := &audit.DetectorData{Users: []types.User{{SAMAccountName: "shared-printer", Disabled: false}}}
	f := NewSharedAccountOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (active account must not be counted as a disabled shared account)", f.Count)
	}
}

// TestSharedAccountOnDisabledAccount_NonMatchNotFlagged: a disabled account
// whose name matches none of the patterns must not be counted.
func TestSharedAccountOnDisabledAccount_NonMatchNotFlagged(t *testing.T) {
	data := &audit.DetectorData{Users: []types.User{{SAMAccountName: "jdupont", Disabled: true}}}
	f := NewSharedAccountOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (non-matching name must not be flagged)", f.Count)
	}
}

// TestSharedAccountOnDisabledAccount_PrefixMustBeAnchored proves the ^
// anchor on each pattern, on the disabled-account side: a prefix appearing
// after the start of the name must not match.
func TestSharedAccountOnDisabledAccount_PrefixMustBeAnchored(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"xshared01", false},
		{"my-common", false},
		{"nongeneric", false},
		{"xguest-01", false},
	}

	for _, c := range cases {
		data := &audit.DetectorData{Users: []types.User{{SAMAccountName: c.name, Disabled: true}}}
		f := NewSharedAccountOnDisabledAccountDetector().Detect(context.Background(), data)[0]
		got := f.Count == 1
		if got != c.want {
			t.Errorf("%q: matched=%v, want %v", c.name, got, c.want)
		}
	}
}

// TestSharedAccountOnDisabledAccount_CaseInsensitive proves the (?i) flag
// on each pattern, on the disabled-account side: a name matching in a
// different case must still be counted.
func TestSharedAccountOnDisabledAccount_CaseInsensitive(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"SHARED-ops", true},
		{"Common_svc", true},
		{"GENERIC01", true},
		{"Guest-Lab", true},
	}

	for _, c := range cases {
		data := &audit.DetectorData{Users: []types.User{{SAMAccountName: c.name, Disabled: true}}}
		f := NewSharedAccountOnDisabledAccountDetector().Detect(context.Background(), data)[0]
		got := f.Count == 1
		if got != c.want {
			t.Errorf("%q: matched=%v, want %v", c.name, got, c.want)
		}
	}
}

// TestSharedAccountOnDisabledAccount_SeverityIsLow locks this detector's
// severity at Low, distinct from the Medium of the active-account
// detector.
func TestSharedAccountOnDisabledAccount_SeverityIsLow(t *testing.T) {
	data := &audit.DetectorData{Users: []types.User{{SAMAccountName: "shared-printer", Disabled: true}}}
	f := NewSharedAccountOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Severity != types.SeverityLow {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityLow)
	}
}
