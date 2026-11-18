package patterns

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestSharedAccount_MatchesNamingPatterns pins the currently supported
// shared/generic naming patterns.
func TestSharedAccount_MatchesNamingPatterns(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"shared-printer", true},
		{"common-mailbox", true},
		{"generic-admin", true},
		{"guest-wifi", true},
		{"jdoe", false},
	}

	for _, c := range cases {
		data := &audit.DetectorData{Users: []types.User{{SAMAccountName: c.name}}}
		findings := NewSharedAccountDetector().Detect(context.Background(), data)
		got := findings[0].Count == 1
		if got != c.want {
			t.Errorf("%q: matched=%v, want %v", c.name, got, c.want)
		}
	}
}

// TestSharedAccount_PrefixMustBeAnchored proves the ^ anchor on each
// pattern: a prefix appearing after the start of the name must not match.
func TestSharedAccount_PrefixMustBeAnchored(t *testing.T) {
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
		data := &audit.DetectorData{Users: []types.User{{SAMAccountName: c.name}}}
		findings := NewSharedAccountDetector().Detect(context.Background(), data)
		got := findings[0].Count == 1
		if got != c.want {
			t.Errorf("%q: matched=%v, want %v", c.name, got, c.want)
		}
	}
}

// TestSharedAccount_CaseInsensitive proves the (?i) flag on each pattern: a
// name matching in a different case must still be counted.
func TestSharedAccount_CaseInsensitive(t *testing.T) {
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
		data := &audit.DetectorData{Users: []types.User{{SAMAccountName: c.name}}}
		findings := NewSharedAccountDetector().Detect(context.Background(), data)
		got := findings[0].Count == 1
		if got != c.want {
			t.Errorf("%q: matched=%v, want %v", c.name, got, c.want)
		}
	}
}

// TestSharedAccount_DisabledNotFlagged is the partition guard: a disabled
// account matching a shared/generic pattern must not be counted here - it
// belongs to SharedAccountOnDisabledAccountDetector instead.
func TestSharedAccount_DisabledNotFlagged(t *testing.T) {
	data := &audit.DetectorData{Users: []types.User{{SAMAccountName: "shared-printer", Disabled: true}}}
	f := NewSharedAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (disabled account must not be counted as an active shared account)", f.Count)
	}
}
