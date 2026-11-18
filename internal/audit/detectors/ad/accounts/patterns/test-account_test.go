package patterns

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestTestAccount_MatchesNamingPatterns is a coverage test, not a
// red/green regression test: this is a documented naming heuristic with
// no correctness defect (see the Detect doc comment). It pins the
// currently supported patterns.
func TestTestAccount_MatchesNamingPatterns(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"testuser", true},
		{"jdoe-test", true},
		{"demo-presenter", true},
		{"tempadmin", true},
		{"vuln-esc1-test", true}, // the lab's own plant/revert fixture naming
		{"jdupont", false},
	}

	for _, c := range cases {
		data := &audit.DetectorData{Users: []types.User{{SAMAccountName: c.name}}}
		findings := NewTestAccountDetector().Detect(context.Background(), data)
		got := findings[0].Count == 1
		if got != c.want {
			t.Errorf("%q: matched=%v, want %v", c.name, got, c.want)
		}
	}
}

// TestTestAccount_DisabledNotFlagged is the partition guard: a disabled
// account matching a test/demo/temp pattern must not be counted here - it
// belongs to TestAccountOnDisabledAccountDetector instead.
func TestTestAccount_DisabledNotFlagged(t *testing.T) {
	data := &audit.DetectorData{Users: []types.User{{SAMAccountName: "demo-presenter", Disabled: true}}}
	f := NewTestAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (disabled account must not be counted as an active test account)", f.Count)
	}
}

// TestTestAccount_UnderscoreTestPatternOnly targets the (?i)_test pattern
// exclusively: "svc_testrunner" neither starts nor ends with "test", has no
// dot, and has no demo/temp prefix, so only the _test pattern can match it.
func TestTestAccount_UnderscoreTestPatternOnly(t *testing.T) {
	data := &audit.DetectorData{Users: []types.User{{SAMAccountName: "svc_testrunner"}}}
	f := NewTestAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (svc_testrunner only matches the _test pattern)", f.Count)
	}
}

// TestTestAccount_DotTestPatternOnly targets the (?i)\.test pattern
// exclusively: "web.testbed" does not start or end with "test", has no
// underscore, and has no demo/temp prefix, so only the \.test pattern can
// match it.
func TestTestAccount_DotTestPatternOnly(t *testing.T) {
	data := &audit.DetectorData{Users: []types.User{{SAMAccountName: "web.testbed"}}}
	f := NewTestAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (web.testbed only matches the \\.test pattern)", f.Count)
	}
}

// TestTestAccount_DoubleMatchCountedOnce proves the pattern loop stops
// after its first match: "dev.test" satisfies both \.test and test$, and
// must still be counted exactly once. A non-matching account sits alongside
// it so the total stays verifiable (1, not 2 and not 0).
func TestTestAccount_DoubleMatchCountedOnce(t *testing.T) {
	data := &audit.DetectorData{Users: []types.User{
		{SAMAccountName: "dev.test"},
		{SAMAccountName: "jdupont"},
	}}
	f := NewTestAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (dev.test matches two patterns but must be counted once; jdupont must not be counted)", f.Count)
	}
}
