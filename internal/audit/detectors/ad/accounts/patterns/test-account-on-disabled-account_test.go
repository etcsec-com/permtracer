package patterns

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestTestAccountOnDisabledAccount_DisabledMatchFlagged is the baseline
// positive: a disabled account matching a test/demo/temp naming pattern
// must be counted here.
func TestTestAccountOnDisabledAccount_DisabledMatchFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users:          []types.User{{SAMAccountName: "demo-presenter", Disabled: true}},
		IncludeDetails: true,
	}
	f := NewTestAccountOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled test-named account)", f.Count)
	}
	if f.Type != "TEST_ACCOUNT_ON_DISABLED_ACCOUNT" {
		t.Fatalf("Type = %q, want TEST_ACCOUNT_ON_DISABLED_ACCOUNT", f.Type)
	}
}

// TestTestAccountOnDisabledAccount_ActiveMatchNotFlagged is the partition
// guard from this detector's side: an enabled account matching the same
// pattern must not be counted here - it belongs to TestAccountDetector
// instead.
func TestTestAccountOnDisabledAccount_ActiveMatchNotFlagged(t *testing.T) {
	data := &audit.DetectorData{Users: []types.User{{SAMAccountName: "demo-presenter", Disabled: false}}}
	f := NewTestAccountOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (active account must not be counted as a disabled test account)", f.Count)
	}
}

// TestTestAccountOnDisabledAccount_NonMatchNotFlagged: a disabled account
// whose name matches none of the patterns must not be counted.
func TestTestAccountOnDisabledAccount_NonMatchNotFlagged(t *testing.T) {
	data := &audit.DetectorData{Users: []types.User{{SAMAccountName: "jdupont", Disabled: true}}}
	f := NewTestAccountOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (non-matching name must not be flagged)", f.Count)
	}
}

// TestTestAccountOnDisabledAccount_SeverityIsLow locks this detector's
// severity at Low, distinct from the Medium of the active-account
// detector.
func TestTestAccountOnDisabledAccount_SeverityIsLow(t *testing.T) {
	data := &audit.DetectorData{Users: []types.User{{SAMAccountName: "demo-presenter", Disabled: true}}}
	f := NewTestAccountOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Severity != types.SeverityLow {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityLow)
	}
}

// TestTestAccountOnDisabledAccount_UnderscoreTestPatternOnly targets the
// (?i)_test pattern exclusively: "svc_testrunner" neither starts nor ends
// with "test", has no dot, and has no demo/temp prefix, so only the _test
// pattern can match it.
func TestTestAccountOnDisabledAccount_UnderscoreTestPatternOnly(t *testing.T) {
	data := &audit.DetectorData{Users: []types.User{{SAMAccountName: "svc_testrunner", Disabled: true}}}
	f := NewTestAccountOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (svc_testrunner only matches the _test pattern)", f.Count)
	}
}

// TestTestAccountOnDisabledAccount_DotTestPatternOnly targets the
// (?i)\.test pattern exclusively: "web.testbed" does not start or end with
// "test", has no underscore, and has no demo/temp prefix, so only the
// \.test pattern can match it.
func TestTestAccountOnDisabledAccount_DotTestPatternOnly(t *testing.T) {
	data := &audit.DetectorData{Users: []types.User{{SAMAccountName: "web.testbed", Disabled: true}}}
	f := NewTestAccountOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (web.testbed only matches the \\.test pattern)", f.Count)
	}
}

// TestTestAccountOnDisabledAccount_DoubleMatchCountedOnce proves the
// pattern loop stops after its first match: "dev.test" satisfies both
// \.test and test$, and must still be counted exactly once. A non-matching
// account sits alongside it so the total stays verifiable (1, not 2 and
// not 0).
func TestTestAccountOnDisabledAccount_DoubleMatchCountedOnce(t *testing.T) {
	data := &audit.DetectorData{Users: []types.User{
		{SAMAccountName: "dev.test", Disabled: true},
		{SAMAccountName: "jdupont", Disabled: true},
	}}
	f := NewTestAccountOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (dev.test matches two patterns but must be counted once; jdupont must not be counted)", f.Count)
	}
}
