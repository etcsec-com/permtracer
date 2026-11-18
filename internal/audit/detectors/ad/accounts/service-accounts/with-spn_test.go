package serviceaccounts

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestWithSpn_ActiveSpnFlagged is the baseline positive: an active
// (non-disabled) account carrying an SPN must be counted here.
func TestWithSpn_ActiveSpnFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users:          []types.User{{SAMAccountName: "svc-app", Disabled: false, ServicePrincipalNames: []string{"HTTP/svc-app.example.com"}}},
		IncludeDetails: true,
	}
	f := NewWithSpnDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (active account with SPN)", f.Count)
	}
	if f.Type != "SERVICE_ACCOUNT_WITH_SPN" {
		t.Fatalf("Type = %q, want SERVICE_ACCOUNT_WITH_SPN", f.Type)
	}
}

// TestWithSpn_ActiveWithoutSpnNotFlagged: an active account with no SPN at
// all must not be counted.
func TestWithSpn_ActiveWithoutSpnNotFlagged(t *testing.T) {
	data := &audit.DetectorData{Users: []types.User{{SAMAccountName: "jdupont", Disabled: false}}}
	f := NewWithSpnDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (no SPN must not be flagged)", f.Count)
	}
}

// TestWithSpn_DisabledSpnNotFlagged is the partition guard from this
// detector's side: a disabled account with an SPN must not be counted here
// - it belongs to WithSpnOnDisabledAccountDetector instead.
func TestWithSpn_DisabledSpnNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "svc-app", Disabled: true, ServicePrincipalNames: []string{"HTTP/svc-app.example.com"}}},
	}
	f := NewWithSpnDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (disabled account must not be counted here)", f.Count)
	}
}

// TestWithSpn_ActiveMultiSpnCountedOnce: an active account with two SPNs
// is a single account and must be counted once. Count must track the
// number of accounts, not the number of SPN values - a fixture with more
// than one SPN on one account is required to catch a regression where
// Count is swapped for the SPN tally.
func TestWithSpn_ActiveMultiSpnCountedOnce(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{
			SAMAccountName:        "svc-multi",
			Disabled:              false,
			ServicePrincipalNames: []string{"HTTP/svc-multi.example.com", "MSSQLSvc/svc-multi.example.com:1433"},
		}},
	}
	f := NewWithSpnDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (one account with two SPNs counted once)", f.Count)
	}
}
