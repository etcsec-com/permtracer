package serviceaccounts

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestWithSpnOnDisabledAccount_DisabledSpnFlagged is the baseline positive:
// a disabled account carrying an SPN must be counted here.
func TestWithSpnOnDisabledAccount_DisabledSpnFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users:          []types.User{{SAMAccountName: "svc-app", Disabled: true, ServicePrincipalNames: []string{"HTTP/svc-app.example.com"}}},
		IncludeDetails: true,
	}
	f := NewWithSpnOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled account with SPN)", f.Count)
	}
	if f.Type != "SERVICE_ACCOUNT_WITH_SPN_ON_DISABLED_ACCOUNT" {
		t.Fatalf("Type = %q, want SERVICE_ACCOUNT_WITH_SPN_ON_DISABLED_ACCOUNT", f.Type)
	}
}

// TestWithSpnOnDisabledAccount_ActiveSpnNotFlagged is the partition guard
// from this detector's side: an enabled account with an SPN must not be
// counted here - it belongs to WithSpnDetector instead.
func TestWithSpnOnDisabledAccount_ActiveSpnNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "svc-app", Disabled: false, ServicePrincipalNames: []string{"HTTP/svc-app.example.com"}}},
	}
	f := NewWithSpnOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (active account must not be counted as a disabled SPN holder)", f.Count)
	}
}

// TestWithSpnOnDisabledAccount_DisabledWithoutSpnNotFlagged: a disabled
// account with no SPN at all must not be counted.
func TestWithSpnOnDisabledAccount_DisabledWithoutSpnNotFlagged(t *testing.T) {
	data := &audit.DetectorData{Users: []types.User{{SAMAccountName: "jdupont", Disabled: true}}}
	f := NewWithSpnOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (no SPN must not be flagged)", f.Count)
	}
}

// TestWithSpnOnDisabledAccount_SeverityIsLow locks this detector's
// severity at Low, distinct from the Medium of the active-account
// detector.
func TestWithSpnOnDisabledAccount_SeverityIsLow(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "svc-app", Disabled: true, ServicePrincipalNames: []string{"HTTP/svc-app.example.com"}}},
	}
	f := NewWithSpnOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Severity != types.SeverityLow {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityLow)
	}
}

// TestWithSpnOnDisabledAccount_DisabledMultiSpnCountedOnce: a disabled
// account with three SPNs is a single account and must be counted once.
// Count must track the number of accounts, not the number of SPN values -
// a fixture with more than one SPN on one account is required to catch a
// regression where Count is swapped for the SPN tally.
func TestWithSpnOnDisabledAccount_DisabledMultiSpnCountedOnce(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{
			SAMAccountName: "svc-multi",
			Disabled:       true,
			ServicePrincipalNames: []string{
				"HTTP/svc-multi.example.com",
				"MSSQLSvc/svc-multi.example.com:1433",
				"FTP/svc-multi.example.com",
			},
		}},
	}
	f := NewWithSpnOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (one disabled account with three SPNs counted once)", f.Count)
	}
}
