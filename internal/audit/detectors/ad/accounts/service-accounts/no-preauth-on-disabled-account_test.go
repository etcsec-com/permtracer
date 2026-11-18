package serviceaccounts

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestNoPreauthOnDisabledAccount_DisabledServiceAccountFlagged is the
// baseline positive: a disabled service account (SPN-bearing) with
// DONT_REQ_PREAUTH set must be counted here.
func TestNoPreauthOnDisabledAccount_DisabledServiceAccountFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{
			SAMAccountName:        "svc-app",
			Disabled:              true,
			ServicePrincipalNames: []string{"HTTP/svc-app.example.com"},
			UserAccountControl:    0x400202,
		}},
		IncludeDetails: true,
	}
	f := NewNoPreauthOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled service account with DONT_REQ_PREAUTH)", f.Count)
	}
	if f.Type != "SERVICE_ACCOUNT_NO_PREAUTH_ON_DISABLED_ACCOUNT" {
		t.Fatalf("Type = %q, want SERVICE_ACCOUNT_NO_PREAUTH_ON_DISABLED_ACCOUNT", f.Type)
	}
}

// TestNoPreauthOnDisabledAccount_ActiveServiceAccountNotFlagged is the
// partition guard from this detector's side: an enabled service account
// with the same bit must not be counted here - it belongs to
// NoPreauthDetector instead.
func TestNoPreauthOnDisabledAccount_ActiveServiceAccountNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{
			SAMAccountName:        "svc-app",
			Disabled:              false,
			ServicePrincipalNames: []string{"HTTP/svc-app.example.com"},
			UserAccountControl:    0x400202,
		}},
	}
	f := NewNoPreauthOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (active account must not be counted here)", f.Count)
	}
}

// TestNoPreauthOnDisabledAccount_DisabledNonServiceAccountNotFlagged: a
// disabled ordinary user (no SPN, no service naming pattern) with the bit
// set must not be counted - isServiceAccount excludes it, same as the
// active detector.
func TestNoPreauthOnDisabledAccount_DisabledNonServiceAccountNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "jdupont", Disabled: true, UserAccountControl: 0x400202}},
	}
	f := NewNoPreauthOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (non-service-account must not be flagged)", f.Count)
	}
}

// TestNoPreauthOnDisabledAccount_DisabledServiceAccountWithoutBitNotFlagged:
// a disabled service account without DONT_REQ_PREAUTH must not be
// counted.
func TestNoPreauthOnDisabledAccount_DisabledServiceAccountWithoutBitNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "svc-app", Disabled: true, ServicePrincipalNames: []string{"HTTP/svc-app.example.com"}, UserAccountControl: 0x202}},
	}
	f := NewNoPreauthOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (bit not set must not be flagged)", f.Count)
	}
}

// TestNoPreauthOnDisabledAccount_SeverityIsLow locks this detector's
// severity at Low, distinct from the High of the active-account detector.
func TestNoPreauthOnDisabledAccount_SeverityIsLow(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "svc-app", Disabled: true, ServicePrincipalNames: []string{"HTTP/svc-app.example.com"}, UserAccountControl: 0x400202}},
	}
	f := NewNoPreauthOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Severity != types.SeverityLow {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityLow)
	}
}
