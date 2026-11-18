package serviceaccounts

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestNoPreauth_ActiveServiceAccountFlagged is the baseline positive: an
// active (non-disabled) service account (SPN-bearing) with DONT_REQ_PREAUTH
// set must be counted here.
func TestNoPreauth_ActiveServiceAccountFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{
			SAMAccountName:        "svc-app",
			Disabled:              false,
			ServicePrincipalNames: []string{"HTTP/svc-app.example.com"},
			UserAccountControl:    0x400202,
		}},
		IncludeDetails: true,
	}
	f := NewNoPreauthDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (active service account with DONT_REQ_PREAUTH)", f.Count)
	}
	if f.Type != "SERVICE_ACCOUNT_NO_PREAUTH" {
		t.Fatalf("Type = %q, want SERVICE_ACCOUNT_NO_PREAUTH", f.Type)
	}
}

// TestNoPreauth_DisabledServiceAccountNotFlagged is the partition guard from
// this detector's side: a disabled service account with the same bit must
// not be counted here - it belongs to NoPreauthOnDisabledAccountDetector
// instead.
func TestNoPreauth_DisabledServiceAccountNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{
			SAMAccountName:        "svc-app",
			Disabled:              true,
			ServicePrincipalNames: []string{"HTTP/svc-app.example.com"},
			UserAccountControl:    0x400202,
		}},
	}
	f := NewNoPreauthDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (disabled account must not be counted here)", f.Count)
	}
}

// TestNoPreauth_NonServiceAccountNotFlagged: an active ordinary user (no
// SPN, no service naming pattern) with the bit set must not be counted -
// isServiceAccount excludes it.
func TestNoPreauth_NonServiceAccountNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "jdupont", Disabled: false, UserAccountControl: 0x400202}},
	}
	f := NewNoPreauthDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (non-service-account must not be flagged)", f.Count)
	}
}

// TestNoPreauth_ActiveServiceAccountWithoutBitNotFlagged: an active service
// account without DONT_REQ_PREAUTH must not be counted.
func TestNoPreauth_ActiveServiceAccountWithoutBitNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "svc-app", Disabled: false, ServicePrincipalNames: []string{"HTTP/svc-app.example.com"}, UserAccountControl: 0x202}},
	}
	f := NewNoPreauthDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (bit not set must not be flagged)", f.Count)
	}
}
