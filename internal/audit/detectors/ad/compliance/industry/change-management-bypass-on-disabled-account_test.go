package industry

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

const twinSvcUserDN = "CN=svc,OU=Services,DC=test,DC=local"

// TestChangeManagementBypassOnDisabledAccount_DisabledWithSPNAndAdminCount_Fires
// covers the population this twin exists for: a disabled account with both a
// Service Principal Name and AdminCount=true must fire, with Count=1 (one
// account, no threshold) and Severity=Medium per the D1/D2 grid
// (AdminCount marks a domain-level privileged-group ACL).
func TestChangeManagementBypassOnDisabledAccount_DisabledWithSPNAndAdminCount_Fires(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: twinSvcUserDN, SAMAccountName: "svc", Disabled: true, ServicePrincipalNames: []string{"HTTP/svc.test.local"}, AdminCount: true},
		},
		IncludeDetails: true,
	}
	findings := NewChangeManagementBypassOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("disabled account with SPN+AdminCount must fire, got %+v", findings)
	}
	if findings[0].Type != "CHANGE_MANAGEMENT_BYPASS_ON_DISABLED_ACCOUNT" {
		t.Fatalf("finding type must be CHANGE_MANAGEMENT_BYPASS_ON_DISABLED_ACCOUNT, got %s", findings[0].Type)
	}
	if findings[0].Severity != types.SeverityMedium {
		t.Fatalf("Severity = %s, want Medium (AdminCount marks a privileged-group ACL)", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 {
		t.Fatalf("AffectedEntities = %d, want 1 (IncludeDetails set)", len(findings[0].AffectedEntities))
	}
}

// TestChangeManagementBypassOnDisabledAccount_ActiveExcluded kills the
// mirror guard `if u.Enabled() { continue }`: an ENABLED account with
// SPN+AdminCount belongs to the active detector's serviceAdmins
// sub-condition, not to this twin, and must not fire here.
func TestChangeManagementBypassOnDisabledAccount_ActiveExcluded(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: twinSvcUserDN, SAMAccountName: "svc", Disabled: false, ServicePrincipalNames: []string{"HTTP/svc.test.local"}, AdminCount: true},
		},
	}
	findings := NewChangeManagementBypassOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (enabled account must not fire in the disabled-account twin)", findings[0].Count)
	}
}

// TestChangeManagementBypassOnDisabledAccount_IncludeDetailsFalse_NoAffectedEntities
// kills the mutation that drops the `data.IncludeDetails &&` guard (line
// :67): a disabled account with SPN+AdminCount but IncludeDetails=false
// must still fire with Count=1, but AffectedEntities must stay empty.
func TestChangeManagementBypassOnDisabledAccount_IncludeDetailsFalse_NoAffectedEntities(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: twinSvcUserDN, SAMAccountName: "svc", Disabled: true, ServicePrincipalNames: []string{"HTTP/svc.test.local"}, AdminCount: true},
		},
		IncludeDetails: false,
	}
	findings := NewChangeManagementBypassOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (the account itself must still be counted)", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 0 {
		t.Fatalf("AffectedEntities = %d, want 0 (IncludeDetails=false must suppress details)", len(findings[0].AffectedEntities))
	}
}

// TestChangeManagementBypassOnDisabledAccount_SPNOnly_DoesNotFire covers a
// disabled account with an SPN but AdminCount=false: only one half of the
// AND condition is met, so it must not fire.
func TestChangeManagementBypassOnDisabledAccount_SPNOnly_DoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: twinSvcUserDN, SAMAccountName: "svc", Disabled: true, ServicePrincipalNames: []string{"HTTP/svc.test.local"}, AdminCount: false},
		},
	}
	findings := NewChangeManagementBypassOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (SPN alone, without AdminCount, must not fire)", findings[0].Count)
	}
}

// TestChangeManagementBypassOnDisabledAccount_AdminCountOnly_DoesNotFire
// covers a disabled account with AdminCount=true but no SPN: only one half
// of the AND condition is met, so it must not fire.
func TestChangeManagementBypassOnDisabledAccount_AdminCountOnly_DoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: twinSvcUserDN, SAMAccountName: "svc", Disabled: true, AdminCount: true},
		},
	}
	findings := NewChangeManagementBypassOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (AdminCount alone, without SPN, must not fire)", findings[0].Count)
	}
}
