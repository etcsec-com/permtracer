package industry

import (
	"context"
	"fmt"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

const domainAdminsDN = "CN=Domain Admins,CN=Users,DC=test,DC=local"
const enterpriseAdminsDN = "CN=Enterprise Admins,CN=Users,DC=test,DC=local"

func adminUsers(n int, disabled bool) []types.User {
	users := make([]types.User, n)
	for i := range users {
		users[i] = types.User{
			DN:             fmt.Sprintf("CN=admin%d,DC=test,DC=local", i),
			SAMAccountName: fmt.Sprintf("admin%d", i),
			MemberOf:       []string{domainAdminsDN},
			Disabled:       disabled,
		}
	}
	return users
}

func enterpriseAdminUsers(n int, disabled bool) []types.User {
	users := make([]types.User, n)
	for i := range users {
		users[i] = types.User{
			DN:             fmt.Sprintf("CN=eadmin%d,DC=test,DC=local", i),
			SAMAccountName: fmt.Sprintf("eadmin%d", i),
			MemberOf:       []string{enterpriseAdminsDN},
			Disabled:       disabled,
		}
	}
	return users
}

func adminCountOnlyUsers(n int, disabled bool) []types.User {
	users := make([]types.User, n)
	for i := range users {
		users[i] = types.User{
			DN:             fmt.Sprintf("CN=ac%d,DC=test,DC=local", i),
			SAMAccountName: fmt.Sprintf("ac%d", i),
			AdminCount:     true,
			Disabled:       disabled,
		}
	}
	return users
}

func spnOnlyUsers(n int, disabled bool) []types.User {
	users := make([]types.User, n)
	for i := range users {
		users[i] = types.User{
			DN:                    fmt.Sprintf("CN=spn%d,DC=test,DC=local", i),
			SAMAccountName:        fmt.Sprintf("spn%d", i),
			ServicePrincipalNames: []string{fmt.Sprintf("HTTP/spn%d.test.local", i)},
			Disabled:              disabled,
		}
	}
	return users
}

func serviceAdminUsers(n int, disabled bool) []types.User {
	users := make([]types.User, n)
	for i := range users {
		users[i] = types.User{
			DN:                    fmt.Sprintf("CN=svc%d,DC=test,DC=local", i),
			SAMAccountName:        fmt.Sprintf("svc%d", i),
			ServicePrincipalNames: []string{fmt.Sprintf("HTTP/svc%d.test.local", i)},
			AdminCount:            true,
			Disabled:              disabled,
		}
	}
	return users
}

// TestChangeManagementBypass_AdminCountBoundary covers the adminCount > 10
// threshold (sub-condition 1, unchanged by this ticket): 10 enabled Domain
// Admins members must not fire, 11 must fire.
func TestChangeManagementBypass_AdminCountBoundary(t *testing.T) {
	t.Run("10 enabled admins does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{Users: adminUsers(10, false)}
		findings := NewChangeManagementBypassDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("Count = %d, want 0 at the adminCount=10 boundary", findings[0].Count)
		}
	})

	t.Run("11 enabled admins fires", func(t *testing.T) {
		data := &audit.DetectorData{Users: adminUsers(11, false)}
		findings := NewChangeManagementBypassDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("Count = %d, want 1 at adminCount=11", findings[0].Count)
		}
	})
}

// TestChangeManagementBypass_ServiceAdminsBoundary covers the serviceAdmins
// > 5 threshold (sub-condition 2, line :65): 5 enabled SPN+AdminCount
// accounts must not fire, 6 must fire.
func TestChangeManagementBypass_ServiceAdminsBoundary(t *testing.T) {
	t.Run("5 enabled service admins does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{Users: serviceAdminUsers(5, false)}
		findings := NewChangeManagementBypassDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("Count = %d, want 0 at the serviceAdmins=5 boundary", findings[0].Count)
		}
	})

	t.Run("6 enabled service admins fires", func(t *testing.T) {
		data := &audit.DetectorData{Users: serviceAdminUsers(6, false)}
		findings := NewChangeManagementBypassDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("Count = %d, want 1 at serviceAdmins=6", findings[0].Count)
		}
		if findings[0].Severity != types.SeverityMedium {
			t.Fatalf("Severity = %s, want Medium", findings[0].Severity)
		}
	})
}

// TestChangeManagementBypass_OR confirms the two sub-conditions are combined
// with OR into the single binary Count: either one firing alone is enough.
func TestChangeManagementBypass_OR(t *testing.T) {
	t.Run("only adminCount over threshold fires", func(t *testing.T) {
		data := &audit.DetectorData{Users: adminUsers(11, false)}
		findings := NewChangeManagementBypassDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("Count = %d, want 1 (adminCount alone over threshold)", findings[0].Count)
		}
	})

	t.Run("only serviceAdmins over threshold fires", func(t *testing.T) {
		data := &audit.DetectorData{Users: serviceAdminUsers(6, false)}
		findings := NewChangeManagementBypassDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("Count = %d, want 1 (serviceAdmins alone over threshold)", findings[0].Count)
		}
	})

	t.Run("neither over threshold does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{Users: append(adminUsers(10, false), serviceAdminUsers(5, false)...)}
		findings := NewChangeManagementBypassDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("Count = %d, want 0 (both sub-conditions at their boundary, neither fires)", findings[0].Count)
		}
	})
}

// TestChangeManagementBypass_DisabledAdminCountExcluded kills the "garde
// Enabled retiree" mutation on sub-condition 1 (line :46): 11 disabled Domain
// Admins members must not be counted in adminCount, so the detector must not
// fire. If the `if !u.Enabled() { continue }` guard at line :46 is removed,
// this test fails with Count=1.
func TestChangeManagementBypass_DisabledAdminCountExcluded(t *testing.T) {
	data := &audit.DetectorData{Users: adminUsers(11, true)}
	findings := NewChangeManagementBypassDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (disabled Domain Admins members must be excluded from adminCount)", findings[0].Count)
	}
	if privileged, _ := findings[0].Details["privilegedAccounts"].(int); privileged != 0 {
		t.Fatalf("privilegedAccounts = %v, want 0 (disabled accounts excluded)", privileged)
	}
}

// TestChangeManagementBypass_ServiceAdminsRequiresSPNAndAdminCount kills
// mutations that reduce the serviceAdmins AND condition (line :68,
// `len(u.ServicePrincipalNames) > 0 && u.AdminCount`) to only one of its two
// operands: 6 enabled users with AdminCount but no SPN, and 6 enabled users
// with an SPN but no AdminCount, must each leave serviceAdmins at 0 since
// both halves of the AND are required, so Count stays 0 in both cases.
func TestChangeManagementBypass_ServiceAdminsRequiresSPNAndAdminCount(t *testing.T) {
	t.Run("AdminCount without SPN does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{Users: adminCountOnlyUsers(6, false)}
		findings := NewChangeManagementBypassDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("Count = %d, want 0 (AdminCount alone, without SPN, must not count as a service admin)", findings[0].Count)
		}
	})

	t.Run("SPN without AdminCount does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{Users: spnOnlyUsers(6, false)}
		findings := NewChangeManagementBypassDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("Count = %d, want 0 (SPN alone, without AdminCount, must not count as a service admin)", findings[0].Count)
		}
	})
}

// TestChangeManagementBypass_EnterpriseAdminsMembershipCounted kills the
// mutation that replaces the "enterprise admins" substring check (line :51)
// with a literal false: 11 enabled users who are members of Enterprise
// Admins only (not Domain Admins) must still be counted into adminCount and
// fire, since the two group names are combined with OR.
func TestChangeManagementBypass_EnterpriseAdminsMembershipCounted(t *testing.T) {
	data := &audit.DetectorData{Users: enterpriseAdminUsers(11, false)}
	findings := NewChangeManagementBypassDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (11 Enterprise Admins members alone must cross the adminCount>10 threshold)", findings[0].Count)
	}
	if privileged, _ := findings[0].Details["privilegedAccounts"].(int); privileged != 11 {
		t.Fatalf("privilegedAccounts = %v, want 11", privileged)
	}
}

// TestChangeManagementBypass_DisabledServiceAdminsExcluded kills the "garde
// Enabled retiree" mutation on sub-condition 2 (line :65, added by this
// ticket): 6 disabled service accounts with SPN+AdminCount must not be
// counted in serviceAdmins, so the detector must not fire. If the
// `if !u.Enabled() { continue }` guard at line :65 is removed, this test
// fails with Count=1.
func TestChangeManagementBypass_DisabledServiceAdminsExcluded(t *testing.T) {
	data := &audit.DetectorData{Users: serviceAdminUsers(6, true)}
	findings := NewChangeManagementBypassDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (disabled service admin accounts must be excluded from serviceAdmins)", findings[0].Count)
	}
	if serviceAccountsAdmin, _ := findings[0].Details["serviceAccountsAdmin"].(int); serviceAccountsAdmin != 0 {
		t.Fatalf("serviceAccountsAdmin = %v, want 0 (disabled accounts excluded)", serviceAccountsAdmin)
	}
}
