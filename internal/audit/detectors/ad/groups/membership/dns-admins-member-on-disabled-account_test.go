package membership

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestDnsAdminsMemberOnDisabledAccount_DisabledMemberFires is the mirror
// positive of TestDnsAdminsMember_DisabledUserNotFlagged: a disabled direct
// member of the real DnsAdmins group must be counted here.
func TestDnsAdminsMemberOnDisabledAccount_DisabledMemberFires(t *testing.T) {
	g := types.Group{
		SAMAccountName: "DnsAdmins",
		DN:             "CN=DnsAdmins,CN=Users,DC=example,DC=com",
	}
	u := types.User{
		DN:             "CN=disabled-member,CN=Users,DC=example,DC=com",
		SAMAccountName: "disabled-member",
		Disabled:       true,
		MemberOf:       []string{"CN=DnsAdmins,CN=Users,DC=example,DC=com"},
	}
	data := &audit.DetectorData{Users: []types.User{u}, Groups: []types.Group{g}, IncludeDetails: true}

	f := NewDnsAdminsMemberOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled member of the real DnsAdmins group must fire here)", f.Count)
	}
	if len(f.AffectedEntities) != 1 || f.AffectedEntities[0].DN != u.DN {
		t.Fatalf("AffectedEntities = %v, want only %q", f.AffectedEntities, u.DN)
	}
}

// TestDnsAdminsMemberOnDisabledAccount_ActiveMemberDoesNotFire is the
// mirror negative: an active (non-disabled) member of the real DnsAdmins
// group must not be counted here - it is covered instead by
// DnsAdminsMemberDetector (dns-admins-member.go).
func TestDnsAdminsMemberOnDisabledAccount_ActiveMemberDoesNotFire(t *testing.T) {
	g := types.Group{
		SAMAccountName: "DnsAdmins",
		DN:             "CN=DnsAdmins,CN=Users,DC=example,DC=com",
	}
	u := types.User{
		SAMAccountName: "active-member",
		Disabled:       false,
		MemberOf:       []string{"CN=DnsAdmins,CN=Users,DC=example,DC=com"},
	}
	data := &audit.DetectorData{Users: []types.User{u}, Groups: []types.Group{g}}

	f := NewDnsAdminsMemberOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (active member must not fire here, covered by the active detector instead)", f.Count)
	}
}

// TestDnsAdminsMemberOnDisabledAccount_DisabledNonMemberDoesNotFire proves
// the group-membership condition still applies: a disabled user who is NOT
// a member of DnsAdmins must not be counted.
func TestDnsAdminsMemberOnDisabledAccount_DisabledNonMemberDoesNotFire(t *testing.T) {
	g := types.Group{
		SAMAccountName: "DnsAdmins",
		DN:             "CN=DnsAdmins,CN=Users,DC=example,DC=com",
	}
	u := types.User{
		SAMAccountName: "disabled-non-member",
		Disabled:       true,
		MemberOf:       []string{"CN=SomeOtherGroup,CN=Users,DC=example,DC=com"},
	}
	data := &audit.DetectorData{Users: []types.User{u}, Groups: []types.Group{g}}

	f := NewDnsAdminsMemberOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (disabled but not a DnsAdmins member)", f.Count)
	}
}

// TestDnsAdminsMemberOnDisabledAccount_TypeAndSeverity locks the finding's
// identifying fields, in particular the Medium severity mandated by the
// split severity grid (D1) for a domain-level privilege.
func TestDnsAdminsMemberOnDisabledAccount_TypeAndSeverity(t *testing.T) {
	data := &audit.DetectorData{}
	f := NewDnsAdminsMemberOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Type != "DNS_ADMINS_MEMBER_ON_DISABLED_ACCOUNT" {
		t.Fatalf("Type = %q, want %q", f.Type, "DNS_ADMINS_MEMBER_ON_DISABLED_ACCOUNT")
	}
	if f.Severity != types.SeverityMedium {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityMedium)
	}
}

// TestDnsAdminsMemberOnDisabledAccount_IncludeDetailsFalseNoEntities proves
// that with IncludeDetails=false, AffectedEntities stays empty even though
// the same user is counted (Count=1).
func TestDnsAdminsMemberOnDisabledAccount_IncludeDetailsFalseNoEntities(t *testing.T) {
	g := types.Group{
		SAMAccountName: "DnsAdmins",
		DN:             "CN=DnsAdmins,CN=Users,DC=example,DC=com",
	}
	u := types.User{
		DN:             "CN=disabled-member,CN=Users,DC=example,DC=com",
		SAMAccountName: "disabled-member",
		Disabled:       true,
		MemberOf:       []string{"CN=DnsAdmins,CN=Users,DC=example,DC=com"},
	}
	data := &audit.DetectorData{Users: []types.User{u}, Groups: []types.Group{g}, IncludeDetails: false}

	f := NewDnsAdminsMemberOnDisabledAccountDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (member still counted regardless of IncludeDetails)", f.Count)
	}
	if len(f.AffectedEntities) != 0 {
		t.Fatalf("len(AffectedEntities) = %d, want 0 (IncludeDetails=false must not populate entities)", len(f.AffectedEntities))
	}
}
