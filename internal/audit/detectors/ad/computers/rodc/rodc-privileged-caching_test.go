package rodc

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func run(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	d := NewRODCPrivilegedCachingDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	return findings[0]
}

func TestRODC_NoRODCs(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{SAMAccountName: "DC01$", IsRODC: false, RevealedList: []string{"CN=Administrator,DC=test,DC=local"}},
		},
		Users: []types.User{
			{DN: "CN=Administrator,DC=test,DC=local", AdminCount: true},
		},
		IncludeDetails: true,
	}
	f := run(t, data)
	if f.Count != 0 {
		t.Fatalf("expected 0 findings for domain with no RODCs, got %d", f.Count)
	}
}

func TestRODC_EmptyRevealedList(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{SAMAccountName: "RODC01$", DNSHostName: "rodc01.test.local", IsRODC: true, RevealedList: nil},
		},
		IncludeDetails: true,
	}
	f := run(t, data)
	if f.Count != 0 {
		t.Fatalf("expected 0 findings for RODC with empty revealed list, got %d", f.Count)
	}
}

func TestRODC_NonPrivilegedCached(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{SAMAccountName: "RODC01$", DNSHostName: "rodc01.test.local", IsRODC: true,
				RevealedList: []string{"CN=JohnDoe,OU=Users,DC=test,DC=local"}},
		},
		Users: []types.User{
			{DN: "CN=JohnDoe,OU=Users,DC=test,DC=local", SAMAccountName: "jdoe", AdminCount: false},
		},
		IncludeDetails: true,
	}
	f := run(t, data)
	if f.Count != 0 {
		t.Fatalf("expected 0 findings for non-privileged reveal, got %d", f.Count)
	}
}

// TestRODC_PrivilegedCached covers a parser bug: msDS-RevealedList carries
// the Object(DN-String) MS-ADTS syntax ("S:<char count>:<lDAPDisplayName>:
// <object DN>", e.g. "S:10:unicodePwd:CN=..."), not a bare DN. The fixture
// here previously used a bare DN, which happened to match the (buggy)
// bare-DN comparison in the detector - masking the bug instead of proving
// anything about it. Fixed to the real LDAP format: RED on the pre-fix
// detector (bare strings.ToLower(revealedDN) never matches a DN prefixed
// with "S:10:unicodePwd:"), GREEN after (extractRevealedDN strips the
// prefix).
func TestRODC_PrivilegedCached(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{SAMAccountName: "RODC01$", DNSHostName: "rodc01.test.local", IsRODC: true,
				RevealedList: []string{"S:10:unicodePwd:CN=Administrator,DC=test,DC=local"}},
		},
		Users: []types.User{
			{DN: "CN=Administrator,DC=test,DC=local", SAMAccountName: "Administrator", AdminCount: true},
		},
		IncludeDetails: true,
	}
	f := run(t, data)
	if f.Count != 1 {
		t.Fatalf("expected 1 finding for privileged reveal, got %d", f.Count)
	}
	if f.Severity != types.SeverityCritical {
		t.Fatalf("expected severity critical, got %s", f.Severity)
	}
}

// TestRODC_MultipleRODCsMixed: same real-LDAP-format correction as
// TestRODC_PrivilegedCached above, for the two entries expected to match.
func TestRODC_MultipleRODCsMixed(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{SAMAccountName: "RODC01$", DNSHostName: "rodc01.test.local", IsRODC: true,
				RevealedList: []string{"S:10:unicodePwd:CN=Administrator,DC=test,DC=local"}},
			{SAMAccountName: "RODC02$", DNSHostName: "rodc02.test.local", IsRODC: true,
				RevealedList: []string{"S:10:unicodePwd:CN=JohnDoe,OU=Users,DC=test,DC=local"}},
			{SAMAccountName: "RODC03$", DNSHostName: "rodc03.test.local", IsRODC: true,
				RevealedList: []string{"S:10:unicodePwd:CN=DomainAdminsGroup,DC=test,DC=local"}},
		},
		Users: []types.User{
			{DN: "CN=Administrator,DC=test,DC=local", SAMAccountName: "Administrator", AdminCount: true},
			{DN: "CN=JohnDoe,OU=Users,DC=test,DC=local", SAMAccountName: "jdoe", AdminCount: false},
		},
		Groups: []types.Group{
			{DN: "CN=DomainAdminsGroup,DC=test,DC=local", SAMAccountName: "Domain Admins", ObjectSID: "S-1-5-21-1-2-3-512"},
		},
		IncludeDetails: true,
	}
	f := run(t, data)
	if f.Count != 2 {
		t.Fatalf("expected 2 findings (RODC01 + RODC03), got %d", f.Count)
	}
}

// TestRODC_MalformedRevealedValue_Skipped: a value that doesn't match the
// documented "S:n:attr:DN" shape must degrade to a miss (fallback:
// lowercase the raw value), never be guessed at - doctrine "pas de
// verdict sans donnée".
func TestRODC_MalformedRevealedValue_Skipped(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{SAMAccountName: "RODC01$", DNSHostName: "rodc01.test.local", IsRODC: true,
				RevealedList: []string{"not-the-expected-format-at-all"}},
		},
		Users: []types.User{
			{DN: "CN=Administrator,DC=test,DC=local", SAMAccountName: "Administrator", AdminCount: true},
		},
		IncludeDetails: true,
	}
	f := run(t, data)
	if f.Count != 0 {
		t.Fatalf("expected 0 findings for a malformed RevealedList value, got %d", f.Count)
	}
}

// TestRODC_TwoPrivilegedRevealsSameRODC_CountedOnce: a single RODC that has
// revealed two distinct privileged principals must still count as ONE
// affected RODC (Count == 1), while both pairs appear in the detail list.
// This is the only test that exercises flaggedThisRODC's per-RODC dedup
// (mutation a).
func TestRODC_TwoPrivilegedRevealsSameRODC_CountedOnce(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{SAMAccountName: "RODC01$", DNSHostName: "rodc01.test.local", IsRODC: true,
				RevealedList: []string{
					"S:10:unicodePwd:CN=Administrator,DC=test,DC=local",
					"S:10:unicodePwd:CN=DomainAdminsGroup,DC=test,DC=local",
				}},
		},
		Users: []types.User{
			{DN: "CN=Administrator,DC=test,DC=local", SAMAccountName: "Administrator", AdminCount: true},
		},
		Groups: []types.Group{
			{DN: "CN=DomainAdminsGroup,DC=test,DC=local", SAMAccountName: "Domain Admins", ObjectSID: "S-1-5-21-1-2-3-512"},
		},
		IncludeDetails: true,
	}
	f := run(t, data)
	if f.Count != 1 {
		t.Fatalf("expected 1 affected RODC (deduped), got %d", f.Count)
	}
	pairs, _ := f.Details["pairs"].([]string)
	if len(pairs) != 2 {
		t.Fatalf("expected 2 detail pairs for the two reveals, got %d: %v", len(pairs), pairs)
	}
}

// TestRODC_GroupPrivilegedByAdminCountOnly: a group flagged privileged solely
// via AdminCount=true, with a SID that matches no well-known privileged
// suffix, must still be treated as privileged (mutation b: removing
// g.AdminCount from the condition).
func TestRODC_GroupPrivilegedByAdminCountOnly(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{SAMAccountName: "RODC01$", DNSHostName: "rodc01.test.local", IsRODC: true,
				RevealedList: []string{"S:10:unicodePwd:CN=CustomPrivGroup,DC=test,DC=local"}},
		},
		Groups: []types.Group{
			{DN: "CN=CustomPrivGroup,DC=test,DC=local", SAMAccountName: "CustomPrivGroup",
				ObjectSID: "S-1-5-21-1-2-3-9999", AdminCount: true},
		},
		IncludeDetails: true,
	}
	f := run(t, data)
	if f.Count != 1 {
		t.Fatalf("expected 1 finding for a group privileged by adminCount only, got %d", f.Count)
	}
}

// TestRODC_UserPrivilegedBySIDOnly: a user with AdminCount=false but a SID
// matching a well-known privileged group suffix (Enterprise Admins, -519)
// must still be treated as privileged (mutation c: removing
// audit.IsPrivilegedSID(u.ObjectSID) from the condition).
func TestRODC_UserPrivilegedBySIDOnly(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{SAMAccountName: "RODC01$", DNSHostName: "rodc01.test.local", IsRODC: true,
				RevealedList: []string{"S:10:unicodePwd:CN=SidOnlyUser,OU=Users,DC=test,DC=local"}},
		},
		Users: []types.User{
			{DN: "CN=SidOnlyUser,OU=Users,DC=test,DC=local", SAMAccountName: "sidonlyuser",
				ObjectSID: "S-1-5-21-1-2-3-519", AdminCount: false},
		},
		IncludeDetails: true,
	}
	f := run(t, data)
	if f.Count != 1 {
		t.Fatalf("expected 1 finding for a user privileged by SID only, got %d", f.Count)
	}
}

// TestRODC_EmptyDNUser_NotIndexed: a user that is privileged (AdminCount)
// but carries an empty DN must never be indexed into privilegedDNs, so a
// revealed entry that degrades to the same empty key must not match
// (mutation e: removing the u.DN != "" guard).
func TestRODC_EmptyDNUser_NotIndexed(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{SAMAccountName: "RODC01$", DNSHostName: "rodc01.test.local", IsRODC: true,
				RevealedList: []string{""}},
		},
		Users: []types.User{
			{DN: "", SAMAccountName: "ghostadmin", AdminCount: true},
		},
		IncludeDetails: true,
	}
	f := run(t, data)
	if f.Count != 0 {
		t.Fatalf("expected 0 findings when the privileged user's DN is empty, got %d", f.Count)
	}
}

// TestRODC_NonRODCComputer_NotCounted: a computer that is NOT an RODC must
// never be counted even if its RevealedList (however populated) contains a
// privileged principal (mutation d: removing the !c.IsRODC guard).
func TestRODC_NonRODCComputer_NotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{SAMAccountName: "DC02$", DNSHostName: "dc02.test.local", IsRODC: false,
				RevealedList: []string{"S:10:unicodePwd:CN=Administrator,DC=test,DC=local"}},
		},
		Users: []types.User{
			{DN: "CN=Administrator,DC=test,DC=local", SAMAccountName: "Administrator", AdminCount: true},
		},
		IncludeDetails: true,
	}
	f := run(t, data)
	if f.Count != 0 {
		t.Fatalf("expected 0 findings for a non-RODC computer, got %d", f.Count)
	}
}
