package smb

import "testing"

// TestParseRegistryValues_RestrictRemoteSAM is the regression test.
// RestrictRemoteSAM is configured as a Security Option in GptTmpl.inf's
// [Registry Values] section, which Windows writes as REG_SZ (type 1) - an
// SDDL string, never a REG_DWORD. parseRegistryValues used to filter to
// type-4 entries only and had no case for it at all, so this path was
// invisible regardless of GPO content.
func TestParseRegistryValues_RestrictRemoteSAM(t *testing.T) {
	sec := map[string]string{
		`MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSam`: `1,"O:BAG:BAD:(A;;RC;;;BA)"`,
	}

	rs := parseRegistryValues(sec)

	if rs == nil {
		t.Fatal("parseRegistryValues returned nil for a section containing RestrictRemoteSam")
	}
	if rs.RestrictRemoteSAM == nil {
		t.Fatal("RestrictRemoteSAM not populated")
	}
	if got, want := *rs.RestrictRemoteSAM, `O:BAG:BAD:(A;;RC;;;BA)`; got != want {
		t.Fatalf("RestrictRemoteSAM = %q, want %q (quotes must be stripped)", got, want)
	}
}

// TestParseRegistryValues_DwordEntriesStillWork guards against a regression
// where broadening the type filter from "type 4 only" to
// "4, or 1/2 for a couple of string settings" breaks the REG_DWORD path
// every other setting in this function relies on.
func TestParseRegistryValues_DwordEntriesStillWork(t *testing.T) {
	sec := map[string]string{
		`MACHINE\System\CurrentControlSet\Control\Lsa\RunAsPPL`: `4,1`,
	}

	rs := parseRegistryValues(sec)

	if rs == nil || rs.LSARunAsPPL == nil {
		t.Fatal("RunAsPPL (REG_DWORD) not populated")
	}
	if *rs.LSARunAsPPL != 1 {
		t.Fatalf("LSARunAsPPL = %d, want 1", *rs.LSARunAsPPL)
	}
}

// TestParseRegistryValues_UnrecognizedStringIgnored confirms a REG_SZ/
// REG_EXPAND_SZ entry that isn't RestrictRemoteSAM doesn't get misfiled
// into it, and doesn't make the function report found=true on its own.
func TestParseRegistryValues_UnrecognizedStringIgnored(t *testing.T) {
	sec := map[string]string{
		`MACHINE\Some\Unrelated\StringValue`: `1,"whatever"`,
	}

	rs := parseRegistryValues(sec)

	if rs != nil {
		t.Fatalf("expected nil for a section with no recognized entries, got %+v", rs)
	}
}

// TestParseGroupMembership_SingleSpecWithMembersAndMemberof kills P2
// (`if len(sec) == 0` -> `if true || (…)`, which makes the function always
// return nil), P3 (`if idx < 0 { continue }` -> `if true || (…)`, which skips
// every key including well-formed ones) and P5 (`if !ok {…}` -> `if true ||
// !ok`, which re-creates the spec on every key and lets `__Memberof`
// overwrite the `__Members` aggregation instead of merging into the same
// spec).
// Both __Members and __Memberof carry a non-empty, distinct value on
// purpose: correct code aggregates both fields onto the same spec regardless
// of which map key is visited first, while the P5 mutation (recreating the
// spec from scratch on every key instead of reusing the existing one)
// populates only whichever field was set by the LAST key visited - which
// field that is depends on Go's randomized map iteration order. Asserting
// both fields simultaneously therefore fails under the mutation on every
// run, not just on an unlucky map order.
func TestParseGroupMembership_SingleSpecWithMembersAndMemberof(t *testing.T) {
	sec := map[string]string{
		"*S-1-5-32-544__Members":  "*S-1-5-21-1-2-3-512,*S-1-5-21-1-2-3-1001",
		"*S-1-5-32-544__Memberof": "*S-1-5-21-1-2-3-999",
	}

	specs := parseGroupMembership(sec)

	if len(specs) != 1 {
		t.Fatalf("expected exactly 1 spec, got %d: %+v", len(specs), specs)
	}
	spec := specs[0]
	if spec.GroupSID != "S-1-5-32-544" {
		t.Fatalf("GroupSID = %q, want %q (leading '*' must be stripped)", spec.GroupSID, "S-1-5-32-544")
	}
	wantMembers := []string{"S-1-5-21-1-2-3-512", "S-1-5-21-1-2-3-1001"}
	if len(spec.MembersSIDs) != len(wantMembers) {
		t.Fatalf("MembersSIDs = %v, want %v (both __Members and __Memberof must aggregate onto the same spec)", spec.MembersSIDs, wantMembers)
	}
	for i, want := range wantMembers {
		if spec.MembersSIDs[i] != want {
			t.Fatalf("MembersSIDs[%d] = %q, want %q", i, spec.MembersSIDs[i], want)
		}
	}
	wantMemberOf := []string{"S-1-5-21-1-2-3-999"}
	if len(spec.MemberOfSIDs) != len(wantMemberOf) || spec.MemberOfSIDs[0] != wantMemberOf[0] {
		t.Fatalf("MemberOfSIDs = %v, want %v (both __Members and __Memberof must aggregate onto the same spec)", spec.MemberOfSIDs, wantMemberOf)
	}
}

// TestParseGroupMembership_KeyWithoutDunderIgnoredWithoutPanic kills P4
// (`if idx < 0 { continue }` -> `if false && (…)`), which lets a key with no
// "__" separator fall through to `key[:idx]` with idx == -1 and panic on the
// slice expression instead of being skipped.
func TestParseGroupMembership_KeyWithoutDunderIgnoredWithoutPanic(t *testing.T) {
	sec := map[string]string{
		"NoSeparatorHere": "*S-1-5-21-1-2-3-500",
	}

	specs := parseGroupMembership(sec)

	if len(specs) != 0 {
		t.Fatalf("expected no specs for a key without '__', got %+v", specs)
	}
}

// TestParseGroupMembership_EmptySectionReturnsNoSpecs documents the empty-
// input behavior so a later change to the len(sec)==0 guard is caught.
func TestParseGroupMembership_EmptySectionReturnsNoSpecs(t *testing.T) {
	specs := parseGroupMembership(map[string]string{})

	if len(specs) != 0 {
		t.Fatalf("expected no specs for an empty section, got %+v", specs)
	}
}

// TestParseGroupMembership_TwoDistinctPrincipalsProduceTwoSpecs kills P6
// (`if !ok {…}` -> `if false && !ok`), which skips creating the spec map
// entry entirely and dereferences a nil *RestrictedGroupSpec on the first
// key seen for any principal.
func TestParseGroupMembership_TwoDistinctPrincipalsProduceTwoSpecs(t *testing.T) {
	sec := map[string]string{
		"*S-1-5-32-544__Members": "*S-1-5-21-1-2-3-500",
		"*S-1-5-32-551__Members": "*S-1-5-21-1-2-3-600",
	}

	specs := parseGroupMembership(sec)

	if len(specs) != 2 {
		t.Fatalf("expected 2 distinct specs, got %d: %+v", len(specs), specs)
	}

	bySID := map[string][]string{}
	for _, s := range specs {
		bySID[s.GroupSID] = s.MembersSIDs
	}
	if got, ok := bySID["S-1-5-32-544"]; !ok || len(got) != 1 || got[0] != "S-1-5-21-1-2-3-500" {
		t.Fatalf("spec for S-1-5-32-544 wrong: %v (ok=%v)", got, ok)
	}
	if got, ok := bySID["S-1-5-32-551"]; !ok || len(got) != 1 || got[0] != "S-1-5-21-1-2-3-600" {
		t.Fatalf("spec for S-1-5-32-551 wrong: %v (ok=%v)", got, ok)
	}
}

// TestParseSIDList_TrimsAndDropsEmptyEntries kills P7
// (`if sid != ""` -> `if true || (…)`, which injects empty-string SIDs) and
// P8 (`if sid != ""` -> `if false && (…)`, which always produces an empty
// list regardless of input).
func TestParseSIDList_TrimsAndDropsEmptyEntries(t *testing.T) {
	got := parseSIDList(" *S-1, , *S-2 ")

	want := []string{"S-1", "S-2"}
	if len(got) != len(want) {
		t.Fatalf("parseSIDList(...) = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parseSIDList(...)[%d] = %q, want %q (full result %v)", i, got[i], want[i], got)
		}
	}
	for _, sid := range got {
		if sid == "" {
			t.Fatalf("parseSIDList(...) contains an empty SID: %v", got)
		}
	}
}

// TestParseSIDList_EmptyStringReturnsEmptyList is the sibling case for P8:
// an empty input must yield an empty (nil or zero-length) list, not a list
// containing an empty string.
func TestParseSIDList_EmptyStringReturnsEmptyList(t *testing.T) {
	got := parseSIDList("")

	if len(got) != 0 {
		t.Fatalf("parseSIDList(\"\") = %v, want empty list", got)
	}
}

// TestParseGptTmpl_GroupMembershipSection exercises ParseGptTmpl end-to-end
// on a minimal in-memory GptTmpl.inf containing [Unicode], [Version] and
// [Group Membership], confirming the Restricted Groups return value is wired
// through from the raw file bytes.
func TestParseGptTmpl_GroupMembershipSection(t *testing.T) {
	content := "[Unicode]\n" +
		"Unicode=yes\n" +
		"[Version]\n" +
		"signature=\"$CHICAGO$\"\n" +
		"Revision=1\n" +
		"[Group Membership]\n" +
		"*S-1-5-32-544__Members = *S-1-5-21-1-2-3-500\n" +
		"*S-1-5-32-544__Memberof =\n"

	_, _, _, _, _, rg := ParseGptTmpl([]byte(content))

	if len(rg) != 1 {
		t.Fatalf("expected exactly 1 RestrictedGroupSpec, got %d: %+v", len(rg), rg)
	}
	if rg[0].GroupSID != "S-1-5-32-544" {
		t.Fatalf("GroupSID = %q, want %q", rg[0].GroupSID, "S-1-5-32-544")
	}
	if len(rg[0].MembersSIDs) != 1 || rg[0].MembersSIDs[0] != "S-1-5-21-1-2-3-500" {
		t.Fatalf("MembersSIDs = %v, want [S-1-5-21-1-2-3-500]", rg[0].MembersSIDs)
	}
}

// TestParseRegistryValues_SMBServerSigning kills the disabled-branch
// mutation on the LanManServer RequireSecuritySignature (server) case of
// parseRegistryValues. The section carries ONLY this one key so that a
// disabled branch leaves rs nil (found stays false) instead of populating
// RequireSMBSigningServer.
func TestParseRegistryValues_SMBServerSigning(t *testing.T) {
	sec := map[string]string{
		`MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature`: `4,1`,
	}

	rs := parseRegistryValues(sec)

	if rs == nil || rs.RequireSMBSigningServer == nil {
		t.Fatal("RequireSMBSigningServer not populated from the LanmanServer RequireSecuritySignature entry")
	}
	if *rs.RequireSMBSigningServer != 1 {
		t.Fatalf("RequireSMBSigningServer = %d, want 1", *rs.RequireSMBSigningServer)
	}
}

// TestParseRegistryValues_SMBClientSigning kills the disabled-branch
// mutation on the LanmanWorkstation RequireSecuritySignature (client) case.
func TestParseRegistryValues_SMBClientSigning(t *testing.T) {
	sec := map[string]string{
		`MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature`: `4,1`,
	}

	rs := parseRegistryValues(sec)

	if rs == nil || rs.RequireSMBSigningClient == nil {
		t.Fatal("RequireSMBSigningClient not populated from the LanmanWorkstation RequireSecuritySignature entry")
	}
	if *rs.RequireSMBSigningClient != 1 {
		t.Fatalf("RequireSMBSigningClient = %d, want 1", *rs.RequireSMBSigningClient)
	}
}

// TestParseRegistryValues_LDAPServerIntegrity kills the disabled-branch
// mutation on the NTDS LDAPServerIntegrity case.
func TestParseRegistryValues_LDAPServerIntegrity(t *testing.T) {
	sec := map[string]string{
		`MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity`: `4,2`,
	}

	rs := parseRegistryValues(sec)

	if rs == nil || rs.LDAPServerIntegrity == nil {
		t.Fatal("LDAPServerIntegrity not populated from the NTDS LDAPServerIntegrity entry")
	}
	if *rs.LDAPServerIntegrity != 2 {
		t.Fatalf("LDAPServerIntegrity = %d, want 2", *rs.LDAPServerIntegrity)
	}
}

// TestParseRegistryValues_LDAPChannelBinding kills the disabled-branch
// mutation on the NTDS LdapEnforceChannelBinding case.
func TestParseRegistryValues_LDAPChannelBinding(t *testing.T) {
	sec := map[string]string{
		`MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding`: `4,2`,
	}

	rs := parseRegistryValues(sec)

	if rs == nil || rs.LDAPChannelBinding == nil {
		t.Fatal("LDAPChannelBinding not populated from the NTDS LdapEnforceChannelBinding entry")
	}
	if *rs.LDAPChannelBinding != 2 {
		t.Fatalf("LDAPChannelBinding = %d, want 2", *rs.LDAPChannelBinding)
	}
}

// TestParseGptTmpl_PrivilegeRightsSIDList confirms ParseGptTmpl routes
// [Privilege Rights] values through the same parseSIDList helper exercised
// above, end-to-end from raw file bytes.
func TestParseGptTmpl_PrivilegeRightsSIDList(t *testing.T) {
	content := "[Unicode]\n" +
		"Unicode=yes\n" +
		"[Version]\n" +
		"signature=\"$CHICAGO$\"\n" +
		"Revision=1\n" +
		"[Privilege Rights]\n" +
		"SeDebugPrivilege = *S-1-5-32-544\n"

	_, _, _, pr, _, _ := ParseGptTmpl([]byte(content))

	if pr == nil {
		t.Fatal("expected non-nil PrivilegeRights")
	}
	want := []string{"S-1-5-32-544"}
	if len(pr.SeDebugPrivilege) != len(want) || pr.SeDebugPrivilege[0] != want[0] {
		t.Fatalf("SeDebugPrivilege = %v, want %v", pr.SeDebugPrivilege, want)
	}
}

// TestParseGptTmpl_PrivilegeRightsTCBAndDelegation confirms ParseGptTmpl
// routes BOTH SeEnableDelegationPrivilege and SeTcbPrivilege through
// parseSIDList end to end from raw file bytes - the two rights CIS_USER_RIGHTS
// reads from PrivilegeRights (2.2.4 and 2.2.29).
func TestParseGptTmpl_PrivilegeRightsTCBAndDelegation(t *testing.T) {
	content := "[Unicode]\n" +
		"Unicode=yes\n" +
		"[Version]\n" +
		"signature=\"$CHICAGO$\"\n" +
		"Revision=1\n" +
		"[Privilege Rights]\n" +
		"SeEnableDelegationPrivilege = *S-1-5-32-544\n" +
		"SeTcbPrivilege = *S-1-5-21-1-2-3-4000\n"

	_, _, _, pr, _, _ := ParseGptTmpl([]byte(content))

	if pr == nil {
		t.Fatal("expected non-nil PrivilegeRights")
	}
	wantDelegation := []string{"S-1-5-32-544"}
	if len(pr.SeEnableDelegationPrivilege) != len(wantDelegation) || pr.SeEnableDelegationPrivilege[0] != wantDelegation[0] {
		t.Fatalf("SeEnableDelegationPrivilege = %v, want %v", pr.SeEnableDelegationPrivilege, wantDelegation)
	}
	wantTCB := []string{"S-1-5-21-1-2-3-4000"}
	if len(pr.SeTcbPrivilege) != len(wantTCB) || pr.SeTcbPrivilege[0] != wantTCB[0] {
		t.Fatalf("SeTcbPrivilege = %v, want %v", pr.SeTcbPrivilege, wantTCB)
	}
}

// TestParseGptTmpl_PrivilegeRightsDenyLogonRights_StarAndCommaLists confirms
// ParseGptTmpl routes all three SeDeny*LogonRight keys through parseSIDList,
// with a mix of a leading '*' and plain SIDs, and more than one SID per key.
func TestParseGptTmpl_PrivilegeRightsDenyLogonRights_StarAndCommaLists(t *testing.T) {
	content := "[Unicode]\n" +
		"Unicode=yes\n" +
		"[Version]\n" +
		"signature=\"$CHICAGO$\"\n" +
		"Revision=1\n" +
		"[Privilege Rights]\n" +
		"SeDenyNetworkLogonRight = *S-1-5-11,S-1-5-32-545\n" +
		"SeDenyInteractiveLogonRight = S-1-5-7\n" +
		"SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546,S-1-1-0\n"

	_, _, _, pr, _, _ := ParseGptTmpl([]byte(content))

	if pr == nil {
		t.Fatal("expected non-nil PrivilegeRights")
	}
	checkSIDList := func(name string, got, want []string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s = %v, want %v", name, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s[%d] = %q, want %q (full result %v)", name, i, got[i], want[i], got)
			}
		}
	}
	checkSIDList("SeDenyNetworkLogonRight", pr.SeDenyNetworkLogonRight, []string{"S-1-5-11", "S-1-5-32-545"})
	checkSIDList("SeDenyInteractiveLogonRight", pr.SeDenyInteractiveLogonRight, []string{"S-1-5-7"})
	checkSIDList("SeDenyRemoteInteractiveLogonRight", pr.SeDenyRemoteInteractiveLogonRight, []string{"S-1-5-32-546", "S-1-1-0"})
}

// TestParseGptTmpl_NoPrivilegeRightsSectionReturnsNilPrivilegeRights is the
// sibling absent-section case for [Privilege Rights]: a file with no such
// header must yield a nil PrivilegeRights, not a zero-value struct.
func TestParseGptTmpl_NoPrivilegeRightsSectionReturnsNilPrivilegeRights(t *testing.T) {
	content := "[Unicode]\n" +
		"Unicode=yes\n" +
		"[Version]\n" +
		"signature=\"$CHICAGO$\"\n" +
		"Revision=1\n"

	_, _, _, pr, _, _ := ParseGptTmpl([]byte(content))

	if pr != nil {
		t.Fatalf("expected nil PrivilegeRights when [Privilege Rights] section is absent, got %+v", pr)
	}
}

// TestParseRegistryValues_CredentialGuardEnabledVBS_DeviceGuardKey covers the
// :504 case (CredentialGuardEnabled, the VBS prerequisite for Credential
// Guard): a DeviceGuard\EnableVirtualizationBasedSecurity DWORD entry must
// populate CredentialGuardEnabled.
func TestParseRegistryValues_CredentialGuardEnabledVBS_DeviceGuardKey(t *testing.T) {
	sec := map[string]string{
		`MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity`: `4,1`,
	}

	rs := parseRegistryValues(sec)

	if rs == nil || rs.CredentialGuardEnabled == nil {
		t.Fatal("CredentialGuardEnabled not populated for the DeviceGuard\\EnableVirtualizationBasedSecurity entry")
	}
	if *rs.CredentialGuardEnabled != 1 {
		t.Fatalf("CredentialGuardEnabled = %d, want 1", *rs.CredentialGuardEnabled)
	}
}

// TestParseRegistryValues_CredentialGuardEnabledVBS_DeviceGuardKeyWithoutVBSNotSet
// guards the :504 key match: a DeviceGuard key that does not contain
// "enablevirtualizationbasedsecurity" must not populate CredentialGuardEnabled.
func TestParseRegistryValues_CredentialGuardEnabledVBS_DeviceGuardKeyWithoutVBSNotSet(t *testing.T) {
	sec := map[string]string{
		`MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures`: `4,1`,
	}

	rs := parseRegistryValues(sec)

	if rs != nil && rs.CredentialGuardEnabled != nil {
		t.Fatalf("CredentialGuardEnabled should not be populated from a DeviceGuard key without the VBS value name, got %d", *rs.CredentialGuardEnabled)
	}
}

// TestParseRegistryValues_CredentialGuardEnabledVBS_VBSValueOutsideDeviceGuardNotSet
// guards the :504 key match from the other side: an
// EnableVirtualizationBasedSecurity value name outside any DeviceGuard key
// must not populate CredentialGuardEnabled.
func TestParseRegistryValues_CredentialGuardEnabledVBS_VBSValueOutsideDeviceGuardNotSet(t *testing.T) {
	sec := map[string]string{
		`MACHINE\Software\Policies\Microsoft\Windows\SomeOtherFeature\EnableVirtualizationBasedSecurity`: `4,1`,
	}

	rs := parseRegistryValues(sec)

	if rs != nil && rs.CredentialGuardEnabled != nil {
		t.Fatalf("CredentialGuardEnabled should not be populated from an EnableVirtualizationBasedSecurity value outside DeviceGuard, got %d", *rs.CredentialGuardEnabled)
	}
}

// TestParseGptTmpl_EventAuditSection exercises ParseGptTmpl's [Event Audit]
// branch end-to-end from raw file bytes. Values are the DC_AUDIT_POLICY_INCOMPLETE
// detector's own 6 consumed keys. Kills a mutation of the section-name lookup
// (sections["Event Audit"] -> any other string): the "ok" check would then
// never match a real [Event Audit] header, leaving ea nil.
func TestParseGptTmpl_EventAuditSection(t *testing.T) {
	content := "[Unicode]\n" +
		"Unicode=yes\n" +
		"[Version]\n" +
		"signature=\"$CHICAGO$\"\n" +
		"Revision=1\n" +
		"[Event Audit]\n" +
		"AuditAccountLogon=3\n" +
		"AuditAccountManage=3\n" +
		"AuditDSAccess=2\n" +
		"AuditLogonEvents=3\n" +
		"AuditPolicyChange=3\n" +
		"AuditSystemEvents=3\n"

	_, _, ea, _, _, _ := ParseGptTmpl([]byte(content))

	if ea == nil {
		t.Fatal("expected non-nil EventAudit for a file containing [Event Audit]")
	}
	if ea.AuditAccountLogon != 3 {
		t.Fatalf("AuditAccountLogon = %d, want 3", ea.AuditAccountLogon)
	}
	if ea.AuditAccountManage != 3 {
		t.Fatalf("AuditAccountManage = %d, want 3", ea.AuditAccountManage)
	}
	if ea.AuditDSAccess != 2 {
		t.Fatalf("AuditDSAccess = %d, want 2", ea.AuditDSAccess)
	}
	if ea.AuditLogonEvents != 3 {
		t.Fatalf("AuditLogonEvents = %d, want 3", ea.AuditLogonEvents)
	}
	if ea.AuditPolicyChange != 3 {
		t.Fatalf("AuditPolicyChange = %d, want 3", ea.AuditPolicyChange)
	}
	if ea.AuditSystemEvents != 3 {
		t.Fatalf("AuditSystemEvents = %d, want 3", ea.AuditSystemEvents)
	}
}

// TestParseGptTmpl_NoEventAuditSectionReturnsNilEventAudit is the sibling
// case: a file with no [Event Audit] header at all must yield a nil
// EventAudit, not a zero-valued struct.
func TestParseGptTmpl_NoEventAuditSectionReturnsNilEventAudit(t *testing.T) {
	content := "[Unicode]\n" +
		"Unicode=yes\n" +
		"[Version]\n" +
		"signature=\"$CHICAGO$\"\n" +
		"Revision=1\n"

	_, _, ea, _, _, _ := ParseGptTmpl([]byte(content))

	if ea != nil {
		t.Fatalf("expected nil EventAudit when [Event Audit] section is absent, got %+v", ea)
	}
}
