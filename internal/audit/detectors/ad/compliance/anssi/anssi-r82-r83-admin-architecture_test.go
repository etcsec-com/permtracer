package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// --- R82/R83 relabeling ---

func denyRightsPolicy(sids ...string) map[string]*audit.GPOPolicy {
	return map[string]*audit.GPOPolicy{
		"policy-1": {
			PrivilegeRights: &audit.PrivilegeRights{
				SeDenyNetworkLogonRight:           sids,
				SeDenyInteractiveLogonRight:       sids,
				SeDenyRemoteInteractiveLogonRight: sids,
			},
		},
	}
}

func TestR82R83AdminArchitecture_Detect(t *testing.T) {
	cases := []struct {
		name     string
		policies map[string]*audit.GPOPolicy
		wantFlag bool
	}{
		{"deny rights configured for Authenticated Users -> clean", denyRightsPolicy("S-1-5-11"), false},
		{"no GPO configures deny rights -> flagged", nil, true},
		{"deny rights configured for an unrelated SID only -> flagged", denyRightsPolicy("S-1-5-32-544"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{GPOPolicies: tc.policies}
			d := NewR82R83AdminArchitectureDetector()
			findings := d.Detect(context.Background(), data)
			flagged := len(findings) == 1 && findings[0].Count > 0
			if flagged != tc.wantFlag {
				t.Errorf("flagged = %v, want %v (findings=%+v)", flagged, tc.wantFlag, findings)
			}
		})
	}
}

// this finding used to claim it measures ANSSI R82 + R83. Both are
// about restricting Tier 0's OUTBOUND connections to less-trusted zones
// (the opposite direction of a deny-inbound-logon GPO check), and the
// guide's own footnote on R83 says deny-logon GPO settings alone don't
// satisfy it. The finding must no longer attribute this check to R82/R83.
func TestR82R83AdminArchitecture_DoesNotClaimANSSIR82R83(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: nil}
	d := NewR82R83AdminArchitectureDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count == 0 {
		t.Fatalf("expected a flagged finding, got %+v", findings)
	}
	title, desc := findings[0].Title, findings[0].Description
	if strings.Contains(title, "R82") || strings.Contains(title, "R83") {
		t.Errorf("title still attributes this check to R82/R83: %q", title)
	}
	if !strings.Contains(desc, "NOT a measurement of ANSSI R82 or R83") {
		t.Errorf("description should explicitly disclaim R82/R83 attribution, got %q", desc)
	}
}

// TestR82R83AdminArchitecture_DescriptionHasNoEmptyFragment proves the
// catalog-vs-runtime text fix: the previous "...such SIDs: "+
// strings.Join(missing, "; ")+"." concatenation lost the dynamic missing-SIDs
// list entirely once cataloggen extracted the static literal for the catalog,
// leaving "SIDs: ." there - but the fix must not regress the runtime
// Description either, which has to keep reporting the actual missing rights.
func TestR82R83AdminArchitecture_DescriptionHasNoEmptyFragment(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: nil}
	d := NewR82R83AdminArchitectureDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count == 0 {
		t.Fatalf("expected a flagged finding, got %+v", findings)
	}
	desc := findings[0].Description
	if strings.Contains(desc, "SIDs: .") {
		t.Errorf("description contains the empty-fragment pattern 'SIDs: .': %q", desc)
	}
	if !strings.Contains(desc, "SeDenyNetworkLogonRight") {
		t.Errorf("description dropped the dynamic missing-rights list: %q", desc)
	}
}

// --- Branches of the deny-logon control previously left untested: the
// -513 suffix match, rights split across several GPOs, a single right set
// alone, each commonNonTier0SIDs entry, the nil guards, and Severity/Count
// literals. ---

// TestR82R83AdminArchitecture_Suffix513MatchesAcrossAllDenyRights proves the
// "-513" (Domain Users) suffix match: a fictitious domain SID ending in -513
// on all three deny rights is treated as a non-Tier-0 SID and satisfies the
// control, detector.go line 98 (strings.HasSuffix(clean, "-513")).
func TestR82R83AdminArchitecture_Suffix513MatchesAcrossAllDenyRights(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: denyRightsPolicy("S-1-5-21-1111111111-2222222222-3333333333-513")}
	d := NewR82R83AdminArchitectureDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding for a -513 suffixed SID on all three deny rights, got %+v", findings)
	}
}

// TestR82R83AdminArchitecture_Suffix512DoesNotMatch is the sibling negative
// case: a SID with the same domain prefix but RID 512 (Domain Admins, not
// Domain Users) must NOT match the -513 suffix check.
func TestR82R83AdminArchitecture_Suffix512DoesNotMatch(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: denyRightsPolicy("S-1-5-21-1111111111-2222222222-3333333333-512")}
	d := NewR82R83AdminArchitectureDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected a flagged finding for a -512 suffixed SID, got %+v", findings)
	}
}

// TestR82R83AdminArchitecture_RightsSplitAcrossTwoGPOs proves denyNetwork and
// denyRemote accumulate across the data.GPOPolicies loop (detector.go lines
// 66-78): one GPO setting the network deny and a SEPARATE GPO setting the
// remote deny must together satisfy the control.
func TestR82R83AdminArchitecture_RightsSplitAcrossTwoGPOs(t *testing.T) {
	policies := map[string]*audit.GPOPolicy{
		"policy-network-deny": {PrivilegeRights: &audit.PrivilegeRights{
			SeDenyNetworkLogonRight: []string{"S-1-5-11"},
		}},
		"policy-remote-deny": {PrivilegeRights: &audit.PrivilegeRights{
			SeDenyRemoteInteractiveLogonRight: []string{"S-1-5-11"},
		}},
	}
	data := &audit.DetectorData{GPOPolicies: policies}
	d := NewR82R83AdminArchitectureDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding when network deny and remote deny are configured in two separate GPOs, got %+v", findings)
	}
}

// TestR82R83AdminArchitecture_OnlyNetworkDenySet_MissingRemoteOnly proves the
// "missing" list only names the right that is actually absent: with
// SeDenyNetworkLogonRight set alone, only SeDenyRemoteInteractiveLogonRight
// must be reported missing.
func TestR82R83AdminArchitecture_OnlyNetworkDenySet_MissingRemoteOnly(t *testing.T) {
	policies := map[string]*audit.GPOPolicy{
		"policy-1": {PrivilegeRights: &audit.PrivilegeRights{
			SeDenyNetworkLogonRight: []string{"S-1-5-11"},
		}},
	}
	data := &audit.DetectorData{GPOPolicies: policies}
	d := NewR82R83AdminArchitectureDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected a flagged finding when only network deny is set, got %+v", findings)
	}
	desc := findings[0].Description
	if !strings.Contains(desc, "SeDenyRemoteInteractiveLogonRight") {
		t.Errorf("description should list SeDenyRemoteInteractiveLogonRight as missing, got %q", desc)
	}
	if strings.Contains(desc, "SeDenyNetworkLogonRight / SeDenyInteractiveLogonRight") {
		t.Errorf("description should NOT list the network/interactive pair as missing since network deny is set, got %q", desc)
	}
}

// TestR82R83AdminArchitecture_OnlyRemoteDenySet_MissingNetworkOnly is the
// symmetric case: with only SeDenyRemoteInteractiveLogonRight set, only the
// "SeDenyNetworkLogonRight / SeDenyInteractiveLogonRight" label must appear.
func TestR82R83AdminArchitecture_OnlyRemoteDenySet_MissingNetworkOnly(t *testing.T) {
	policies := map[string]*audit.GPOPolicy{
		"policy-1": {PrivilegeRights: &audit.PrivilegeRights{
			SeDenyRemoteInteractiveLogonRight: []string{"S-1-5-11"},
		}},
	}
	data := &audit.DetectorData{GPOPolicies: policies}
	d := NewR82R83AdminArchitectureDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected a flagged finding when only remote deny is set, got %+v", findings)
	}
	desc := findings[0].Description
	if !strings.Contains(desc, "SeDenyNetworkLogonRight / SeDenyInteractiveLogonRight") {
		t.Errorf("description should list the network/interactive pair as missing, got %q", desc)
	}
	if strings.Contains(desc, "SeDenyRemoteInteractiveLogonRight") {
		t.Errorf("description should NOT list SeDenyRemoteInteractiveLogonRight as missing since remote deny is set, got %q", desc)
	}
}

// TestR82R83AdminArchitecture_InteractiveAloneSatisfiesNetworkDeny covers the
// "||" sub-term on detector.go line 72: SeDenyInteractiveLogonRight alone
// (no SeDenyNetworkLogonRight at all) must satisfy denyNetwork.
func TestR82R83AdminArchitecture_InteractiveAloneSatisfiesNetworkDeny(t *testing.T) {
	policies := map[string]*audit.GPOPolicy{
		"policy-1": {PrivilegeRights: &audit.PrivilegeRights{
			SeDenyInteractiveLogonRight: []string{"S-1-5-11"},
		}},
	}
	data := &audit.DetectorData{GPOPolicies: policies}
	d := NewR82R83AdminArchitectureDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected a flagged finding when only interactive deny is set, got %+v", findings)
	}
	desc := findings[0].Description
	if strings.Contains(desc, "SeDenyNetworkLogonRight / SeDenyInteractiveLogonRight") {
		t.Errorf("SeDenyInteractiveLogonRight alone should satisfy the network/interactive OR term, got %q", desc)
	}
	if !strings.Contains(desc, "SeDenyRemoteInteractiveLogonRight") {
		t.Errorf("remote deny should still be reported missing, got %q", desc)
	}
}

// TestR82R83AdminArchitecture_EachCommonNonTier0SID proves each literal entry
// of commonNonTier0SIDs (except the -513 template, covered by the suffix
// tests above) individually satisfies the control when it is the only SID
// present.
func TestR82R83AdminArchitecture_EachCommonNonTier0SID(t *testing.T) {
	cases := []string{
		"S-1-5-7",
		"S-1-1-0",
		"S-1-5-11",
		"S-1-5-32-545",
		"S-1-5-32-546",
	}
	for _, sid := range cases {
		t.Run(sid, func(t *testing.T) {
			data := &audit.DetectorData{GPOPolicies: denyRightsPolicy(sid)}
			d := NewR82R83AdminArchitectureDetector()
			findings := d.Detect(context.Background(), data)
			if len(findings) != 0 {
				t.Errorf("SID %s is in commonNonTier0SIDs, expected no finding, got %+v", sid, findings)
			}
		})
	}
}

// TestR82R83AdminArchitecture_SIDNotInListStillFlagged is the negative control
// for the table above: a well-known SID that is NOT in commonNonTier0SIDs
// (BUILTIN\Administrators, S-1-5-32-544) must still leave the control
// unsatisfied.
func TestR82R83AdminArchitecture_SIDNotInListStillFlagged(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: denyRightsPolicy("S-1-5-32-544")}
	d := NewR82R83AdminArchitectureDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("S-1-5-32-544 is not in commonNonTier0SIDs, expected a flagged finding, got %+v", findings)
	}
}

// TestR82R83AdminArchitecture_SIDWithWhitespaceAndStarPrefixStillMatches
// proves containsAnyNonTier0SID trims surrounding whitespace and a leading
// '*' before comparing (detector.go line 96).
func TestR82R83AdminArchitecture_SIDWithWhitespaceAndStarPrefixStillMatches(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: denyRightsPolicy("  *S-1-5-11  ")}
	d := NewR82R83AdminArchitectureDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected trimming of whitespace and '*' prefix before matching, got %+v", findings)
	}
}

// TestR82R83AdminArchitecture_SIDCaseInsensitiveMatch proves the comparison
// against commonNonTier0SIDs is case-insensitive (strings.EqualFold,
// detector.go line 102).
func TestR82R83AdminArchitecture_SIDCaseInsensitiveMatch(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: denyRightsPolicy("s-1-5-7")}
	d := NewR82R83AdminArchitectureDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected case-insensitive SID match, got %+v", findings)
	}
}

// TestR82R83AdminArchitecture_MatchFoundAmongMultipleSIDs proves
// containsAnyNonTier0SID scans the WHOLE sids slice, not just its first
// element: the matching SID here is neither first nor last in the list.
func TestR82R83AdminArchitecture_MatchFoundAmongMultipleSIDs(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: denyRightsPolicy("S-1-5-32-544", "S-1-5-11", "S-1-5-32-547")}
	d := NewR82R83AdminArchitectureDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected the match on S-1-5-11 among several SIDs to be found, got %+v", findings)
	}
}

// TestR82R83AdminArchitecture_NilGPOEntryInMapDoesNotPanic proves the
// "p == nil" half of the detector.go line 67 guard: a nil value for a GUID
// key in data.GPOPolicies must be skipped without panicking.
func TestR82R83AdminArchitecture_NilGPOEntryInMapDoesNotPanic(t *testing.T) {
	policies := map[string]*audit.GPOPolicy{"policy-1": nil}
	data := &audit.DetectorData{GPOPolicies: policies}
	d := NewR82R83AdminArchitectureDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected a flagged finding (nil GPO entry contributes nothing), got %+v", findings)
	}
}

// TestR82R83AdminArchitecture_NilPrivilegeRightsDoesNotPanic proves the
// "p.PrivilegeRights == nil" half of the detector.go line 67 guard: a GPO
// with no PrivilegeRights section must be skipped without panicking.
func TestR82R83AdminArchitecture_NilPrivilegeRightsDoesNotPanic(t *testing.T) {
	policies := map[string]*audit.GPOPolicy{"policy-1": {PrivilegeRights: nil}}
	data := &audit.DetectorData{GPOPolicies: policies}
	d := NewR82R83AdminArchitectureDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected a flagged finding (nil PrivilegeRights contributes nothing), got %+v", findings)
	}
}

// TestR82R83AdminArchitecture_SeverityHighAndCountOne proves the finding's
// Severity and Count literals (detector.go line 91: types.SeverityHigh, 1).
func TestR82R83AdminArchitecture_SeverityHighAndCountOne(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: nil}
	d := NewR82R83AdminArchitectureDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly one finding, got %+v", findings)
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Errorf("Severity = %v, want %v", findings[0].Severity, types.SeverityHigh)
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1", findings[0].Count)
	}
}
