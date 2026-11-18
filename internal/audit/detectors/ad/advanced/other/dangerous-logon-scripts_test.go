package other

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestDangerousLogonScripts_FlagsNetworkPathWithoutClaimingACLCheck proves two
// things about DANGEROUS_LOGON_SCRIPTS:
//
//  1. The path-substring heuristic actually flags a UNC-style scriptPath and
//     leaves a relative (NETLOGON-resolved) scriptPath alone - the detection
//     logic itself works as intended.
//  2. The finding's description no longer claims to detect "weak ACLs". The
//     code has never read any file/share/NTFS ACL (it only inspects the
//     scriptPath string), so a description promising ACL analysis was false.
//     This assertion fails against the pre-fix description ("Logon scripts
//     with weak ACLs can be modified by attackers...") and passes once the
//     description honestly describes a path-only heuristic.
func TestDangerousLogonScripts_FlagsNetworkPathWithoutClaimingACLCheck(t *testing.T) {
	users := []types.User{
		{DN: "CN=alice,OU=Users,DC=example,DC=com", ScriptPath: `\\fileserver01\netlogon\login.bat`},
		{DN: "CN=bob,OU=Users,DC=example,DC=com", ScriptPath: "login.bat"},
		{DN: "CN=carol,OU=Users,DC=example,DC=com", ScriptPath: ""},
	}
	data := &audit.DetectorData{IncludeDetails: true, Users: users}

	findings := NewDangerousLogonScriptsDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]

	if f.Count != 1 {
		t.Fatalf("expected Count=1 (only alice's UNC-path script), got %d", f.Count)
	}
	if len(f.AffectedEntities) != 1 || f.AffectedEntities[0].DN != users[0].DN {
		t.Fatalf("expected only alice flagged, got %+v", f.AffectedEntities)
	}

	descLower := strings.ToLower(f.Description)
	if strings.Contains(descLower, "weak acl") {
		t.Fatalf("description still claims to detect weak ACLs, but the code never reads any ACL: %q", f.Description)
	}
	if !strings.Contains(descLower, "does not read") && !strings.Contains(descLower, "not read the file") {
		t.Fatalf("description does not honestly disclose that no ACL is read: %q", f.Description)
	}
}

// TestDangerousLogonScripts_DisabledAccountExcluded kills the removal of the
// state guard (dangerous-logon-scripts.go: `if u.Disabled { continue }`): a
// disabled account with the same UNC scriptPath as an active account must
// not be counted by the active detector - it belongs to the twin,
// DANGEROUS_LOGON_SCRIPTS_ON_DISABLED_ACCOUNT, instead.
func TestDangerousLogonScripts_DisabledAccountExcluded(t *testing.T) {
	users := []types.User{
		{DN: "CN=active,OU=Users,DC=example,DC=com", Disabled: false, ScriptPath: `\\fileserver01\netlogon\login.bat`},
		{DN: "CN=disabled,OU=Users,DC=example,DC=com", Disabled: true, ScriptPath: `\\fileserver01\netlogon\login.bat`},
	}
	data := &audit.DetectorData{IncludeDetails: true, Users: users}

	findings := NewDangerousLogonScriptsDetector().Detect(context.Background(), data)
	f := findings[0]

	if f.Count != 1 {
		t.Fatalf("expected Count=1 (disabled account excluded), got %d", f.Count)
	}
	if len(f.AffectedEntities) != 1 || f.AffectedEntities[0].DN != users[0].DN {
		t.Fatalf("expected only the active account flagged, got %+v", f.AffectedEntities)
	}
}

// TestDangerousLogonScripts_PatternSubterms exercises every sub-term of the
// motif at dangerous-logon-scripts.go:52
// (strings.Contains(u.ScriptPath, "\\\\") || strings.HasPrefix(u.ScriptPath, "//"))
// on active accounts only.
func TestDangerousLogonScripts_PatternSubterms(t *testing.T) {
	tests := []struct {
		name       string
		scriptPath string
		wantCount  int
	}{
		{"leading_backslash_counted", `\\fileserver01\netlogon\login.bat`, 1},
		{"backslash_mid_string_counted", `scripts\\sub\\login.bat`, 1},
		{"double_slash_prefix_counted", "//fileserver01/netlogon/login.bat", 1},
		{"local_path_not_counted", "login.bat", 0},
		{"empty_scriptpath_not_counted", "", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			users := []types.User{
				{DN: "CN=target,OU=Users,DC=example,DC=com", Disabled: false, ScriptPath: tc.scriptPath},
			}
			data := &audit.DetectorData{IncludeDetails: true, Users: users}

			findings := NewDangerousLogonScriptsDetector().Detect(context.Background(), data)
			if findings[0].Count != tc.wantCount {
				t.Fatalf("scriptPath=%q: Count = %d, want %d", tc.scriptPath, findings[0].Count, tc.wantCount)
			}
		})
	}
}

// TestDangerousLogonScripts_IncludeDetailsFalse_NoAffectedEntities kills a
// reduction of `data.IncludeDetails && len(affected) > 0` to
// `len(affected) > 0` at dangerous-logon-scripts.go: AffectedEntities must
// stay nil when the caller did not ask for details, even though an affected
// account exists.
func TestDangerousLogonScripts_IncludeDetailsFalse_NoAffectedEntities(t *testing.T) {
	users := []types.User{
		{DN: "CN=alice,OU=Users,DC=example,DC=com", ScriptPath: `\\fileserver01\netlogon\login.bat`},
	}
	data := &audit.DetectorData{IncludeDetails: false, Users: users}

	findings := NewDangerousLogonScriptsDetector().Detect(context.Background(), data)
	f := findings[0]

	if f.Count != 1 {
		t.Fatalf("expected Count=1, got %d", f.Count)
	}
	if f.AffectedEntities != nil {
		t.Fatalf("expected AffectedEntities=nil when IncludeDetails=false, got %+v", f.AffectedEntities)
	}
}

// TestDangerousLogonScripts_SeverityIsMedium kills a reduction of
// `types.SeverityMedium` to `types.SeverityLow` on the active detector: an
// active account flagged by the network-path motif must stay Medium (the
// twin, DANGEROUS_LOGON_SCRIPTS_ON_DISABLED_ACCOUNT, has its own severity
// test and is the only case allowed to report Low).
func TestDangerousLogonScripts_SeverityIsMedium(t *testing.T) {
	users := []types.User{
		{DN: "CN=alice,OU=Users,DC=example,DC=com", Disabled: false, ScriptPath: `\\fileserver01\netlogon\login.bat`},
	}
	data := &audit.DetectorData{IncludeDetails: true, Users: users}

	findings := NewDangerousLogonScriptsDetector().Detect(context.Background(), data)
	f := findings[0]

	if f.Severity != types.SeverityMedium {
		t.Fatalf("expected Severity=Medium for an active account, got %v", f.Severity)
	}
}

// TestDangerousLogonScripts_IncludeDetailsTrue_NoAffectedAccounts_NilEntities
// kills a reduction of `data.IncludeDetails && len(affected) > 0` to
// `data.IncludeDetails` alone: AffectedEntities must stay nil when
// IncludeDetails is true but no account matched the motif.
func TestDangerousLogonScripts_IncludeDetailsTrue_NoAffectedAccounts_NilEntities(t *testing.T) {
	users := []types.User{
		{DN: "CN=bob,OU=Users,DC=example,DC=com", ScriptPath: "login.bat"},
	}
	data := &audit.DetectorData{IncludeDetails: true, Users: users}

	findings := NewDangerousLogonScriptsDetector().Detect(context.Background(), data)
	f := findings[0]

	if f.Count != 0 {
		t.Fatalf("expected Count=0, got %d", f.Count)
	}
	if f.AffectedEntities != nil {
		t.Fatalf("expected AffectedEntities=nil when no account matched, got %+v", f.AffectedEntities)
	}
}
