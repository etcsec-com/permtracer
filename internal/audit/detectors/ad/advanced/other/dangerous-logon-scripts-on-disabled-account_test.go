package other

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestDangerousLogonScriptsOnDisabledAccount_ActiveAccountExcluded kills the
// inversion of the twin's state guard (dangerous-logon-scripts-on-disabled-account.go:
// `if !u.Disabled { continue }`): an active account with a UNC scriptPath
// must not be counted here - it belongs to the active detector instead.
func TestDangerousLogonScriptsOnDisabledAccount_ActiveAccountExcluded(t *testing.T) {
	users := []types.User{
		{DN: "CN=active,OU=Users,DC=example,DC=com", Disabled: false, ScriptPath: `\\fileserver01\netlogon\login.bat`},
		{DN: "CN=disabled,OU=Users,DC=example,DC=com", Disabled: true, ScriptPath: `\\fileserver01\netlogon\login.bat`},
	}
	data := &audit.DetectorData{IncludeDetails: true, Users: users}

	findings := NewDangerousLogonScriptsOnDisabledAccountDetector().Detect(context.Background(), data)
	f := findings[0]

	if f.Count != 1 {
		t.Fatalf("expected Count=1 (active account excluded), got %d", f.Count)
	}
	if len(f.AffectedEntities) != 1 || f.AffectedEntities[0].DN != users[1].DN {
		t.Fatalf("expected only the disabled account flagged, got %+v", f.AffectedEntities)
	}
}

// TestDangerousLogonScriptsOnDisabledAccount_PatternSubterms exercises every
// sub-term of the motif, mirrored from the active detector, on disabled
// accounts only.
func TestDangerousLogonScriptsOnDisabledAccount_PatternSubterms(t *testing.T) {
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
				{DN: "CN=target,OU=Users,DC=example,DC=com", Disabled: true, ScriptPath: tc.scriptPath},
			}
			data := &audit.DetectorData{IncludeDetails: true, Users: users}

			findings := NewDangerousLogonScriptsOnDisabledAccountDetector().Detect(context.Background(), data)
			if findings[0].Count != tc.wantCount {
				t.Fatalf("scriptPath=%q: Count = %d, want %d", tc.scriptPath, findings[0].Count, tc.wantCount)
			}
		})
	}
}

// TestDangerousLogonScriptsOnDisabledAccount_SeverityIsLow kills a change of
// Severity from types.SeverityLow to types.SeverityMedium: the attribute
// alone confers no domain-level privilege and no exposed secret (D1/D2
// grid), per SPLIT.md.
func TestDangerousLogonScriptsOnDisabledAccount_SeverityIsLow(t *testing.T) {
	users := []types.User{
		{DN: "CN=disabled,OU=Users,DC=example,DC=com", Disabled: true, ScriptPath: `\\fileserver01\netlogon\login.bat`},
	}
	data := &audit.DetectorData{IncludeDetails: true, Users: users}

	findings := NewDangerousLogonScriptsOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Severity != types.SeverityLow {
		t.Fatalf("Severity = %v, want %v", findings[0].Severity, types.SeverityLow)
	}
}

// TestDangerousLogonScriptsOnDisabledAccount_IncludeDetailsFalse_NoAffectedEntities
// kills a reduction of `data.IncludeDetails && len(affected) > 0` to
// `len(affected) > 0`.
func TestDangerousLogonScriptsOnDisabledAccount_IncludeDetailsFalse_NoAffectedEntities(t *testing.T) {
	users := []types.User{
		{DN: "CN=disabled,OU=Users,DC=example,DC=com", Disabled: true, ScriptPath: `\\fileserver01\netlogon\login.bat`},
	}
	data := &audit.DetectorData{IncludeDetails: false, Users: users}

	findings := NewDangerousLogonScriptsOnDisabledAccountDetector().Detect(context.Background(), data)
	f := findings[0]

	if f.Count != 1 {
		t.Fatalf("expected Count=1, got %d", f.Count)
	}
	if f.AffectedEntities != nil {
		t.Fatalf("expected AffectedEntities=nil when IncludeDetails=false, got %+v", f.AffectedEntities)
	}
}

// TestDangerousLogonScriptsOnDisabledAccount_IncludeDetailsTrue_NoAffectedAccounts_NilEntities
// kills a reduction of `data.IncludeDetails && len(affected) > 0` to
// `data.IncludeDetails` alone.
func TestDangerousLogonScriptsOnDisabledAccount_IncludeDetailsTrue_NoAffectedAccounts_NilEntities(t *testing.T) {
	users := []types.User{
		{DN: "CN=disabled,OU=Users,DC=example,DC=com", Disabled: true, ScriptPath: "login.bat"},
	}
	data := &audit.DetectorData{IncludeDetails: true, Users: users}

	findings := NewDangerousLogonScriptsOnDisabledAccountDetector().Detect(context.Background(), data)
	f := findings[0]

	if f.Count != 0 {
		t.Fatalf("expected Count=0, got %d", f.Count)
	}
	if f.AffectedEntities != nil {
		t.Fatalf("expected AffectedEntities=nil when no account matched, got %+v", f.AffectedEntities)
	}
}
