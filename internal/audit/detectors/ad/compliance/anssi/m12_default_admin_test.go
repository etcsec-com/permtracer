package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestM12DefaultAdminNotRenamed_DescriptionHasNoEmptyFragment proves the
// catalog-vs-runtime text fix: the previous "...(\""+data.DomainInfo.AdminAccountName+"\")..."
// concatenation lost the dynamic account name entirely once cataloggen
// extracted the static literal for the catalog, leaving the empty fragment
// ("""") there - but the fix must not regress the runtime Description
// either, which has to keep reporting the actual account name.
func TestM12DefaultAdminNotRenamed_DescriptionHasNoEmptyFragment(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{AdminAccountName: "Administrator"},
	}
	findings := NewM12DefaultAdminNotRenamedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	desc := findings[0].Description
	if strings.Contains(desc, "(\"\")") {
		t.Errorf("description contains the empty-fragment pattern '(\"\")': %q", desc)
	}
	if !strings.Contains(desc, "\"Administrator\"") {
		t.Errorf("description dropped the dynamic account name: %q", desc)
	}
}

// TestM12_NilDomainInfo_NoFindingNoPanic covers the guard at line 35
// (`if data.DomainInfo == nil { return nil }`): without it, Detect
// dereferences a nil DomainInfo at line 38 and panics instead of returning
// no finding for an audit where domain info was not collected.
func TestM12_NilDomainInfo_NoFindingNoPanic(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: nil}
	findings := NewM12DefaultAdminNotRenamedDetector().Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding with nil DomainInfo, got %d", len(findings))
	}
}

// TestM12_DefaultNameVariants_AllTrigger exercises each of the 10 entries of
// defaultNames (:50-61), with the original Windows-reported casing, plus a
// whitespace-padded case covering strings.TrimSpace (:38). Each subtest only
// passes if its own variant (or TrimSpace) is actually applied by Detect, so
// removing any single entry from defaultNames, or removing TrimSpace, fails
// exactly the corresponding subtest.
func TestM12_DefaultNameVariants_AllTrigger(t *testing.T) {
	cases := []struct {
		name         string
		adminAccount string
	}{
		{"administrator", "Administrator"},
		{"administrateur", "Administrateur"},
		{"administrador", "Administrador"},
		{"administrators", "Administrators"},
		{"amministratore", "Amministratore"},
		{"rendszergazda", "Rendszergazda"},
		{"administraator", "Administraator"},
		{"järjestelmänvalvoja", "Järjestelmänvalvoja"},
		{"administratör", "Administratör"},
		{"administrator (built-in)", "Administrator (Built-in)"},
		{"padded whitespace", "  Administrator  "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{
				DomainInfo: &types.DomainInfo{AdminAccountName: tc.adminAccount},
			}
			findings := NewM12DefaultAdminNotRenamedDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("%q: expected 1 finding, got %d", tc.adminAccount, len(findings))
			}
			if findings[0].Count != 1 {
				t.Fatalf("%q: expected Count 1, got %d", tc.adminAccount, findings[0].Count)
			}
		})
	}
}
