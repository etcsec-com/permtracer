package serviceaccounts

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestNaming_HyphenPrefixFlagged pins the fix: Microsoft's own documented
// convention ("Secure user-based service accounts in Active Directory",
// Microsoft Learn) is the hyphenated "svc-" prefix, exemplified as
// "svc-HRDataConnector". The old pattern set only matched the underscore
// form ("svc_") and missed this one.
func TestNaming_HyphenPrefixFlagged(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "svc-HRDataConnector"},
		},
	}

	findings := NewNamingDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: \"svc-HRDataConnector\" matches Microsoft's documented naming convention", findings[0].Count)
	}
}

// TestNaming_DotVariantFlagged pins the dotted-prefix gap seen on the lab
// (svc.* accounts).
func TestNaming_DotVariantFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "svc.backup"},
		},
	}

	findings := NewNamingDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: \"svc.backup\" is a naming variant this detector must catch", findings[0].Count)
	}
}

// TestNaming_UnrelatedAccountNotFlagged guards against over-matching.
func TestNaming_UnrelatedAccountNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "jdupont"},
		},
	}

	findings := NewNamingDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: an ordinary username must not match", findings[0].Count)
	}
}

// TestNaming_DisabledAccountNotFlagged pins the Disabled guard: a disabled
// account matching a naming pattern must not be reported here - that case
// belongs to the _ON_DISABLED_ACCOUNT variant, not this detector.
func TestNaming_DisabledAccountNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "svc_disabledmutationcheck", Disabled: true},
		},
	}

	findings := NewNamingDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a disabled account matching a naming pattern must not be flagged", findings[0].Count)
	}
}

// TestNaming_SPNAccountNotFlagged pins the SPN exclusion: an active account
// matching a naming pattern but carrying a SPN is covered by
// SERVICE_ACCOUNT_WITH_SPN instead, not here.
func TestNaming_SPNAccountNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{
				SAMAccountName:        "svc_spnmutationcheck",
				ServicePrincipalNames: []string{"HTTP/spnmutationcheck.example.org"},
			},
		},
	}

	findings := NewNamingDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: an account with a SPN must not be flagged (covered by SERVICE_ACCOUNT_WITH_SPN)", findings[0].Count)
	}
}

// TestNaming_SuffixSvcVariantsFlagged pins the "[_.-]svc$" suffix pattern:
// each account name here matches only that pattern, none of the others.
func TestNaming_SuffixSvcVariantsFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "backup_svc"},
			{SAMAccountName: "backup.svc"},
			{SAMAccountName: "backup-svc"},
		},
	}

	findings := NewNamingDetector().Detect(context.Background(), data)
	if findings[0].Count != 3 {
		t.Fatalf("Count = %d, want 3: \"backup_svc\", \"backup.svc\" and \"backup-svc\" all match the \"[_.-]svc$\" suffix pattern", findings[0].Count)
	}
}

// TestNaming_ServiceKeywordFlagged pins the bare "service" pattern: the name
// here contains lowercase "service" in the middle and matches no other
// pattern. Lowercase is deliberate so this test isolates the pattern's
// presence from its "(?i)" case-insensitivity flag, which is pinned
// separately by TestNaming_ServiceKeywordCaseInsensitive.
func TestNaming_ServiceKeywordFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "webservicegateway"},
		},
	}

	findings := NewNamingDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: \"webservicegateway\" contains \"service\" and must match the \"service\" pattern", findings[0].Count)
	}
}

// TestNaming_PrefixSaFlagged pins the "^sa_" prefix pattern: the name here
// matches only that pattern, none of the others.
func TestNaming_PrefixSaFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "sa_backupjob"},
		},
	}

	findings := NewNamingDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: \"sa_backupjob\" matches the \"^sa_\" prefix pattern", findings[0].Count)
	}
}

// TestNaming_SuffixSaFlagged pins the "_sa$" suffix pattern: the name here
// matches only that pattern, none of the others.
func TestNaming_SuffixSaFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "backupjob_sa"},
		},
	}

	findings := NewNamingDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: \"backupjob_sa\" matches the \"_sa$\" suffix pattern", findings[0].Count)
	}
}

// TestNaming_ServiceKeywordCaseInsensitive pins the "(?i)" case-insensitivity
// flag on the "service" pattern: the name here contains "SERVICE" in
// uppercase only and matches no other pattern.
func TestNaming_ServiceKeywordCaseInsensitive(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "SERVICEACCOUNT1"},
		},
	}

	findings := NewNamingDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: \"SERVICEACCOUNT1\" must match the case-insensitive \"service\" pattern", findings[0].Count)
	}
}

// TestNaming_SaNeighborNotFlagged guards against over-matching on
// near-misses of the "sa_"/"_sa" patterns: neither name below carries the
// required underscore, so neither should match any pattern.
func TestNaming_SaNeighborNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "sax1"},
			{SAMAccountName: "xsa"},
		},
	}

	findings := NewNamingDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: \"sax1\" and \"xsa\" are near-misses of the sa_/_sa patterns and must not match", findings[0].Count)
	}
}
