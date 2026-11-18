package serviceaccounts

import (
	"testing"

	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestIsServiceAccount_SPNRecognized: a user with a Service Principal Name
// is a service account regardless of its naming.
func TestIsServiceAccount_SPNRecognized(t *testing.T) {
	u := types.User{SAMAccountName: "jdupont", ServicePrincipalNames: []string{"HTTP/jdupont.example.com"}}
	if !isServiceAccount(u) {
		t.Fatalf("isServiceAccount(%q with SPN) = false, want true", u.SAMAccountName)
	}
}

// TestIsServiceAccount_NeutralNameNotRecognized: a user with no SPN and a
// name matching none of the naming alternatives is not a service account.
func TestIsServiceAccount_NeutralNameNotRecognized(t *testing.T) {
	u := types.User{SAMAccountName: "jdupont"}
	if isServiceAccount(u) {
		t.Fatalf("isServiceAccount(%q, no SPN) = true, want false", u.SAMAccountName)
	}
}

// TestIsServiceAccount_NamingAlternatives exercises each of the 8 naming
// alternatives of serviceAccountPatterns in isServiceAccount, one at a time.
// Each name here satisfies exactly one alternative and carries no SPN, so a
// failure pinpoints which alternative broke.
func TestIsServiceAccount_NamingAlternatives(t *testing.T) {
	cases := []struct {
		name       string
		samAccount string
	}{
		{"prefix_svc_underscore_or_dash", "svc-report"},
		{"suffix_svc", "backup-svc"},
		{"prefix_sa_underscore_or_dash", "sa-backup"},
		{"suffix_sa", "backup-sa"},
		{"contains_service", "fileservice"},
		{"prefix_sql", "sqlagent01"},
		{"prefix_iis", "iisapppool"},
		{"prefix_app", "appworker"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := types.User{SAMAccountName: tc.samAccount}
			if !isServiceAccount(u) {
				t.Fatalf("isServiceAccount(%q) = false, want true", tc.samAccount)
			}
		})
	}
}
