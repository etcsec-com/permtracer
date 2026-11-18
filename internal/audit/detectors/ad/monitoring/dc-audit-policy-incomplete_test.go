package monitoring

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/detectors/ad/compliance/auditpolicy"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func TestDCAuditPolicyIncomplete_AdvancedAuditPolicyPrecedence(t *testing.T) {
	d := NewDCAuditPolicyIncompleteDetector()

	t.Run("legacy Event Audit shows every category unaudited but audit.csv configures every subcategory correctly: not flagged", func(t *testing.T) {
		data := &audit.DetectorData{
			GPOPolicies: map[string]*audit.GPOPolicy{
				"GUID": {
					EventAudit: &audit.EventAudit{}, // all zero = "nothing audited" at legacy level
					AdvancedAudit: map[string]int{
						auditpolicy.CredentialValidation:   3,
						auditpolicy.UserAccountManagement:  3,
						auditpolicy.Logon:                  3,
						auditpolicy.AuditPolicyChange:      3,
						auditpolicy.SecurityStateChange:    3,
						auditpolicy.DirectoryServiceAccess: 2,
					},
				},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("expected count=0 (subcategories win over legacy for every category), got %d: %v", findings[0].Count, findings[0].Details)
		}
	})

	t.Run("legacy shows fully audited but one subcategory is insufficient in audit.csv: that one category is flagged", func(t *testing.T) {
		data := &audit.DetectorData{
			GPOPolicies: map[string]*audit.GPOPolicy{
				"GUID": {
					EventAudit: &audit.EventAudit{
						AuditAccountLogon:  3,
						AuditAccountManage: 3,
						AuditLogonEvents:   3,
						AuditPolicyChange:  3,
						AuditSystemEvents:  3,
						AuditDSAccess:      3,
					},
					AdvancedAudit: map[string]int{
						auditpolicy.AuditPolicyChange: 0,
					},
				},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("expected count=1 (only Policy Change subcategory is insufficient), got %d: %v", findings[0].Count, findings[0].Details)
		}
	})

	t.Run("no audit policy anywhere: not flagged as incomplete, finding is honest instead of categorical", func(t *testing.T) {
		data := &audit.DetectorData{
			GPOPolicies: map[string]*audit.GPOPolicy{"GUID": {}},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("expected count=0 (no GPO evidence is not proof of an incomplete policy), got %d", findings[0].Count)
		}
		if findings[0].Details == nil {
			t.Fatal("expected honest details explaining nothing is configured via GPO, got nil")
		}
	})
}

// TestDCAuditPolicyIncomplete_ThresholdsPerCategory kills a lowered minimum
// (3->2, 3->1 or 2->1) for EACH of the 6 categories individually, not just
// Account Logon. Each category is isolated via the authoritative AdvancedAudit
// map, keyed by its own subcategory GUID, with no [Event Audit] section at
// all: every OTHER category then has ok=false (not measured, never counted as
// an issue - see advancedAuditLevel/auditpolicy.Level), so Count reflects only
// the category under test.
//
// just_below_minimum (value = minimum-1) must produce an issue under the real
// minimum; if a mutation lowers the minimum to <= that value, the issue
// disappears and Count drops to 0, failing the test. at_minimum (value =
// minimum) must NOT produce an issue; if a mutation raises the minimum above
// it, an issue appears and Count rises to 1, failing the test.
func TestDCAuditPolicyIncomplete_ThresholdsPerCategory(t *testing.T) {
	d := NewDCAuditPolicyIncompleteDetector()

	categories := []struct {
		name    string
		guid    string
		minimum int
	}{
		{"Account Logon", auditpolicy.CredentialValidation, 3},
		{"Account Management", auditpolicy.UserAccountManagement, 3},
		{"Logon Events", auditpolicy.Logon, 3},
		{"Policy Change", auditpolicy.AuditPolicyChange, 3},
		{"System Events", auditpolicy.SecurityStateChange, 3},
		{"Directory Service Access", auditpolicy.DirectoryServiceAccess, 2},
	}

	for _, c := range categories {
		c := c
		t.Run(c.name+"/just_below_minimum_is_flagged", func(t *testing.T) {
			data := &audit.DetectorData{
				GPOPolicies: map[string]*audit.GPOPolicy{
					"GUID": {AdvancedAudit: map[string]int{c.guid: c.minimum - 1}},
				},
			}
			findings := d.Detect(context.Background(), data)
			if findings[0].Count != 1 {
				t.Fatalf("%s at value=%d (minimum-1): expected Count=1, got %d: %v", c.name, c.minimum-1, findings[0].Count, findings[0].Details)
			}
		})
		t.Run(c.name+"/at_minimum_is_not_flagged", func(t *testing.T) {
			data := &audit.DetectorData{
				GPOPolicies: map[string]*audit.GPOPolicy{
					"GUID": {AdvancedAudit: map[string]int{c.guid: c.minimum}},
				},
			}
			findings := d.Detect(context.Background(), data)
			if findings[0].Count != 0 {
				t.Fatalf("%s at value=%d (minimum): expected Count=0, got %d: %v", c.name, c.minimum, findings[0].Count, findings[0].Details)
			}
		})
	}
}

// TestDCAuditPolicyIncomplete_LegacyClosureCategoryBinding kills any exchange
// between two of the 6 legacy closures (dc-audit-policy-incomplete.go:42-47)
// that map a category to its EventAudit field, and any closure that reads the
// wrong field outright. Each subtest puts ONLY its own category's field at 0
// and the other five at 3 (no AdvancedAudit map at all, so audit.csv never
// wins and every category falls back to the legacy closure per
// auditpolicy.Level). A swapped closure either fails to flag the category
// under test (its field reads 3 via the wrong getter) or flags a different
// category instead (the wrong getter happens to read the one field that is
// 0) - both cases are caught because the test asserts the exact wantIssue
// string, not just Count.
func TestDCAuditPolicyIncomplete_LegacyClosureCategoryBinding(t *testing.T) {
	d := NewDCAuditPolicyIncompleteDetector()

	cases := []struct {
		name      string
		ea        audit.EventAudit
		wantIssue string
	}{
		{
			name: "Account Logon",
			ea: audit.EventAudit{
				AuditAccountLogon:  0,
				AuditAccountManage: 3,
				AuditLogonEvents:   3,
				AuditPolicyChange:  3,
				AuditSystemEvents:  3,
				AuditDSAccess:      3,
			},
			wantIssue: "Account Logon: not logging both success and failure",
		},
		{
			name: "Account Management",
			ea: audit.EventAudit{
				AuditAccountLogon:  3,
				AuditAccountManage: 0,
				AuditLogonEvents:   3,
				AuditPolicyChange:  3,
				AuditSystemEvents:  3,
				AuditDSAccess:      3,
			},
			wantIssue: "Account Management: not logging both success and failure",
		},
		{
			name: "Logon Events",
			ea: audit.EventAudit{
				AuditAccountLogon:  3,
				AuditAccountManage: 3,
				AuditLogonEvents:   0,
				AuditPolicyChange:  3,
				AuditSystemEvents:  3,
				AuditDSAccess:      3,
			},
			wantIssue: "Logon Events: not logging both success and failure",
		},
		{
			name: "Policy Change",
			ea: audit.EventAudit{
				AuditAccountLogon:  3,
				AuditAccountManage: 3,
				AuditLogonEvents:   3,
				AuditPolicyChange:  0,
				AuditSystemEvents:  3,
				AuditDSAccess:      3,
			},
			wantIssue: "Policy Change: not logging both success and failure",
		},
		{
			name: "System Events",
			ea: audit.EventAudit{
				AuditAccountLogon:  3,
				AuditAccountManage: 3,
				AuditLogonEvents:   3,
				AuditPolicyChange:  3,
				AuditSystemEvents:  0,
				AuditDSAccess:      3,
			},
			wantIssue: "System Events: not logging both success and failure",
		},
		{
			name: "Directory Service Access",
			ea: audit.EventAudit{
				AuditAccountLogon:  3,
				AuditAccountManage: 3,
				AuditLogonEvents:   3,
				AuditPolicyChange:  3,
				AuditSystemEvents:  3,
				AuditDSAccess:      0,
			},
			wantIssue: "Directory Service Access: failure auditing not enabled",
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			data := &audit.DetectorData{
				GPOPolicies: map[string]*audit.GPOPolicy{
					"GUID": {EventAudit: &c.ea},
				},
			}
			findings := d.Detect(context.Background(), data)
			if findings[0].Count != 1 {
				t.Fatalf("%s: expected Count=1, got %d: %v", c.name, findings[0].Count, findings[0].Details)
			}
			details := findings[0].Details
			issues, ok := details["issues"].([]string)
			if !ok {
				t.Fatalf("%s: expected issues to be []string, got %T", c.name, details["issues"])
			}
			if len(issues) != 1 {
				t.Fatalf("%s: expected exactly 1 issue, got %d: %v", c.name, len(issues), issues)
			}
			if issues[0] != c.wantIssue {
				t.Fatalf("%s: expected issue %q, got %q", c.name, c.wantIssue, issues[0])
			}
		})
	}
}

// TestDCAuditPolicyIncomplete_SeverityIsMedium kills Severity Medium->High:
// the finding carries the detector's declared severity verbatim and it must
// be observed directly, not inferred from any other field.
func TestDCAuditPolicyIncomplete_SeverityIsMedium(t *testing.T) {
	d := NewDCAuditPolicyIncompleteDetector()
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"GUID": {AdvancedAudit: map[string]int{auditpolicy.AuditPolicyChange: 0}},
		},
	}
	findings := d.Detect(context.Background(), data)
	if findings[0].Count == 0 {
		t.Fatal("expected a non-zero-count finding so Severity is observed on an actually emitted finding")
	}
	if findings[0].Severity != types.SeverityMedium {
		t.Fatalf("Severity = %q, want %q", findings[0].Severity, types.SeverityMedium)
	}
}
