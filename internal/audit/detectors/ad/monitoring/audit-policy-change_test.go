package monitoring

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/detectors/ad/compliance/auditpolicy"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func TestAuditPolicyChange_AdvancedAuditPolicyPrecedence(t *testing.T) {
	d := NewAuditPolicyChangeDetector()

	t.Run("legacy Event Audit shows nothing audited but audit.csv configures the subcategory: not flagged", func(t *testing.T) {
		data := &audit.DetectorData{
			GPOPolicies: map[string]*audit.GPOPolicy{
				"GUID": {
					EventAudit:    &audit.EventAudit{AuditPolicyChange: 0},
					AdvancedAudit: map[string]int{auditpolicy.AuditPolicyChange: 3},
				},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("expected count=0 (subcategory wins), got %d", findings[0].Count)
		}
	})

	t.Run("legacy Event Audit shows fully audited but audit.csv configures the subcategory as insufficient: flagged", func(t *testing.T) {
		data := &audit.DetectorData{
			GPOPolicies: map[string]*audit.GPOPolicy{
				"GUID": {
					EventAudit:    &audit.EventAudit{AuditPolicyChange: 3},
					AdvancedAudit: map[string]int{auditpolicy.AuditPolicyChange: 1},
				},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("expected count=1 (subcategory wins over legacy), got %d", findings[0].Count)
		}
	})

	t.Run("neither source configures it: not flagged, honest details", func(t *testing.T) {
		data := &audit.DetectorData{
			GPOPolicies: map[string]*audit.GPOPolicy{"GUID": {}},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("expected count=0, got %d", findings[0].Count)
		}
		if findings[0].Details == nil {
			t.Fatal("expected honest details, got nil")
		}
	})
}

// value=2 means Success-only or Failure-only auditing: incomplete, and the
// detector requires both (requiredValue=3), so it must still be flagged.
func TestAuditPolicyChange_PartialAuditingAtValueTwoIsFlagged(t *testing.T) {
	d := NewAuditPolicyChangeDetector()
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"GUID": {
				AdvancedAudit: map[string]int{auditpolicy.AuditPolicyChange: 2},
			},
		},
	}
	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("value=2 (Success-or-Failure only) must be flagged since 2<3 (requiredValue=3), got Count=%d", findings[0].Count)
	}
}

// The legacy fallback must read EventAudit.AuditPolicyChange specifically.
// Every other EventAudit field is left at its zero value, so reading any
// other field instead would see 0 (<3) and wrongly flag this as violated.
func TestAuditPolicyChange_LegacyFallbackReadsAuditPolicyChangeField(t *testing.T) {
	d := NewAuditPolicyChangeDetector()
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"GUID": {
				EventAudit: &audit.EventAudit{AuditPolicyChange: 3},
			},
		},
	}
	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("legacy AuditPolicyChange=3 is fully audited (3<3 is false) and must not be flagged; got Count=%d", findings[0].Count)
	}
}

// The finding's Severity must stay High when the violation is flagged: a
// detector that silently degrades its own severity misleads triage even
// though Count still correctly signals a violation.
func TestAuditPolicyChange_FlaggedSeverityIsHigh(t *testing.T) {
	d := NewAuditPolicyChangeDetector()
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"GUID": {
				AdvancedAudit: map[string]int{auditpolicy.AuditPolicyChange: 0},
			},
		},
	}
	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("expected count=1 to exercise the flagged path, got %d", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Fatalf("expected Severity=%v, got %v", types.SeverityHigh, findings[0].Severity)
	}
}
