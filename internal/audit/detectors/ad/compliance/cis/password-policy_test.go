package cis

import (
	"context"
	"reflect"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func compliantPasswordPolicy() *types.DomainInfo {
	return &types.DomainInfo{
		MinPwdLength:     14,
		PwdHistoryLength: 24,
		MaxPwdAge:        90,
		MinPwdAge:        1,
		LockoutThreshold: 5,
	}
}

// TestPasswordPolicy_MaxAge90_NotFlagged: the CIS Benchmark
// requires maximum password age <= 365 days (not 0), not <= 60 - 60 belongs
// to the DISA STIG variant of the benchmark. A domain with MaxPwdAge=90 was
// previously (wrongly) flagged under the 60-day threshold.
func TestPasswordPolicy_MaxAge90_NotFlagged(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: compliantPasswordPolicy()}
	findings := NewPasswordPolicyDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("got %+v, want Count=0 (MaxPwdAge=90 is CIS-compliant, <=365)", findings)
	}
}

// TestPasswordPolicy_MaxAge400_Flagged is the regression check for a
// genuinely too-long max age.
func TestPasswordPolicy_MaxAge400_Flagged(t *testing.T) {
	info := compliantPasswordPolicy()
	info.MaxPwdAge = 400
	data := &audit.DetectorData{DomainInfo: info}
	findings := NewPasswordPolicyDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (MaxPwdAge=400 > 365)", findings)
	}
}

// TestPasswordPolicy_LockoutThresholdZero_Flagged: CIS 1.2.2
// explicitly excludes 0 ("unacceptable") from the compliant range, but the
// old code exempted LockoutThreshold==0 from the check entirely - a domain
// with account lockout disabled outright was reported as compliant.
func TestPasswordPolicy_LockoutThresholdZero_Flagged(t *testing.T) {
	info := compliantPasswordPolicy()
	info.LockoutThreshold = 0
	data := &audit.DetectorData{DomainInfo: info}
	findings := NewPasswordPolicyDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (LockoutThreshold=0 must be flagged, not exempted)", findings)
	}
}

// TestPasswordPolicy_FullyCompliant_NoFinding is the regression check for a
// properly configured domain.
func TestPasswordPolicy_FullyCompliant_NoFinding(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: compliantPasswordPolicy()}
	findings := NewPasswordPolicyDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("got %+v, want Count=0", findings)
	}
}

// TestPasswordPolicy_DomainInfoNil_Flagged: a nil DomainInfo must be flagged
// through the "else" branch, not through the data fields. Also kills the
// guard mutation `DomainInfo != nil` -> `true ||`, which would dereference
// the nil pointer instead.
func TestPasswordPolicy_DomainInfoNil_Flagged(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: nil}
	findings := NewPasswordPolicyDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (nil DomainInfo must be flagged)", findings)
	}
	want := []string{"Domain password policy not available"}
	got, _ := findings[0].Details["violations"].([]string)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got violations %+v, want %+v", got, want)
	}
}

// TestPasswordPolicy_MinPwdLength12_Flagged is the single-rule-violation
// case for minimum password length, with the exact CIS 1.1.4 label.
func TestPasswordPolicy_MinPwdLength12_Flagged(t *testing.T) {
	info := compliantPasswordPolicy()
	info.MinPwdLength = 12
	data := &audit.DetectorData{DomainInfo: info}
	findings := NewPasswordPolicyDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (MinPwdLength=12 < 14)", findings)
	}
	want := []string{"CIS 1.1.4: Minimum password length 12 < 14"}
	got, _ := findings[0].Details["violations"].([]string)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got violations %+v, want %+v", got, want)
	}
}

// TestPasswordPolicy_MinPwdLength13_Flagged is the exact boundary (14-1):
// it is the only value that tells `< 14` apart from a loosened `< 13`.
func TestPasswordPolicy_MinPwdLength13_Flagged(t *testing.T) {
	info := compliantPasswordPolicy()
	info.MinPwdLength = 13
	data := &audit.DetectorData{DomainInfo: info}
	findings := NewPasswordPolicyDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (MinPwdLength=13 < 14, boundary)", findings)
	}
}

// TestPasswordPolicy_PwdHistoryLength23_Flagged is the single-rule-violation
// case for password history, with the exact CIS 1.1.1 label; 23 is also the
// boundary that tells `< 24` apart from a loosened `< 23`.
func TestPasswordPolicy_PwdHistoryLength23_Flagged(t *testing.T) {
	info := compliantPasswordPolicy()
	info.PwdHistoryLength = 23
	data := &audit.DetectorData{DomainInfo: info}
	findings := NewPasswordPolicyDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (PwdHistoryLength=23 < 24)", findings)
	}
	want := []string{"CIS 1.1.1: Password history 23 < 24"}
	got, _ := findings[0].Details["violations"].([]string)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got violations %+v, want %+v", got, want)
	}
}

// TestPasswordPolicy_MaxPwdAgeZero_Flagged: MaxPwdAge=0 means "passwords
// never expire", which CIS 1.1.2 explicitly treats as non-compliant, not
// exempt. Also kills the sub-term mutation that drops the `== 0` arm while
// keeping `> 365`.
func TestPasswordPolicy_MaxPwdAgeZero_Flagged(t *testing.T) {
	info := compliantPasswordPolicy()
	info.MaxPwdAge = 0
	data := &audit.DetectorData{DomainInfo: info}
	findings := NewPasswordPolicyDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (MaxPwdAge=0 means never expires, non-compliant)", findings)
	}
	want := []string{"CIS 1.1.2: Maximum password age 0 (must be 1-365 days, not 0/never)"}
	got, _ := findings[0].Details["violations"].([]string)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got violations %+v, want %+v", got, want)
	}
}

// TestPasswordPolicy_MaxPwdAge366_Flagged is the exact boundary (365+1): it
// tells `> 365` apart from a loosened `> 366` or a tightened `>= 365`.
func TestPasswordPolicy_MaxPwdAge366_Flagged(t *testing.T) {
	info := compliantPasswordPolicy()
	info.MaxPwdAge = 366
	data := &audit.DetectorData{DomainInfo: info}
	findings := NewPasswordPolicyDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (MaxPwdAge=366 > 365, boundary)", findings)
	}
	want := []string{"CIS 1.1.2: Maximum password age 366 (must be 1-365 days, not 0/never)"}
	got, _ := findings[0].Details["violations"].([]string)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got violations %+v, want %+v", got, want)
	}
}

// TestPasswordPolicy_MinPwdAgeZero_Flagged is the single-rule-violation case
// for minimum password age, with the exact CIS 1.1.3 label; 0 is also the
// boundary that tells `< 1` apart from a loosened `< 0`.
func TestPasswordPolicy_MinPwdAgeZero_Flagged(t *testing.T) {
	info := compliantPasswordPolicy()
	info.MinPwdAge = 0
	data := &audit.DetectorData{DomainInfo: info}
	findings := NewPasswordPolicyDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (MinPwdAge=0 < 1)", findings)
	}
	want := []string{"CIS 1.1.3: Minimum password age 0 < 1 day"}
	got, _ := findings[0].Details["violations"].([]string)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got violations %+v, want %+v", got, want)
	}
}

// TestPasswordPolicy_LockoutThreshold6_Flagged is the exact boundary (5+1):
// it tells `> 5` apart from a loosened `> 6`, and also kills the sub-term
// mutation that drops the `> 5` arm while keeping `== 0` (which would miss
// a lockout threshold of 6 entirely).
func TestPasswordPolicy_LockoutThreshold6_Flagged(t *testing.T) {
	info := compliantPasswordPolicy()
	info.LockoutThreshold = 6
	data := &audit.DetectorData{DomainInfo: info}
	findings := NewPasswordPolicyDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (LockoutThreshold=6 > 5, boundary)", findings)
	}
	want := []string{"CIS 1.2.2: Account lockout threshold 6 (must be 1-5, not 0)"}
	got, _ := findings[0].Details["violations"].([]string)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got violations %+v, want %+v", got, want)
	}
}

// TestPasswordPolicy_AllBoundariesCompliant_NoFinding sets every field to
// its exact CIS-compliant boundary value at once (14/24/365/1/5). This
// tells every `<` from a tightened `<=` and every `>` from a tightened
// `>=` or a loosened by-one operator apart, for all five rules in one pass.
func TestPasswordPolicy_AllBoundariesCompliant_NoFinding(t *testing.T) {
	info := &types.DomainInfo{
		MinPwdLength:     14,
		PwdHistoryLength: 24,
		MaxPwdAge:        365,
		MinPwdAge:        1,
		LockoutThreshold: 5,
	}
	data := &audit.DetectorData{DomainInfo: info}
	findings := NewPasswordPolicyDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("got %+v, want Count=0 (all fields at their compliant CIS boundary)", findings)
	}
}

// TestPasswordPolicy_Severity_IsHigh locks the finding's Severity, which the
// QA campaign found unguarded by any existing test (High -> Medium survived
// every prior mutation run).
func TestPasswordPolicy_Severity_IsHigh(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: compliantPasswordPolicy()}
	findings := NewPasswordPolicyDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Fatalf("got Severity=%v, want %v", findings[0].Severity, types.SeverityHigh)
	}
}
