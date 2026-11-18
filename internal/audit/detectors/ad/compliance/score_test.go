package compliance

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestScore_MinLength13_NowDeducted: the password-length
// threshold was 12, looser than both CIS (14) and DISA STIG (14) - meaning
// this score could show 100/100 on a domain where CIS_PASSWORD_POLICY and
// DISA_ACCOUNT_POLICIES simultaneously report a High-severity violation for
// the exact same MinPwdLength value. Tightened to 14 to remove that
// contradiction. A domain with MinPwdLength=13 was previously "compliant"
// here; it must now be deducted.
func TestScore_MinLength13_NowDeducted(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: &types.DomainInfo{
		MinPwdLength:     13,
		PwdHistoryLength: 24,
		LockoutThreshold: 5,
		MaxPwdAge:        60,
	}}
	findings := NewScoreDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	score, _ := findings[0].Details["score"].(int)
	if score != 90 {
		t.Errorf("score = %d, want 90 (MinPwdLength=13 < 14 must deduct 10)", score)
	}
}

// TestScore_History23_NowDeducted is the analogous fix for password history
// (was 12, now 24, matching CIS 1.1.1 / DISA WN22-AC-000040).
func TestScore_History23_NowDeducted(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: &types.DomainInfo{
		MinPwdLength:     14,
		PwdHistoryLength: 23,
		LockoutThreshold: 5,
		MaxPwdAge:        60,
	}}
	findings := NewScoreDetector().Detect(context.Background(), data)
	score, _ := findings[0].Details["score"].(int)
	if score != 95 {
		t.Errorf("score = %d, want 95 (PwdHistoryLength=23 < 24 must deduct 5)", score)
	}
}

// TestScore_ScopeHonestlyDisclosed: the title/description used
// to present this as an overall "Compliance Score Assessment" with no scope
// caveat. It must now disclose it only covers password policy + admin count.
func TestScore_ScopeHonestlyDisclosed(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: &types.DomainInfo{
		MinPwdLength: 14, PwdHistoryLength: 24, LockoutThreshold: 5, MaxPwdAge: 60,
	}}
	findings := NewScoreDetector().Detect(context.Background(), data)
	if findings[0].Title == "Compliance Score Assessment" {
		t.Errorf("title must no longer imply an unscoped overall assessment: %q", findings[0].Title)
	}
	if _, ok := findings[0].Details["scope"]; !ok {
		t.Errorf("Details must disclose the score's actual scope")
	}
}

// TestScore_FullyCompliant_100 is the regression check.
func TestScore_FullyCompliant_100(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: &types.DomainInfo{
		MinPwdLength: 14, PwdHistoryLength: 24, LockoutThreshold: 5, MaxPwdAge: 60,
	}}
	findings := NewScoreDetector().Detect(context.Background(), data)
	score, _ := findings[0].Details["score"].(int)
	if score != 100 {
		t.Errorf("score = %d, want 100", score)
	}
}

// TestScore_BaselineCompliant_NoDeductionsNoUsers is the literal baseline:
// a fully compliant domain with no users at all must score 100 with an
// empty deductions map.
func TestScore_BaselineCompliant_NoDeductionsNoUsers(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: &types.DomainInfo{
		MinPwdLength: 14, PwdHistoryLength: 24, LockoutThreshold: 5, MaxPwdAge: 60,
	}}
	findings := NewScoreDetector().Detect(context.Background(), data)
	score, _ := findings[0].Details["score"].(int)
	if score != 100 {
		t.Errorf("score = %d, want 100", score)
	}
	deductions, _ := findings[0].Details["deductions"].(map[string]int)
	if len(deductions) != 0 {
		t.Errorf("deductions = %v, want empty", deductions)
	}
}

// TestScore_WeakPasswordLength_Isolated isolates the length deduction:
// exact score, exact weight and exact key.
func TestScore_WeakPasswordLength_Isolated(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: &types.DomainInfo{
		MinPwdLength: 10, PwdHistoryLength: 24, LockoutThreshold: 5, MaxPwdAge: 60,
	}}
	findings := NewScoreDetector().Detect(context.Background(), data)
	score, _ := findings[0].Details["score"].(int)
	if score != 90 {
		t.Errorf("score = %d, want 90", score)
	}
	deductions, _ := findings[0].Details["deductions"].(map[string]int)
	if len(deductions) != 1 {
		t.Fatalf("deductions = %v, want exactly 1 entry", deductions)
	}
	val, ok := deductions["weak_password_length"]
	if !ok {
		t.Fatalf("deductions missing key \"weak_password_length\": %v", deductions)
	}
	if val != 10 {
		t.Errorf("deductions[\"weak_password_length\"] = %d, want 10", val)
	}
}

// TestScore_WeakPasswordHistory_Isolated isolates the history deduction.
func TestScore_WeakPasswordHistory_Isolated(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: &types.DomainInfo{
		MinPwdLength: 14, PwdHistoryLength: 10, LockoutThreshold: 5, MaxPwdAge: 60,
	}}
	findings := NewScoreDetector().Detect(context.Background(), data)
	score, _ := findings[0].Details["score"].(int)
	if score != 95 {
		t.Errorf("score = %d, want 95", score)
	}
	deductions, _ := findings[0].Details["deductions"].(map[string]int)
	if len(deductions) != 1 {
		t.Fatalf("deductions = %v, want exactly 1 entry", deductions)
	}
	val, ok := deductions["weak_password_history"]
	if !ok {
		t.Fatalf("deductions missing key \"weak_password_history\": %v", deductions)
	}
	if val != 5 {
		t.Errorf("deductions[\"weak_password_history\"] = %d, want 5", val)
	}
}

// TestScore_WeakLockoutPolicy_Isolated isolates the lockout deduction.
func TestScore_WeakLockoutPolicy_Isolated(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: &types.DomainInfo{
		MinPwdLength: 14, PwdHistoryLength: 24, LockoutThreshold: 15, MaxPwdAge: 60,
	}}
	findings := NewScoreDetector().Detect(context.Background(), data)
	score, _ := findings[0].Details["score"].(int)
	if score != 95 {
		t.Errorf("score = %d, want 95", score)
	}
	deductions, _ := findings[0].Details["deductions"].(map[string]int)
	if len(deductions) != 1 {
		t.Fatalf("deductions = %v, want exactly 1 entry", deductions)
	}
	val, ok := deductions["weak_lockout_policy"]
	if !ok {
		t.Fatalf("deductions missing key \"weak_lockout_policy\": %v", deductions)
	}
	if val != 5 {
		t.Errorf("deductions[\"weak_lockout_policy\"] = %d, want 5", val)
	}
}

// TestScore_WeakPasswordAge_Isolated isolates the max-password-age deduction.
func TestScore_WeakPasswordAge_Isolated(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: &types.DomainInfo{
		MinPwdLength: 14, PwdHistoryLength: 24, LockoutThreshold: 5, MaxPwdAge: 120,
	}}
	findings := NewScoreDetector().Detect(context.Background(), data)
	score, _ := findings[0].Details["score"].(int)
	if score != 95 {
		t.Errorf("score = %d, want 95", score)
	}
	deductions, _ := findings[0].Details["deductions"].(map[string]int)
	if len(deductions) != 1 {
		t.Fatalf("deductions = %v, want exactly 1 entry", deductions)
	}
	val, ok := deductions["weak_password_age"]
	if !ok {
		t.Fatalf("deductions missing key \"weak_password_age\": %v", deductions)
	}
	if val != 5 {
		t.Errorf("deductions[\"weak_password_age\"] = %d, want 5", val)
	}
}

// TestScore_LockoutThresholdBoundaries pins the exact boundary of the
// lockout-threshold condition (`> 10 || == 0`) at 0, 1, 10 and 11.
func TestScore_LockoutThresholdBoundaries(t *testing.T) {
	cases := []struct {
		name       string
		threshold  int
		wantScore  int
		wantDeduct bool
	}{
		{"threshold0_deducts", 0, 95, true},
		{"threshold1_noDeduct", 1, 100, false},
		{"threshold10_noDeduct", 10, 100, false},
		{"threshold11_deducts", 11, 95, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{DomainInfo: &types.DomainInfo{
				MinPwdLength: 14, PwdHistoryLength: 24, LockoutThreshold: tc.threshold, MaxPwdAge: 60,
			}}
			findings := NewScoreDetector().Detect(context.Background(), data)
			score, _ := findings[0].Details["score"].(int)
			if score != tc.wantScore {
				t.Errorf("threshold=%d: score = %d, want %d", tc.threshold, score, tc.wantScore)
			}
			deductions, _ := findings[0].Details["deductions"].(map[string]int)
			val, ok := deductions["weak_lockout_policy"]
			if tc.wantDeduct {
				if !ok || val != 5 {
					t.Errorf("threshold=%d: deductions[\"weak_lockout_policy\"] = (%d, ok=%v), want (5, true)", tc.threshold, val, ok)
				}
			} else if ok {
				t.Errorf("threshold=%d: deductions[\"weak_lockout_policy\"] = %d, want absent", tc.threshold, val)
			}
		})
	}
}

// TestScore_MaxPwdAgeBoundaries pins the exact boundary of the max-password-age
// condition (`> 90 || == 0`) at 0, 1, 89, 90 and 91.
func TestScore_MaxPwdAgeBoundaries(t *testing.T) {
	cases := []struct {
		name       string
		maxPwdAge  int
		wantScore  int
		wantDeduct bool
	}{
		{"age0_deducts", 0, 95, true},
		{"age1_noDeduct", 1, 100, false},
		{"age89_noDeduct", 89, 100, false},
		{"age90_noDeduct", 90, 100, false},
		{"age91_deducts", 91, 95, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{DomainInfo: &types.DomainInfo{
				MinPwdLength: 14, PwdHistoryLength: 24, LockoutThreshold: 5, MaxPwdAge: tc.maxPwdAge,
			}}
			findings := NewScoreDetector().Detect(context.Background(), data)
			score, _ := findings[0].Details["score"].(int)
			if score != tc.wantScore {
				t.Errorf("maxPwdAge=%d: score = %d, want %d", tc.maxPwdAge, score, tc.wantScore)
			}
			deductions, _ := findings[0].Details["deductions"].(map[string]int)
			val, ok := deductions["weak_password_age"]
			if tc.wantDeduct {
				if !ok || val != 5 {
					t.Errorf("maxPwdAge=%d: deductions[\"weak_password_age\"] = (%d, ok=%v), want (5, true)", tc.maxPwdAge, val, ok)
				}
			} else if ok {
				t.Errorf("maxPwdAge=%d: deductions[\"weak_password_age\"] = %d, want absent", tc.maxPwdAge, val)
			}
		})
	}
}

// TestScore_DomainInfoNil_NoPanic covers the else branch of the DomainInfo
// nil-check: no panic, exact score and exact deduction weight/key.
func TestScore_DomainInfoNil_NoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Detect panicked with nil DomainInfo: %v", r)
		}
	}()
	data := &audit.DetectorData{DomainInfo: nil}
	findings := NewScoreDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	score, _ := findings[0].Details["score"].(int)
	if score != 85 {
		t.Errorf("score = %d, want 85", score)
	}
	deductions, _ := findings[0].Details["deductions"].(map[string]int)
	if len(deductions) != 1 {
		t.Fatalf("deductions = %v, want exactly 1 entry", deductions)
	}
	val, ok := deductions["no_domain_info"]
	if !ok {
		t.Fatalf("deductions missing key \"no_domain_info\": %v", deductions)
	}
	if val != 15 {
		t.Errorf("deductions[\"no_domain_info\"] = %d, want 15", val)
	}
}

func makeUser(disabled, adminCount bool) types.User {
	return types.User{Disabled: disabled, AdminCount: adminCount}
}

// TestScore_AdminCountBoundaries pins the exact boundary of the
// excessive_admins condition (`> 20`) at 19, 20 and 21 ACTIVE admin accounts.
func TestScore_AdminCountBoundaries(t *testing.T) {
	cases := []struct {
		name         string
		activeAdmins int
		wantScore    int
		wantDeduct   bool
	}{
		{"admins19_noDeduct", 19, 100, false},
		{"admins20_noDeduct", 20, 100, false},
		{"admins21_deducts", 21, 90, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			users := make([]types.User, 0, tc.activeAdmins)
			for i := 0; i < tc.activeAdmins; i++ {
				users = append(users, makeUser(false, true))
			}
			data := &audit.DetectorData{
				DomainInfo: &types.DomainInfo{
					MinPwdLength: 14, PwdHistoryLength: 24, LockoutThreshold: 5, MaxPwdAge: 60,
				},
				Users: users,
			}
			findings := NewScoreDetector().Detect(context.Background(), data)
			score, _ := findings[0].Details["score"].(int)
			if score != tc.wantScore {
				t.Errorf("activeAdmins=%d: score = %d, want %d", tc.activeAdmins, score, tc.wantScore)
			}
			adminCount, _ := findings[0].Details["adminCount"].(int)
			if adminCount != tc.activeAdmins {
				t.Errorf("activeAdmins=%d: adminCount = %d, want %d", tc.activeAdmins, adminCount, tc.activeAdmins)
			}
			deductions, _ := findings[0].Details["deductions"].(map[string]int)
			val, ok := deductions["excessive_admins"]
			if tc.wantDeduct {
				if !ok || val != 10 {
					t.Errorf("activeAdmins=%d: deductions[\"excessive_admins\"] = (%d, ok=%v), want (10, true)", tc.activeAdmins, val, ok)
				}
			} else if ok {
				t.Errorf("activeAdmins=%d: deductions[\"excessive_admins\"] = %d, want absent", tc.activeAdmins, val)
			}
		})
	}
}

// TestScore_DisabledAdminsExcludedFromGuard proves the !u.Disabled guard:
// 21 DISABLED accounts with AdminCount=true plus 1 ACTIVE account with
// AdminCount=true must count adminCount=1, not 22, and must not trigger
// excessive_admins.
func TestScore_DisabledAdminsExcludedFromGuard(t *testing.T) {
	users := make([]types.User, 0, 22)
	for i := 0; i < 21; i++ {
		users = append(users, makeUser(true, true))
	}
	users = append(users, makeUser(false, true))
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{
			MinPwdLength: 14, PwdHistoryLength: 24, LockoutThreshold: 5, MaxPwdAge: 60,
		},
		Users: users,
	}
	findings := NewScoreDetector().Detect(context.Background(), data)
	adminCount, _ := findings[0].Details["adminCount"].(int)
	if adminCount != 1 {
		t.Errorf("adminCount = %d, want 1 (21 disabled admins must be excluded)", adminCount)
	}
	score, _ := findings[0].Details["score"].(int)
	if score != 100 {
		t.Errorf("score = %d, want 100 (no excessive_admins deduction)", score)
	}
	deductions, _ := findings[0].Details["deductions"].(map[string]int)
	if _, ok := deductions["excessive_admins"]; ok {
		t.Errorf("deductions = %v, must not contain \"excessive_admins\"", deductions)
	}
}

// TestScore_ActiveAdminsCountedDisabledExcluded is the inverse of
// TestScore_DisabledAdminsExcludedFromGuard: 21 ACTIVE accounts with
// AdminCount=true plus 1 DISABLED account with AdminCount=true must count
// adminCount=21 (the disabled one excluded) and must trigger excessive_admins.
func TestScore_ActiveAdminsCountedDisabledExcluded(t *testing.T) {
	users := make([]types.User, 0, 22)
	for i := 0; i < 21; i++ {
		users = append(users, makeUser(false, true))
	}
	users = append(users, makeUser(true, true))
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{
			MinPwdLength: 14, PwdHistoryLength: 24, LockoutThreshold: 5, MaxPwdAge: 60,
		},
		Users: users,
	}
	findings := NewScoreDetector().Detect(context.Background(), data)
	adminCount, _ := findings[0].Details["adminCount"].(int)
	if adminCount != 21 {
		t.Errorf("adminCount = %d, want 21 (the disabled admin must be excluded)", adminCount)
	}
	score, _ := findings[0].Details["score"].(int)
	if score != 90 {
		t.Errorf("score = %d, want 90 (excessive_admins deduction must apply)", score)
	}
	deductions, _ := findings[0].Details["deductions"].(map[string]int)
	val, ok := deductions["excessive_admins"]
	if !ok || val != 10 {
		t.Errorf("deductions[\"excessive_admins\"] = (%d, ok=%v), want (10, true)", val, ok)
	}
}

// TestScore_MixedPopulation_ExactCounts pins totalUsers, enabledUsers and
// adminCount on a population mixing active/disabled and admin/non-admin
// accounts, so the !u.Disabled bookkeeping can't be swapped unnoticed.
func TestScore_MixedPopulation_ExactCounts(t *testing.T) {
	users := []types.User{
		makeUser(false, false), // active, non-admin
		makeUser(false, false), // active, non-admin
		makeUser(false, true),  // active, admin -> counted
		makeUser(true, false),  // disabled, non-admin
		makeUser(true, false),  // disabled, non-admin
		makeUser(true, true),   // disabled, admin -> excluded by guard
		makeUser(true, true),   // disabled, admin -> excluded by guard
	}
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{
			MinPwdLength: 14, PwdHistoryLength: 24, LockoutThreshold: 5, MaxPwdAge: 60,
		},
		Users: users,
	}
	findings := NewScoreDetector().Detect(context.Background(), data)
	totalUsers, _ := findings[0].Details["totalUsers"].(int)
	if totalUsers != 7 {
		t.Errorf("totalUsers = %d, want 7", totalUsers)
	}
	enabledUsers, _ := findings[0].Details["enabledUsers"].(int)
	if enabledUsers != 3 {
		t.Errorf("enabledUsers = %d, want 3", enabledUsers)
	}
	adminCount, _ := findings[0].Details["adminCount"].(int)
	if adminCount != 1 {
		t.Errorf("adminCount = %d, want 1", adminCount)
	}
	score, _ := findings[0].Details["score"].(int)
	if score != 100 {
		t.Errorf("score = %d, want 100", score)
	}
}

// TestScore_CountAndSeverity pins the constant Count and Severity fields.
func TestScore_CountAndSeverity(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: &types.DomainInfo{
		MinPwdLength: 14, PwdHistoryLength: 24, LockoutThreshold: 5, MaxPwdAge: 60,
	}}
	findings := NewScoreDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityInfo {
		t.Errorf("Severity = %v, want %v", findings[0].Severity, types.SeverityInfo)
	}
}

// TestScore_DetailsKeysPresent pins the presence and type of every
// calculated key of Details (score, deductions, totalUsers, enabledUsers,
// adminCount), so a renamed key is caught even when its sibling test only
// checks the value under its original name.
func TestScore_DetailsKeysPresent(t *testing.T) {
	users := []types.User{
		makeUser(false, true),
		makeUser(true, false),
	}
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{
			MinPwdLength: 14, PwdHistoryLength: 24, LockoutThreshold: 5, MaxPwdAge: 60,
		},
		Users: users,
	}
	findings := NewScoreDetector().Detect(context.Background(), data)
	details := findings[0].Details

	if _, ok := details["score"].(int); !ok {
		t.Errorf("Details[\"score\"] missing or not an int: %v", details["score"])
	}
	if _, ok := details["deductions"].(map[string]int); !ok {
		t.Errorf("Details[\"deductions\"] missing or not a map[string]int: %v", details["deductions"])
	}
	totalUsers, ok := details["totalUsers"].(int)
	if !ok || totalUsers != 2 {
		t.Errorf("Details[\"totalUsers\"] = (%v, ok=%v), want (2, true)", details["totalUsers"], ok)
	}
	enabledUsers, ok := details["enabledUsers"].(int)
	if !ok || enabledUsers != 1 {
		t.Errorf("Details[\"enabledUsers\"] = (%v, ok=%v), want (1, true)", details["enabledUsers"], ok)
	}
	adminCount, ok := details["adminCount"].(int)
	if !ok || adminCount != 1 {
		t.Errorf("Details[\"adminCount\"] = (%v, ok=%v), want (1, true)", details["adminCount"], ok)
	}
}
