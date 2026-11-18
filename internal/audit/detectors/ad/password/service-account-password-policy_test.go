package password

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func detectServiceAccountPolicy(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewServiceAccountPasswordPolicyDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

func TestServiceAccountPolicy_SPNWithNoPSO_Fires(t *testing.T) {
	f := detectServiceAccountPolicy(t, &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc.sql,DC=contoso,DC=com", SAMAccountName: "svc.sql", ServicePrincipalNames: []string{"MSSQLSvc/db01:1433"}},
		},
	})
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (no policy covers the service account)", f.Count)
	}
}

func TestServiceAccountPolicy_PSOTwentyCharsDirectOnAccount_Covers(t *testing.T) {
	f := detectServiceAccountPolicy(t, &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc.sql,DC=contoso,DC=com", SAMAccountName: "svc.sql", ServicePrincipalNames: []string{"MSSQLSvc/db01:1433"}},
		},
		FGPPs: []types.FGPP{
			{DN: "CN=strong-pso,DC=contoso,DC=com", MinPasswordLength: 20, AppliesTo: []string{"CN=svc.sql,DC=contoso,DC=com"}},
		},
	})
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (a 20-char PSO applies directly to the account)", f.Count)
	}
}

func TestServiceAccountPolicy_PSONineteenChars_StillFires(t *testing.T) {
	f := detectServiceAccountPolicy(t, &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc.sql,DC=contoso,DC=com", SAMAccountName: "svc.sql", ServicePrincipalNames: []string{"MSSQLSvc/db01:1433"}},
		},
		FGPPs: []types.FGPP{
			{DN: "CN=weak-pso,DC=contoso,DC=com", MinPasswordLength: 19, AppliesTo: []string{"CN=svc.sql,DC=contoso,DC=com"}},
		},
	})
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (a 19-char PSO does not meet the threshold)", f.Count)
	}
}

func TestServiceAccountPolicy_PSOOnDirectGroupMember_Covers(t *testing.T) {
	f := detectServiceAccountPolicy(t, &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc.sql,DC=contoso,DC=com", SAMAccountName: "svc.sql", ServicePrincipalNames: []string{"MSSQLSvc/db01:1433"}},
		},
		Groups: []types.Group{
			{DN: "CN=service-accounts,DC=contoso,DC=com", Members: []string{"CN=svc.sql,DC=contoso,DC=com"}},
		},
		FGPPs: []types.FGPP{
			{DN: "CN=strong-pso,DC=contoso,DC=com", MinPasswordLength: 20, AppliesTo: []string{"CN=service-accounts,DC=contoso,DC=com"}},
		},
	})
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (the account is a direct member of the targeted group)", f.Count)
	}
}

// TestServiceAccountPolicy_PSOOnNestedParentGroup_Covers is the regression
// guard for the false positive: a PSO applied to group A, which contains
// group B, which contains the service account, must count as covered. The
// pre-fix code only walked direct members of the targeted group and missed
// this.
func TestServiceAccountPolicy_PSOOnNestedParentGroup_Covers(t *testing.T) {
	f := detectServiceAccountPolicy(t, &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc.sql,DC=contoso,DC=com", SAMAccountName: "svc.sql", ServicePrincipalNames: []string{"MSSQLSvc/db01:1433"}},
		},
		Groups: []types.Group{
			{DN: "CN=group-a,DC=contoso,DC=com", Members: []string{"CN=group-b,DC=contoso,DC=com"}},
			{DN: "CN=group-b,DC=contoso,DC=com", Members: []string{"CN=svc.sql,DC=contoso,DC=com"}},
		},
		FGPPs: []types.FGPP{
			{DN: "CN=strong-pso,DC=contoso,DC=com", MinPasswordLength: 20, AppliesTo: []string{"CN=group-a,DC=contoso,DC=com"}},
		},
	})
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (the account is covered transitively through group-b nested in group-a)", f.Count)
	}
}

// TestServiceAccountPolicy_GroupCycleWithoutAccount_FiresAndDoesNotHang
// covers the cycle guard: group A contains group B, group B contains group
// A, and the service account is in neither. The walk must terminate and
// report the account as not covered.
func TestServiceAccountPolicy_GroupCycleWithoutAccount_FiresAndDoesNotHang(t *testing.T) {
	f := detectServiceAccountPolicy(t, &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc.sql,DC=contoso,DC=com", SAMAccountName: "svc.sql", ServicePrincipalNames: []string{"MSSQLSvc/db01:1433"}},
		},
		Groups: []types.Group{
			{DN: "CN=group-a,DC=contoso,DC=com", Members: []string{"CN=group-b,DC=contoso,DC=com"}},
			{DN: "CN=group-b,DC=contoso,DC=com", Members: []string{"CN=group-a,DC=contoso,DC=com"}},
		},
		FGPPs: []types.FGPP{
			{DN: "CN=strong-pso,DC=contoso,DC=com", MinPasswordLength: 20, AppliesTo: []string{"CN=group-a,DC=contoso,DC=com"}},
		},
	})
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (the cycle contains no service account)", f.Count)
	}
}

func TestServiceAccountPolicy_DomainDefaultTwentyChars_Covers(t *testing.T) {
	f := detectServiceAccountPolicy(t, &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc.sql,DC=contoso,DC=com", SAMAccountName: "svc.sql", ServicePrincipalNames: []string{"MSSQLSvc/db01:1433"}},
		},
		DomainInfo: &types.DomainInfo{MinPasswordLength: 20},
	})
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (the domain default password policy enforces 20 characters)", f.Count)
	}
}

func TestServiceAccountPolicy_DomainDefaultFourteenChars_StillFires(t *testing.T) {
	f := detectServiceAccountPolicy(t, &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc.sql,DC=contoso,DC=com", SAMAccountName: "svc.sql", ServicePrincipalNames: []string{"MSSQLSvc/db01:1433"}},
		},
		DomainInfo: &types.DomainInfo{MinPasswordLength: 14},
	})
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (14 characters does not meet the threshold)", f.Count)
	}
}

func TestServiceAccountPolicy_NoServiceAccounts_DoesNotFire(t *testing.T) {
	f := detectServiceAccountPolicy(t, &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=alice,DC=contoso,DC=com", SAMAccountName: "alice"},
		},
	})
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (no account matches the service-account heuristic)", f.Count)
	}
}

func TestServiceAccountPolicy_NamePrefixSvcUnderscore_Fires(t *testing.T) {
	f := detectServiceAccountPolicy(t, &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc_backup,DC=contoso,DC=com", SAMAccountName: "svc_backup"},
		},
	})
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (the svc_ prefix qualifies as a service account)", f.Count)
	}
}

// TestServiceAccountPolicy_WeakDirectPSOOverridesStrongDomainDefault_Fires
// is the regression guard for the resultant-policy calculation: a PSO linked
// DIRECTLY to the service account always wins the RSOP, even over a domain
// default that would otherwise look sufficient. Fails on the pre-fix code,
// which short-circuited as soon as the domain default alone met the
// threshold and never considered a weaker PSO overriding that account.
func TestServiceAccountPolicy_WeakDirectPSOOverridesStrongDomainDefault_Fires(t *testing.T) {
	f := detectServiceAccountPolicy(t, &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc.sql,DC=contoso,DC=com", SAMAccountName: "svc.sql", ServicePrincipalNames: []string{"MSSQLSvc/db01:1433"}},
		},
		DomainInfo: &types.DomainInfo{MinPasswordLength: 20},
		FGPPs: []types.FGPP{
			{DN: "CN=weak-direct-pso,DC=contoso,DC=com", Precedence: 8, MinPasswordLength: 8, AppliesTo: []string{"CN=svc.sql,DC=contoso,DC=com"}},
		},
	})
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (the directly-linked 8-char PSO overrides the 20-char domain default)", f.Count)
	}
}

// TestServiceAccountPolicy_GroupPSOPrecedenceWins_Covers is the regression
// guard for precedence ordering among group-linked PSOs: when a weak PSO (8
// chars) and a strong PSO (24 chars) both apply via different groups, the
// one with the LOWER Precedence value wins the RSOP regardless of which is
// stronger. Here the strong PSO has the lower precedence, so it wins and the
// account is covered. Fails on the pre-fix code, which only asked whether
// ANY FGPP >= 20 chars covered the account and ignored precedence ordering
// against the competing weak PSO entirely - it happened to still pass by
// coincidence on count, so the real regression this guards is precedence
// selection, exercised together with the sibling "weak PSO wins" case below.
func TestServiceAccountPolicy_GroupPSOPrecedenceWins_Covers(t *testing.T) {
	f := detectServiceAccountPolicy(t, &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc.sql,DC=contoso,DC=com", SAMAccountName: "svc.sql", ServicePrincipalNames: []string{"MSSQLSvc/db01:1433"}},
		},
		DomainInfo: &types.DomainInfo{MinPasswordLength: 20},
		Groups: []types.Group{
			{DN: "CN=weak-group,DC=contoso,DC=com", Members: []string{"CN=svc.sql,DC=contoso,DC=com"}},
			{DN: "CN=strong-group,DC=contoso,DC=com", Members: []string{"CN=svc.sql,DC=contoso,DC=com"}},
		},
		FGPPs: []types.FGPP{
			{DN: "CN=weak-pso,DC=contoso,DC=com", Precedence: 50, MinPasswordLength: 8, AppliesTo: []string{"CN=weak-group,DC=contoso,DC=com"}},
			{DN: "CN=strong-pso,DC=contoso,DC=com", Precedence: 10, MinPasswordLength: 24, AppliesTo: []string{"CN=strong-group,DC=contoso,DC=com"}},
		},
	})
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (the strong 24-char PSO has the lower precedence (10 < 50) and wins)", f.Count)
	}
}

// TestServiceAccountPolicy_GroupPSOPrecedenceLoses_Fires is the mirror of
// the case above: the WEAK PSO now has the lower precedence, so it wins the
// RSOP over the strong one despite the strong PSO also applying via another
// group. Fails on the pre-fix code, which considered the account covered as
// soon as ANY FGPP >= 20 chars applied to it (the strong PSO), never
// checking whether a lower-precedence weaker PSO should have taken priority.
func TestServiceAccountPolicy_GroupPSOPrecedenceLoses_Fires(t *testing.T) {
	f := detectServiceAccountPolicy(t, &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc.sql,DC=contoso,DC=com", SAMAccountName: "svc.sql", ServicePrincipalNames: []string{"MSSQLSvc/db01:1433"}},
		},
		DomainInfo: &types.DomainInfo{MinPasswordLength: 20},
		Groups: []types.Group{
			{DN: "CN=weak-group,DC=contoso,DC=com", Members: []string{"CN=svc.sql,DC=contoso,DC=com"}},
			{DN: "CN=strong-group,DC=contoso,DC=com", Members: []string{"CN=svc.sql,DC=contoso,DC=com"}},
		},
		FGPPs: []types.FGPP{
			{DN: "CN=weak-pso,DC=contoso,DC=com", Precedence: 5, MinPasswordLength: 8, AppliesTo: []string{"CN=weak-group,DC=contoso,DC=com"}},
			{DN: "CN=strong-pso,DC=contoso,DC=com", Precedence: 24, MinPasswordLength: 24, AppliesTo: []string{"CN=strong-group,DC=contoso,DC=com"}},
		},
	})
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (the weak 8-char PSO has the lower precedence (5 < 24) and wins)", f.Count)
	}
}

func TestServiceAccountPolicy_NameContainsService_Fires(t *testing.T) {
	f := detectServiceAccountPolicy(t, &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=backup-service-01,DC=contoso,DC=com", SAMAccountName: "backup-service-01"},
		},
	})
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (the \"service\" substring qualifies as a service account)", f.Count)
	}
}

// TestServiceAccountPolicy_OneCoveredTwoUncovered_CountsPerAccount is the
// regression guard for the existential-OR bug: with THREE active service
// accounts and only one covered by a 20-char PSO, Count must be 2 (the two
// uncovered accounts), each listed under AffectedEntities. Fails on the
// pre-fix code, which set count = 1 iff svcCount > 0 && !anyCovered: the one
// covered account (svc.sql) flipped anyCovered to true and made the whole
// finding report Count = 0, hiding svc.web and svc.backup entirely.
func TestServiceAccountPolicy_OneCoveredTwoUncovered_CountsPerAccount(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{DN: "CN=svc.sql,DC=example,DC=com", SAMAccountName: "svc.sql", ServicePrincipalNames: []string{"MSSQLSvc/db01:1433"}},
			{DN: "CN=svc.web,DC=example,DC=com", SAMAccountName: "svc.web", ServicePrincipalNames: []string{"HTTP/web01:443"}},
			{DN: "CN=svc.backup,DC=example,DC=com", SAMAccountName: "svc.backup", ServicePrincipalNames: []string{"HOST/backup01"}},
		},
		FGPPs: []types.FGPP{
			{DN: "CN=strong-pso,DC=example,DC=com", MinPasswordLength: 20, AppliesTo: []string{"CN=svc.sql,DC=example,DC=com"}},
		},
	}
	f := detectServiceAccountPolicy(t, data)
	if f.Count != 2 {
		t.Fatalf("Count = %d, want 2 (svc.web and svc.backup are not covered by any policy; svc.sql being covered must not mask them)", f.Count)
	}
	if len(f.AffectedEntities) != 2 {
		t.Fatalf("len(AffectedEntities) = %d, want 2 (one entry per uncovered account, svc.sql excluded)", len(f.AffectedEntities))
	}
}

// TestServiceAccountPolicy_DisabledServiceAccountExcluded is the regression
// guard for the missing Disabled guard: a disabled, uncovered service
// account must not be counted by the active detector - it is reported by
// ServiceAccountWeakPasswordPolicyOnDisabledAccountDetector instead. Fails
// on the pre-fix code, which never read u.Disabled and counted this account
// toward the active finding.
func TestServiceAccountPolicy_DisabledServiceAccountExcluded(t *testing.T) {
	f := detectServiceAccountPolicy(t, &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=svc.old,DC=example,DC=com", SAMAccountName: "svc.old", ServicePrincipalNames: []string{"HOST/old01"}, Disabled: true},
		},
	})
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (the only service account is disabled and must be excluded from the active detector)", f.Count)
	}
}
