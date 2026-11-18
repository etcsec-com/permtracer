package password

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// minServiceAccountPasswordLength is the minimum password length a Fine-
// Grained Password Policy (PSO) or the domain's default password policy must
// enforce for service accounts to count as covered.
const minServiceAccountPasswordLength = 20

// ServiceAccountPasswordPolicyDetector checks, for each ACTIVE service
// account independently, whether its RESULTANT password policy enforces at
// least minServiceAccountPasswordLength characters. Each account is counted
// on its own merits: one account covered by a strong policy never hides the
// others. The resultant policy follows AD's own RSOP precedence for
// Fine-Grained Password Policies (Microsoft Learn, "PSO precedence"): a PSO
// linked directly to the account, at the lowest Precedence value, wins
// outright; else a PSO linked to a group the account belongs to (including
// nested groups), at the lowest Precedence value, wins; else the domain's
// default password policy applies. PingCastle A-NoServicePolicy fires when
// neither a GPO nor a PSO enforces this; this detector evaluates the PSO and
// domain-default cases. The domain-default case reads minPwdLength off the
// domain object, which reflects whatever the Default Domain Policy GPO
// currently enforces - it is the one GPO-backed policy AD honors
// domain-wide, not a GPO-independent source. Limitation: service accounts
// are identified heuristically (SPN presence or naming convention), not via
// a dedicated managed-service-account attribute.
//
// Scoped to active accounts: a disabled account cannot authenticate, so the
// missing policy coverage on it is not usable today - see
// ServiceAccountWeakPasswordPolicyOnDisabledAccountDetector
// (service-account-weak-password-policy-on-disabled-account.go) for the
// disabled-account claim, reported separately at Low because policy
// coverage is a persistent configuration state that becomes relevant again
// the instant the account is re-enabled.
type ServiceAccountPasswordPolicyDetector struct {
	audit.BaseDetector
}

func NewServiceAccountPasswordPolicyDetector() *ServiceAccountPasswordPolicyDetector {
	return &ServiceAccountPasswordPolicyDetector{
		BaseDetector: audit.NewBaseDetector("SERVICE_ACCOUNT_WEAK_PASSWORD_POLICY", audit.CategoryPassword),
	}
}

// isLikelyServiceAccount detects service accounts by SPN presence or naming
// conventions (svc-, sa-, sql*, iis*, service*).
func isLikelyServiceAccount(u types.User) bool {
	if len(u.ServicePrincipalNames) > 0 {
		return true
	}
	lower := strings.ToLower(u.SAMAccountName)
	for _, prefix := range []string{"svc_", "svc-", "sa_", "sa-", "sql", "iis", "app"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return strings.Contains(lower, "service")
}

func (d *ServiceAccountPasswordPolicyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	groupsByDN := make(map[string]*types.Group, len(data.Groups))
	for i := range data.Groups {
		if dn := data.Groups[i].DN; dn != "" {
			groupsByDN[strings.ToLower(dn)] = &data.Groups[i]
		}
	}

	domainMinLength := 0
	if data.DomainInfo != nil {
		domainMinLength = data.DomainInfo.MinPasswordLength
	}

	svcCount := 0
	var affected []types.User
	for i := range data.Users {
		u := &data.Users[i]
		if u.Disabled {
			continue
		}
		if !isLikelyServiceAccount(*u) || u.DN == "" {
			continue
		}
		svcCount++
		if resultantMinPasswordLength(u.DN, data.FGPPs, groupsByDN, domainMinLength) < minServiceAccountPasswordLength {
			affected = append(affected, *u)
		}
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityMedium,
		Category: string(d.Category()),
		Title:    "No Strong Password Policy for Service Accounts",
		Description: "Active service accounts whose resultant password policy (Fine-Grained Password Policy " +
			"or the domain's default password policy) enforces a minimum password length below 20 " +
			"characters. Each service account is evaluated and counted independently: one account covered " +
			"by a strong policy does not hide the others. Service accounts should have long, complex " +
			"passwords since they cannot use MFA and are primary targets for Kerberoasting. Service " +
			"accounts are identified heuristically (SPN presence or naming convention), which may miss or " +
			"over-include accounts. Disabled service accounts are reported separately, since a disabled " +
			"account cannot authenticate today though the policy coverage persists across a re-enable.",
		Count: len(affected),
		Details: map[string]interface{}{
			"serviceAccountCount": svcCount,
			"recommendation": "Create a Fine-Grained Password Policy with MinPasswordLength >= 20 and apply it " +
				"(directly, or via a group including nested groups) to all service accounts, or raise the " +
				"domain's default minimum password length to 20 or more.",
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

// resultantMinPasswordLength computes the RSOP-style minimum password length
// that applies to accountDN: a PSO linked directly to the account, at the
// lowest Precedence value, wins outright over every other source; else a PSO
// linked to a group the account belongs to (transitively, nested groups
// included), at the lowest Precedence value, wins; else the domain's default
// password policy (domainMinLength) applies.
func resultantMinPasswordLength(accountDN string, fgpps []types.FGPP, groupsByDN map[string]*types.Group, domainMinLength int) int {
	lowerAccount := strings.ToLower(accountDN)

	haveDirect := false
	directPrecedence, directLength := 0, 0
	for _, fgpp := range fgpps {
		if !appliesToDirectly(fgpp.AppliesTo, lowerAccount) {
			continue
		}
		if !haveDirect || fgpp.Precedence < directPrecedence {
			haveDirect = true
			directPrecedence = fgpp.Precedence
			directLength = fgpp.MinPasswordLength
		}
	}
	if haveDirect {
		return directLength
	}

	haveGroup := false
	groupPrecedence, groupLength := 0, 0
	for _, fgpp := range fgpps {
		matches := false
		for _, applyDN := range fgpp.AppliesTo {
			if appliesTransitivelyViaGroup(applyDN, lowerAccount, groupsByDN) {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}
		if !haveGroup || fgpp.Precedence < groupPrecedence {
			haveGroup = true
			groupPrecedence = fgpp.Precedence
			groupLength = fgpp.MinPasswordLength
		}
	}
	if haveGroup {
		return groupLength
	}

	return domainMinLength
}

// appliesToDirectly reports whether lowerAccountDN (already lowercased)
// appears verbatim in a PSO's AppliesTo list.
func appliesToDirectly(appliesTo []string, lowerAccountDN string) bool {
	for _, dn := range appliesTo {
		if strings.ToLower(dn) == lowerAccountDN {
			return true
		}
	}
	return false
}

// appliesTransitivelyViaGroup reports whether lowerAccountDN (already
// lowercased) is a transitive member of the group at applyDN, walking nested
// groups with a visited set guarding against membership cycles.
func appliesTransitivelyViaGroup(applyDN, lowerAccountDN string, groupsByDN map[string]*types.Group) bool {
	start := strings.ToLower(applyDN)
	visited := map[string]bool{start: true}
	queue := []string{start}
	for len(queue) > 0 {
		dn := queue[0]
		queue = queue[1:]

		g, ok := groupsByDN[dn]
		if !ok {
			continue
		}
		for _, memberDN := range g.Members {
			lowerMember := strings.ToLower(memberDN)
			if lowerMember == lowerAccountDN {
				return true
			}
			if !visited[lowerMember] {
				visited[lowerMember] = true
				queue = append(queue, lowerMember)
			}
		}
	}
	return false
}

func init() {
	audit.MustRegister(NewServiceAccountPasswordPolicyDetector())
}
