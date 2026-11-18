package password

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// ServiceAccountWeakPasswordPolicyOnDisabledAccountDetector checks, for each
// DISABLED service account independently, whether its RESULTANT password
// policy enforces at least minServiceAccountPasswordLength characters. Split
// out of ServiceAccountPasswordPolicyDetector: a disabled account cannot
// authenticate, so the missing policy coverage on it is not usable today -
// but policy coverage (which PSO applies, if any) is a persistent
// configuration state that does not change when the account is disabled,
// and the signal becomes active again the instant the account is
// re-enabled.
//
// Named SERVICE_ACCOUNT_WEAK_PASSWORD_POLICY_ON_DISABLED_ACCOUNT, not
// ..._DISABLED: the _DISABLED suffix is reserved elsewhere in this catalog
// for "a protection was turned off", which reads as good news. Naming the
// population instead of a mechanism state avoids an auditor misreading this
// as the risk itself being off.
type ServiceAccountWeakPasswordPolicyOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewServiceAccountWeakPasswordPolicyOnDisabledAccountDetector creates a new detector
func NewServiceAccountWeakPasswordPolicyOnDisabledAccountDetector() *ServiceAccountWeakPasswordPolicyOnDisabledAccountDetector {
	return &ServiceAccountWeakPasswordPolicyOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("SERVICE_ACCOUNT_WEAK_PASSWORD_POLICY_ON_DISABLED_ACCOUNT", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *ServiceAccountWeakPasswordPolicyOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
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
		if !u.Disabled {
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
		Severity: types.SeverityLow,
		Category: string(d.Category()),
		Title:    "No Strong Password Policy for Service Accounts (Disabled Account)",
		Description: "Disabled service accounts whose resultant password policy (Fine-Grained Password " +
			"Policy or the domain's default password policy) enforces a minimum password length below 20 " +
			"characters. Each service account is evaluated and counted independently. Not usable while " +
			"disabled - a disabled account cannot authenticate - but the policy coverage is a persistent " +
			"configuration state that survives a re-enable, and the account becomes exploitable again the " +
			"instant it is reactivated. Service accounts are identified heuristically (SPN presence or " +
			"naming convention), which may miss or over-include accounts.",
		Count: len(affected),
		Details: map[string]interface{}{
			"serviceAccountCount": svcCount,
			"recommendation": "Create a Fine-Grained Password Policy with MinPasswordLength >= 20 and apply it " +
				"(directly, or via a group including nested groups) to all service accounts, or raise the " +
				"domain's default minimum password length to 20 or more, before any of these accounts are " +
				"re-enabled.",
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewServiceAccountWeakPasswordPolicyOnDisabledAccountDetector())
}
