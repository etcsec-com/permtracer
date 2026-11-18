package password

import (
	"context"
	"regexp"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// CommonPatternsOnDisabledAccountDetector checks for disabled accounts
// whose name matches a pattern suggesting a default or weak password.
// Split out of CommonPatternsDetector: a disabled account cannot obtain a
// ticket and cannot authenticate, so a predictable name on it is not
// usable for a password-spraying attempt today. SAMAccountName is a
// persistent attribute of the object, though, that does not change when
// the account is disabled, so the signal becomes active again the instant
// the account is re-enabled.
//
// Named PASSWORD_COMMON_PATTERNS_ON_DISABLED_ACCOUNT, not
// PASSWORD_COMMON_PATTERNS_DISABLED: the _DISABLED suffix is reserved
// elsewhere in this catalog for "a protection was turned off", which reads
// as good news. Naming the population instead of a mechanism state avoids
// an auditor misreading this as the risk itself being off.
type CommonPatternsOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewCommonPatternsOnDisabledAccountDetector creates a new detector
func NewCommonPatternsOnDisabledAccountDetector() *CommonPatternsOnDisabledAccountDetector {
	return &CommonPatternsOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("PASSWORD_COMMON_PATTERNS_ON_DISABLED_ACCOUNT", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *CommonPatternsOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Patterns that suggest default or weak passwords
	riskyNamePatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)^admin$`),
		regexp.MustCompile(`(?i)^administrator$`),
		regexp.MustCompile(`(?i)^test$`),
		regexp.MustCompile(`(?i)^user$`),
		regexp.MustCompile(`(?i)^guest$`),
		regexp.MustCompile(`(?i)^temp$`),
		regexp.MustCompile(`(?i)^default$`),
		regexp.MustCompile(`(?i)^support$`),
		regexp.MustCompile(`(?i)^service$`),
		regexp.MustCompile(`(?i)^backup$`),
		regexp.MustCompile(`(?i)^demo$`),
		regexp.MustCompile(`(?i)password`),
		regexp.MustCompile(`123$`),
		regexp.MustCompile(`(?i)^sa$`),
		regexp.MustCompile(`(?i)^dba$`),
	}

	var affected []types.User
	var affectedNames []string

	for _, u := range data.Users {
		// Must be disabled
		if !u.Disabled {
			continue
		}

		samName := strings.ToLower(u.SAMAccountName)
		for _, pattern := range riskyNamePatterns {
			if pattern.MatchString(samName) {
				affected = append(affected, u)
				if len(affectedNames) < 10 {
					affectedNames = append(affectedNames, u.SAMAccountName)
				}
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Common Password Pattern Risk (Disabled Account)",
		Description: "Disabled user accounts with names suggesting default or commonly-used passwords (admin, test, user, temp). A disabled account cannot obtain a ticket and cannot authenticate, but SAMAccountName is a persistent attribute of the object that does not change when the account is disabled, and the signal becomes active again the instant the account is re-enabled.",
		Count:       len(affected),
		Details: map[string]interface{}{
			"affectedAccountNames": affectedNames,
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewCommonPatternsOnDisabledAccountDetector())
}
