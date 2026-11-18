package other

import (
	"context"
	"regexp"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// DescriptionSensitiveDetector checks for sensitive data in computer
// descriptions.
//
// Disabled computer accounts are excluded here and reported instead, at
// Medium, by DescriptionSensitiveOnDisabledAccountDetector (see
// description-sensitive-on-disabled-account.go): the description field
// stays readable to any identity with ordinary directory-read access
// regardless of the object's disabled state, so the split is on
// severity grouping, not on whether the exposure applies.
type DescriptionSensitiveDetector struct {
	audit.BaseDetector
}

// NewDescriptionSensitiveDetector creates a new detector
func NewDescriptionSensitiveDetector() *DescriptionSensitiveDetector {
	return &DescriptionSensitiveDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_DESCRIPTION_SENSITIVE", audit.CategoryComputers),
	}
}

// This is a product heuristic, not a requirement from any named
// standard; no external attribution is made here beyond that. The third
// pattern used to be `(?i)admin|root|sa` with no word-boundary anchoring:
// "sa" as a bare substring matched inside "diSAbled", "neceSSAry", and any
// other word merely containing those two letters - both flagged findings
// observed against real data were exactly this false-positive shape, not
// an actual admin/root/sa credential hint. Anchoring with \b applies the
// same fix to "admin" and "root", which had the identical substring risk
// (e.g. "administered", "uproot").
var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)password|passwd|pwd`),
	regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`), // IP addresses
	regexp.MustCompile(`(?i)\b(admin|root|sa)\b`),
}

// Detect executes the detection
func (d *DescriptionSensitiveDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if c.Disabled {
			continue
		}
		if c.Description == "" {
			continue
		}
		for _, pattern := range sensitivePatterns {
			if pattern.MatchString(c.Description) {
				affected = append(affected, c)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Computer Description Sensitive",
		Description: "Computer description contains sensitive data (passwords, IPs, etc.). Information disclosure.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDescriptionSensitiveDetector())
}
