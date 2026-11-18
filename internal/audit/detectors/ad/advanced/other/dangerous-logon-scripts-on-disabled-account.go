package other

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// DangerousLogonScriptsOnDisabledAccountDetector checks for disabled
// accounts whose logon script (scriptPath) references a network location.
// Split out of DangerousLogonScriptsDetector on the gabarit
// ASREP_ROASTING_RISK / ASREP_ROASTING_ON_DISABLED_ACCOUNT
// (public/internal/audit/detectors/ad/kerberos/): a disabled account cannot
// log on at all, so the logon script this attribute names is never
// executed for it today - but the attribute value stays readable on the
// object and would apply again the instant the account is re-enabled, so
// it stays reported, at a severity reflecting dormancy rather than active
// risk.
//
// Named DANGEROUS_LOGON_SCRIPTS_ON_DISABLED_ACCOUNT, not
// DANGEROUS_LOGON_SCRIPTS_DISABLED: the _DISABLED suffix is reserved
// elsewhere in this catalog for "a protection was turned off"
// (LDAP_SIGNING_DISABLED, TRUST_AES_DISABLED, ...), which reads as bad
// news. Naming the population instead of a mechanism state avoids an
// auditor misreading this as the risk itself being off.
type DangerousLogonScriptsOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewDangerousLogonScriptsOnDisabledAccountDetector creates a new detector
func NewDangerousLogonScriptsOnDisabledAccountDetector() *DangerousLogonScriptsOnDisabledAccountDetector {
	return &DangerousLogonScriptsOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("DANGEROUS_LOGON_SCRIPTS_ON_DISABLED_ACCOUNT", audit.CategoryAdvanced),
	}
}

// Detect executes the detection.
//
// Same path-substring heuristic as DangerousLogonScriptsDetector, applied
// only to accounts with u.Disabled == true. No normative source assigns a
// domain-level privilege or exposed secret to this attribute, so the
// severity grid's default (Low) applies rather than its Medium branch.
func (d *DangerousLogonScriptsOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if !u.Disabled {
			continue
		}
		if u.ScriptPath != "" {
			if strings.Contains(u.ScriptPath, "\\\\") || strings.HasPrefix(u.ScriptPath, "//") {
				affected = append(affected, u)
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Logon Script Configured With Network Path (Disabled Account)",
		Description: "This disabled account's logon script (scriptPath) references a network location (a UNC-style path) rather than a name resolved relative to NETLOGON. Not executable today - a disabled account cannot log on, so this script never runs - but the attribute value stays readable on the object and would apply again the instant the account is re-enabled. Like the active-account detector, this only inspects the path string; it does not read the file, share, or NTFS ACL protecting that script.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDangerousLogonScriptsOnDisabledAccountDetector())
}
