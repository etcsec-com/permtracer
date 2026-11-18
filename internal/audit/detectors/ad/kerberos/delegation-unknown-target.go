package kerberos

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/internal/audit/helpers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// DelegationUnknownTargetDetector checks for constrained delegation to SPNs that don't resolve to known computers
type DelegationUnknownTargetDetector struct {
	audit.BaseDetector
}

// NewDelegationUnknownTargetDetector creates a new detector
func NewDelegationUnknownTargetDetector() *DelegationUnknownTargetDetector {
	return &DelegationUnknownTargetDetector{
		BaseDetector: audit.NewBaseDetector("DELEGATION_UNKNOWN_TARGET", audit.CategoryKerberos),
	}
}

// Detect executes the detection
func (d *DelegationUnknownTargetDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	knownHosts := buildKnownDelegationHosts(data.Computers)

	var affected []types.User
	unknownTargets := make(map[string][]string) // user → unknown SPNs

	for _, u := range data.Users {
		if u.Disabled {
			continue
		}
		if len(u.AllowedToDelegateTo) == 0 {
			continue
		}
		unknownSPNs := unknownDelegationSPNs(u.AllowedToDelegateTo, knownHosts)
		if len(unknownSPNs) > 0 {
			affected = append(affected, u)
			unknownTargets[u.SAMAccountName] = unknownSPNs
		}
	}

	// Also check computers with constrained delegation
	var affectedComputers []types.Computer
	for _, c := range data.Computers {
		if c.Disabled {
			continue
		}
		if len(c.AllowedToDelegateTo) == 0 {
			continue
		}
		unknownSPNs := unknownDelegationSPNs(c.AllowedToDelegateTo, knownHosts)
		if len(unknownSPNs) > 0 {
			affectedComputers = append(affectedComputers, c)
			unknownTargets[c.SAMAccountName] = unknownSPNs
		}
	}

	totalCount := len(affected) + len(affectedComputers)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Constrained Delegation to Unknown Target",
		Description: "Active accounts with constrained delegation configured to SPNs whose target hostname does not match any known computer in Active Directory. This may indicate stale delegation entries pointing to decommissioned servers, or delegation to external/unknown systems. Attackers could potentially register a machine with the missing hostname to intercept delegated credentials.",
		Count:       totalCount,
	}

	if data.IncludeDetails && totalCount > 0 {
		var entities []types.AffectedEntity
		if len(affected) > 0 {
			entities = append(entities, helpers.ToAffectedUserEntities(affected)...)
		}
		if len(affectedComputers) > 0 {
			entities = append(entities, helpers.ToAffectedComputerEntities(affectedComputers)...)
		}
		finding.AffectedEntities = entities
		finding.Details = map[string]interface{}{
			"unknownTargets": unknownTargets,
		}
	}

	return []types.Finding{finding}
}

// extractHostFromSPN extracts the hostname from a SPN. The Microsoft SPN
// format is serviceclass/host:port/servicename - the trailing "/servicename"
// component is optional and must be stripped along with the port, or a
// three-part SPN to a known computer is misread as an unknown target.
func extractHostFromSPN(spn string) string {
	parts := strings.SplitN(spn, "/", 2)
	if len(parts) < 2 {
		return ""
	}
	host := parts[1]
	// Drop an optional third component (e.g., "server/servicename")
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	// Remove port if present (e.g., "server:1433")
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return host
}

// buildKnownDelegationHosts returns the set of computer DNS hostnames and
// SAMAccountNames known in the domain, lowercased. It is built from every
// computer in data.Computers regardless of that computer's own Disabled
// state: resolving a delegation target depends only on whether the host
// exists in the domain, not on whether it happens to be active. Extracted so
// the active detector and its DELEGATION_UNKNOWN_TARGET_ON_DISABLED_ACCOUNT
// twin share one implementation instead of each keeping its own copy.
func buildKnownDelegationHosts(computers []types.Computer) map[string]bool {
	knownHosts := make(map[string]bool)
	for _, c := range computers {
		if c.DNSHostName != "" {
			knownHosts[strings.ToLower(c.DNSHostName)] = true
		}
		if c.SAMAccountName != "" {
			// Strip trailing $ from computer account name
			name := strings.TrimSuffix(strings.ToLower(c.SAMAccountName), "$")
			knownHosts[name] = true
		}
	}
	return knownHosts
}

// unknownDelegationSPNs returns the SPNs in allowedToDelegateTo whose
// resolved host is not present in knownHosts. Extracted so the active
// detector and its DELEGATION_UNKNOWN_TARGET_ON_DISABLED_ACCOUNT twin share
// one implementation of "unknown target" instead of each keeping its own
// copy.
func unknownDelegationSPNs(allowedToDelegateTo []string, knownHosts map[string]bool) []string {
	var unknownSPNs []string
	for _, spn := range allowedToDelegateTo {
		host := extractHostFromSPN(spn)
		if host == "" {
			continue
		}
		hostLower := strings.ToLower(host)
		if !knownHosts[hostLower] {
			unknownSPNs = append(unknownSPNs, spn)
		}
	}
	return unknownSPNs
}

func init() {
	audit.MustRegister(NewDelegationUnknownTargetDetector())
}
