// End-to-end proof that DISPLAY_SPECIFIER_CHANGES' 90-day window follows the
// audit's own reference clock (RunOptions.AsOf, with a time.Now() fallback
// when it is zero), not the wall clock at replay time. The fake provider
// below records the cutoff it actually receives from engine.Run, so the
// assertion is on what the engine computed, not on what the detector does
// with it.
package other_test

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	_ "github.com/etcsec-com/permtracer/internal/audit/detectors/ad/advanced/other"
	"github.com/etcsec-com/permtracer/internal/providers"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// dspProvider is a minimal LDAPProvider + ReplMetadataProvider +
// displaySpecifierProvider fake. GetDisplaySpecifierChangesSince records the
// cutoff it was called with, which is the only thing this test cares about.
type dspProvider struct {
	changedDNs     []string
	receivedCutoff time.Time
	calls          int
}

func (p *dspProvider) Type() providers.ProviderType  { return providers.ProviderTypeLDAP }
func (p *dspProvider) Connect(context.Context) error { return nil }
func (p *dspProvider) Close() error                  { return nil }
func (p *dspProvider) IsConnected() bool             { return true }

func (p *dspProvider) GetUsers(context.Context, providers.QueryOptions) ([]types.User, error) {
	return nil, nil
}
func (p *dspProvider) GetGroups(context.Context, providers.QueryOptions) ([]types.Group, error) {
	return nil, nil
}
func (p *dspProvider) GetComputers(context.Context, providers.QueryOptions) ([]types.Computer, error) {
	return nil, nil
}
func (p *dspProvider) GetDomainInfo(context.Context) (*types.DomainInfo, error) {
	return &types.DomainInfo{DomainName: "corp", DomainDN: "DC=corp,DC=local"}, nil
}

func (p *dspProvider) GetGPOs(context.Context, providers.QueryOptions) ([]types.GPO, error) {
	return nil, nil
}
func (p *dspProvider) GetOUs(context.Context, providers.QueryOptions) ([]types.OU, error) {
	return nil, nil
}
func (p *dspProvider) GetGPOLinks(context.Context) ([]audit.GPOLink, error) { return nil, nil }
func (p *dspProvider) GetGPOAcls(context.Context, []string) ([]audit.GPOAcl, error) {
	return nil, nil
}
func (p *dspProvider) GetTrusts(context.Context, providers.QueryOptions) ([]types.Trust, error) {
	return nil, nil
}
func (p *dspProvider) GetCertTemplates(context.Context, providers.QueryOptions) ([]types.CertTemplate, error) {
	return nil, nil
}
func (p *dspProvider) GetCertAuthorities(context.Context) ([]types.CertAuthority, error) {
	return nil, nil
}
func (p *dspProvider) GetACLs(context.Context, []string) ([]types.ACLEntry, map[string]string, error) {
	return nil, nil, nil
}
func (p *dspProvider) GetDNSZones(context.Context) ([]types.DNSZone, error) { return nil, nil }
func (p *dspProvider) GetFGPPs(context.Context) ([]types.FGPP, error)       { return nil, nil }
func (p *dspProvider) GetSitesAndSubnets(context.Context) ([]audit.Site, []audit.Subnet, error) {
	return nil, nil, nil
}
func (p *dspProvider) LookupBatch(context.Context, []string) ([]audit.ObjectLookupEntry, error) {
	return nil, nil
}
func (p *dspProvider) GetDCMetadata(context.Context, []types.Computer) (map[string]*audit.DCMetadata, error) {
	return nil, nil
}

func (p *dspProvider) GetReplMetadata(context.Context, string) ([]audit.ReplMetadataEntry, error) {
	return nil, nil
}
func (p *dspProvider) GetReplValueMetadata(context.Context, string) (map[string]time.Time, error) {
	return nil, nil
}

func (p *dspProvider) GetDisplaySpecifierChangesSince(_ context.Context, cutoff time.Time) ([]string, error) {
	p.calls++
	p.receivedCutoff = cutoff
	return p.changedDNs, nil
}

func runDSP(t *testing.T, provider *dspProvider, opts audit.RunOptions) *types.AuditResult {
	t.Helper()
	opts.DetectorIDs = []string{"DISPLAY_SPECIFIER_CHANGES"}
	engine := audit.NewEngine(audit.DefaultRegistry, provider)
	result, err := engine.Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("engine.Run returned an error: %v", err)
	}
	return result
}

func findingFor(result *types.AuditResult, detectorID string) *types.Finding {
	for i := range result.Findings {
		if result.Findings[i].Type == detectorID {
			return &result.Findings[i]
		}
	}
	return nil
}

// Case 1: a literal AsOf must produce a literal cutoff 90 days earlier - the
// engine's own reference clock, not the wall clock at replay time.
func TestDisplaySpecifierChanges_CutoffFollowsAsOf(t *testing.T) {
	asOf := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	wantCutoff := time.Date(2025, 10, 17, 0, 0, 0, 0, time.UTC)

	provider := &dspProvider{changedDNs: []string{"CN=409,CN=DisplaySpecifiers,CN=Configuration,DC=corp,DC=local"}}
	result := runDSP(t, provider, audit.RunOptions{AsOf: asOf})

	if provider.calls != 1 {
		t.Fatalf("GetDisplaySpecifierChangesSince was called %d times, want 1", provider.calls)
	}
	if !provider.receivedCutoff.Equal(wantCutoff) {
		t.Fatalf("cutoff received by the provider = %v, want %v (AsOf %v minus 90 days)",
			provider.receivedCutoff, wantCutoff, asOf)
	}

	f := findingFor(result, "DISPLAY_SPECIFIER_CHANGES")
	if f == nil {
		t.Fatal("no DISPLAY_SPECIFIER_CHANGES finding in result")
	}
	if f.Count != 1 {
		t.Fatalf("finding Count = %d, want 1", f.Count)
	}
}

// Case 2: with no AsOf, the cutoff must still be close to time.Now()-90d -
// the fallback path, not a frozen or wrong default.
func TestDisplaySpecifierChanges_CutoffFallsBackToWallClockWithoutAsOf(t *testing.T) {
	provider := &dspProvider{changedDNs: []string{"CN=409,CN=DisplaySpecifiers,CN=Configuration,DC=corp,DC=local"}}
	before := time.Now().AddDate(0, 0, -90)
	runDSP(t, provider, audit.RunOptions{})
	after := time.Now().AddDate(0, 0, -90)

	if provider.calls != 1 {
		t.Fatalf("GetDisplaySpecifierChangesSince was called %d times, want 1", provider.calls)
	}

	tolerance := time.Minute
	if provider.receivedCutoff.Before(before.Add(-tolerance)) || provider.receivedCutoff.After(after.Add(tolerance)) {
		t.Fatalf("cutoff %v is not within %v of time.Now()-90d (window [%v, %v])",
			provider.receivedCutoff, tolerance, before, after)
	}
}

// Case 3: no changed DN at all must mean no finding, since the detector's
// own finding.Count (len(data.DisplaySpecifierChanges)) is 0 and the engine
// drops zero-count findings before returning them.
func TestDisplaySpecifierChanges_NoChangesMeansNoFinding(t *testing.T) {
	provider := &dspProvider{changedDNs: nil}
	result := runDSP(t, provider, audit.RunOptions{})

	if provider.calls != 1 {
		t.Fatalf("GetDisplaySpecifierChangesSince was called %d times, want 1", provider.calls)
	}
	if f := findingFor(result, "DISPLAY_SPECIFIER_CHANGES"); f != nil {
		t.Fatalf("expected no DISPLAY_SPECIFIER_CHANGES finding, got one with Count=%d", f.Count)
	}
}
