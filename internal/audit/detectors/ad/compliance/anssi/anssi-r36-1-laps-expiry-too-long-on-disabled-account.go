package anssi

import (
	"context"
	"fmt"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// R361LAPSExpiryOnDisabledAccountDetector checks for disabled computer
// accounts whose LAPS password expiry is beyond the product benchmark.
// Split out of R361LAPSExpiryDetector, on the same model as
// COMPUTER_NO_LAPS/_ON_DISABLED_ACCOUNT: a disabled computer account cannot
// authenticate, so a stale LAPS rotation on it is not an active risk today -
// but it is not the same thing as the risk disappearing. The local
// administrator password stays expired beyond the benchmark, and the
// rotation delay is exactly as relevant as before the instant the account is
// re-enabled, without any rotation having happened in the meantime - a
// dormant configuration residue, not a live administrative surface.
type R361LAPSExpiryOnDisabledAccountDetector struct{ audit.BaseDetector }

func NewR361LAPSExpiryOnDisabledAccountDetector() *R361LAPSExpiryOnDisabledAccountDetector {
	return &R361LAPSExpiryOnDisabledAccountDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R36_1_LAPS_EXPIRY_TOO_LONG_ON_DISABLED_ACCOUNT", audit.CategoryCompliance)}
}

func (d *R361LAPSExpiryOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	threshold := data.Now.AddDate(0, 0, lapsMaxExpiryDaysBenchmark)
	var stale []types.Computer
	for _, c := range data.Computers {
		if c.Enabled() {
			continue // only disabled computers are counted here - the enabled population is ANSSI_R36_1_LAPS_EXPIRY_TOO_LONG
		}
		if c.LAPSPasswordExpiry.IsZero() {
			continue // computer outside LAPS scope - not in scope of this check
		}
		if c.LAPSPasswordExpiry.After(threshold) {
			stale = append(stale, c)
		}
	}
	if len(stale) == 0 {
		return nil
	}
	return wrapFinding(d, "LAPS password expiry beyond product benchmark (30 days) (Disabled Account)",
		fmt.Sprintf("%d disabled computer(s) have a LAPS expiry timestamp more than %d days in the future - beyond the legacy LAPS default and PermTracer's product benchmark for 'rotation interval too long'. Not exploitable while disabled - the account cannot authenticate - but the stale rotation remains and would apply again if the account is re-enabled.", len(stale), lapsMaxExpiryDaysBenchmark),
		types.SeverityLow, len(stale), computersToEntities(stale, data.IncludeDetails))
}

func init() {
	audit.MustRegister(NewR361LAPSExpiryOnDisabledAccountDetector())
}
