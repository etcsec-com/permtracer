package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// Built-in Guest account (RID 501) left enabled. This is a general
// account-hygiene control, not a numbered ANSSI PA-099 recommendation:
// PA-099's full text contains no mention of the Guest account and no
// decimal sub-recommendation numbering at all, so there is no PA-099
// control to cite here.
//
// v3.1.21 dedup - ANSSI_R2_1_BUILTIN_ADMIN_NOT_RENAMED removed (same check
// as M12_DEFAULT_ADMIN_NOT_RENAMED). Mapping migrated (M12 now maps to
// both GP-042 M12 and PA-099 R44).

// --- Guest account enabled ---

type R22GuestEnabledDetector struct{ audit.BaseDetector }

func NewR22GuestEnabledDetector() *R22GuestEnabledDetector {
	return &R22GuestEnabledDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R2_2_GUEST_ENABLED", audit.CategoryCompliance)}
}
func (d *R22GuestEnabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	count := 0
	for _, u := range data.Users {
		if strings.HasSuffix(u.ObjectSID, "-501") && !u.Disabled {
			count = 1
			break
		}
	}
	return wrapFinding(d, "Built-in Guest Account Enabled",
		"The built-in Guest account (well-known RID 501) is enabled and should be permanently disabled. This is a standard account-hygiene control; it is not tied to any specific ANSSI PA-099 recommendation number.",
		types.SeverityHigh, count, nil)
}

func init() {
	audit.MustRegister(NewR22GuestEnabledDetector())
}
