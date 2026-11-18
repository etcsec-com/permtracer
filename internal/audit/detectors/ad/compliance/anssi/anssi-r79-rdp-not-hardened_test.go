package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// --- R79 relabeling + no-data false positive ---

// TestR79RDPHardened_NoDataAtAll_NoFalsePositive: with no
// GPOPolicies at all (SMB/SYSVOL not collected), both the highEnc and rpcEnc
// signals default to false, and the detector used to report a guaranteed
// "not hardened" finding indistinguishable from a real violation. Absence of
// evidence must not be reported as a violation (same principle as the R4/R13
// no-data fix in r4-logging.go).
func TestR79RDPHardened_NoDataAtAll_NoFalsePositive(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: nil}
	d := NewR79RDPHardenedDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding when no GPO data was collected at all, got %+v", findings)
	}
}

// TestR79RDPHardened_WeakSettingsPresent_StillFlagged is the regression
// check: when GPO data IS present and genuinely doesn't set the required
// encryption, the finding must still fire.
func TestR79RDPHardened_WeakSettingsPresent_StillFlagged(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {RegistrySettings: &audit.RegistrySettings{}},
	}}
	d := NewR79RDPHardenedDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count == 0 {
		t.Fatalf("expected a flagged finding, got %+v", findings)
	}
}

// TestR79RDPHardened_DoesNotClaimANSSIR79: this detector checks
// server-side RDP encryption (MinEncryptionLevel/fEncryptRPCTraffic), but
// ANSSI R79 (p.104-105) is about hardening the RDP CLIENT (graphics
// acceleration, clipboard/smart-card redirection) - an entirely different,
// uncollected set of settings. The finding must not attribute this check to
// R79.
func TestR79RDPHardened_DoesNotClaimANSSIR79(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {RegistrySettings: &audit.RegistrySettings{}},
	}}
	d := NewR79RDPHardenedDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	title := findings[0].Title
	if strings.Contains(title, "R79") {
		t.Errorf("title still attributes this check to ANSSI R79: %q", title)
	}
	if !strings.Contains(findings[0].Description, "NOT a measurement of ANSSI R79") {
		t.Errorf("description should explicitly disclaim R79 attribution, got %q", findings[0].Description)
	}
}

// TestR79RDPHardened_DescriptionHasNoEmptyFragment proves the
// catalog-vs-runtime text fix: the previous "Missing GPO setting(s): "+
// strings.Join(missing, "; ")+"." concatenation lost the dynamic missing-settings
// list entirely once cataloggen extracted the static literal for the catalog,
// leaving "setting(s): ." there - but the fix must not regress the runtime
// Description either, which has to keep reporting the actual missing settings.
func TestR79RDPHardened_DescriptionHasNoEmptyFragment(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {RegistrySettings: &audit.RegistrySettings{}},
	}}
	d := NewR79RDPHardenedDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	desc := findings[0].Description
	if strings.Contains(desc, "setting(s): .") {
		t.Errorf("description contains the empty-fragment pattern 'setting(s): .': %q", desc)
	}
	if !strings.Contains(desc, "MinEncryptionLevel") {
		t.Errorf("description dropped the dynamic missing-settings list: %q", desc)
	}
}

// --- RPC-only / MinEncryptionLevel-only branches, split-GPO case, threshold
// boundaries, nil guards, Severity/Count ---

// TestR79RDPHardened_RPCTrafficOnly_Flagged is Branch 3: only
// RDPEncryptRPCTraffic is set to the compliant value (1), MinEncryptionLevel
// is left unset. rpcEnc is true and highEnc is false, so the finding must
// still fire (:67-69) and the Description must cite ONLY the missing
// MinEncryptionLevel setting, not fEncryptRPCTraffic (:71-76).
func TestR79RDPHardened_RPCTrafficOnly_Flagged(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {RegistrySettings: &audit.RegistrySettings{RDPEncryptRPCTraffic: intPtr(1)}},
	}}
	d := NewR79RDPHardenedDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected 1 flagged finding with Count 1, got %+v", findings)
	}
	desc := findings[0].Description
	if !strings.Contains(desc, "MinEncryptionLevel") {
		t.Errorf("description should cite the missing MinEncryptionLevel setting, got %q", desc)
	}
	if strings.Contains(desc, "fEncryptRPCTraffic") {
		t.Errorf("description should NOT cite fEncryptRPCTraffic, since it was already satisfied: %q", desc)
	}
}

// TestR79RDPHardened_MinEncryptionLevelOnly_Flagged is Branch 4: only
// RDPMinEncryptionLevel is set to the compliant value (3), fEncryptRPCTraffic
// is left unset. highEnc is true and rpcEnc is false, so the finding must
// still fire and the Description must cite ONLY the missing
// fEncryptRPCTraffic setting, not MinEncryptionLevel.
func TestR79RDPHardened_MinEncryptionLevelOnly_Flagged(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {RegistrySettings: &audit.RegistrySettings{RDPMinEncryptionLevel: intPtr(3)}},
	}}
	d := NewR79RDPHardenedDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected 1 flagged finding with Count 1, got %+v", findings)
	}
	desc := findings[0].Description
	if !strings.Contains(desc, "fEncryptRPCTraffic") {
		t.Errorf("description should cite the missing fEncryptRPCTraffic setting, got %q", desc)
	}
	if strings.Contains(desc, "MinEncryptionLevel") {
		t.Errorf("description should NOT cite MinEncryptionLevel, since it was already satisfied: %q", desc)
	}
}

// TestR79RDPHardened_SplitAcrossTwoGPOs_NotFlagged is Branch 5: one GPO sets
// MinEncryptionLevel=3 and a SEPARATE GPO sets fEncryptRPCTraffic=1. Since
// highEnc and rpcEnc are accumulated across ALL GPOPolicies in the same
// loop (:52-63), both end up true even though no single GPO enforces both
// settings, and the detector must not flag (:67-69).
func TestR79RDPHardened_SplitAcrossTwoGPOs_NotFlagged(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo-enc}": {RegistrySettings: &audit.RegistrySettings{RDPMinEncryptionLevel: intPtr(3)}},
		"{gpo-rpc}": {RegistrySettings: &audit.RegistrySettings{RDPEncryptRPCTraffic: intPtr(1)}},
	}}
	d := NewR79RDPHardenedDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding when the two settings are split across two different GPOs, got %+v", findings)
	}
}

// TestR79RDPHardened_BothSettingsOnSameGPO_NotFlagged is the companion of
// Branch 5: both compliant settings on the SAME GPO must also clear the
// finding.
func TestR79RDPHardened_BothSettingsOnSameGPO_NotFlagged(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {RegistrySettings: &audit.RegistrySettings{
			RDPMinEncryptionLevel: intPtr(3),
			RDPEncryptRPCTraffic:  intPtr(1),
		}},
	}}
	d := NewR79RDPHardenedDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding when both settings are compliant on the same GPO, got %+v", findings)
	}
}

// TestR79RDPHardened_MinEncryptionLevelJustBelowThreshold_StillFlagged pins
// the ">= 3" threshold (:57) against a boundary-shift mutation (e.g. ">= 2"):
// MinEncryptionLevel=2 (just below the required high-encryption value of 3)
// must leave highEnc false, with fEncryptRPCTraffic compliant (1) to isolate
// the MinEncryptionLevel branch of `missing`.
func TestR79RDPHardened_MinEncryptionLevelJustBelowThreshold_StillFlagged(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {RegistrySettings: &audit.RegistrySettings{
			RDPMinEncryptionLevel: intPtr(2),
			RDPEncryptRPCTraffic:  intPtr(1),
		}},
	}}
	d := NewR79RDPHardenedDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected a flagged finding for MinEncryptionLevel=2 (below the required 3), got %+v", findings)
	}
	desc := findings[0].Description
	if !strings.Contains(desc, "MinEncryptionLevel") {
		t.Errorf("description should cite the still-missing MinEncryptionLevel setting, got %q", desc)
	}
	if strings.Contains(desc, "fEncryptRPCTraffic") {
		t.Errorf("fEncryptRPCTraffic was compliant and should not be cited: %q", desc)
	}
}

// TestR79RDPHardened_RPCTrafficJustBelowThreshold_StillFlagged pins the
// ">= 1" threshold (:60) against a boundary-shift mutation (e.g. ">= 0"):
// fEncryptRPCTraffic=0 (just below the required value of 1) must leave
// rpcEnc false, with MinEncryptionLevel compliant (3) to isolate the
// fEncryptRPCTraffic branch of `missing`.
func TestR79RDPHardened_RPCTrafficJustBelowThreshold_StillFlagged(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {RegistrySettings: &audit.RegistrySettings{
			RDPMinEncryptionLevel: intPtr(3),
			RDPEncryptRPCTraffic:  intPtr(0),
		}},
	}}
	d := NewR79RDPHardenedDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected a flagged finding for fEncryptRPCTraffic=0 (below the required 1), got %+v", findings)
	}
	desc := findings[0].Description
	if !strings.Contains(desc, "fEncryptRPCTraffic") {
		t.Errorf("description should cite the still-missing fEncryptRPCTraffic setting, got %q", desc)
	}
	if strings.Contains(desc, "MinEncryptionLevel") {
		t.Errorf("MinEncryptionLevel was compliant and should not be cited: %q", desc)
	}
}

// TestR79RDPHardened_NilGuards_MixedEntries_NoPanicAndStillFlagged exercises
// all three nil-shaped inputs together in one map, so Go's randomized map
// iteration order cannot hide a guard mutation behind a lucky order:
//   - a nil *audit.GPOPolicy map entry (guard `p == nil`, :53);
//   - a non-nil GPOPolicy with a nil RegistrySettings (guard
//     `p.RegistrySettings == nil`, :53);
//   - a non-nil RegistrySettings whose two relevant fields are both nil
//     (must still set sawAnyRegistrySettings, :56, and leave highEnc/rpcEnc
//     false since the nil-pointer checks at :57/:60 guard the dereference).
//
// Removing either guard subterm, or flipping `||` to `&&`, makes the nil
// *audit.GPOPolicy entry (or the nil-RegistrySettings entry once p is
// dereferenced unguarded) panic on a nil pointer dereference instead of
// being skipped.
func TestR79RDPHardened_NilGuards_MixedEntries_NoPanicAndStillFlagged(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{nil-entry}":         nil,
		"{nil-regsettings}":   {RegistrySettings: nil},
		"{empty-regsettings}": {RegistrySettings: &audit.RegistrySettings{}},
	}}
	d := NewR79RDPHardenedDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected sawAnyRegistrySettings to stay true from the one real empty RegistrySettings entry and flag, got %+v", findings)
	}
	desc := findings[0].Description
	if !strings.Contains(desc, "MinEncryptionLevel") || !strings.Contains(desc, "fEncryptRPCTraffic") {
		t.Errorf("both settings were unset on the only real entry, both should be cited as missing: %q", desc)
	}
}

// TestR79RDPHardened_SeverityMediumAndCountOne asserts the literal finding
// shape (:79): Severity must be medium and Count must be 1 - neither is
// asserted by any pre-existing test, so a mutation on either literal
// (Severity to another level, or Count to 0/2) previously survived silently.
func TestR79RDPHardened_SeverityMediumAndCountOne(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {RegistrySettings: &audit.RegistrySettings{}},
	}}
	d := NewR79RDPHardenedDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityMedium {
		t.Errorf("Severity = %q, want %q", findings[0].Severity, types.SeverityMedium)
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1", findings[0].Count)
	}
}
