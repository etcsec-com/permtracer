package other

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestDCShadow_FlagsDCObjectOutsideStandardOU is a synthetic-data proof that
// DCSHADOW_EVIDENCE actually fires. The detector has never triggered on the
// lab (no plant/revert was ever attempted for a rogue-DC registration), so
// this test builds the two shapes of positive input the code looks for
// (a DomainControllers entry outside OU=Domain Controllers, and a Computer
// carrying the SERVER_TRUST_ACCOUNT UAC flag outside that OU) and confirms
// both are actually flagged, while a properly-placed DC is not.
func TestDCShadow_FlagsDCObjectOutsideStandardOU(t *testing.T) {
	legitDC := types.Computer{
		DN:                 "CN=DC01,OU=Domain Controllers,DC=example,DC=com",
		UserAccountControl: uacServerTrustAccountFlag,
	}
	rogueDC := types.Computer{
		DN:                 "CN=EVIL01,CN=Computers,DC=example,DC=com",
		UserAccountControl: uacServerTrustAccountFlag,
	}

	data := &audit.DetectorData{
		IncludeDetails:    true,
		DomainControllers: []types.Computer{legitDC, rogueDC},
		Computers:         []types.Computer{legitDC, rogueDC},
	}

	findings := NewDCShadowDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]

	if f.Count != 1 {
		t.Fatalf("expected Count=1 (only the rogue DC outside the standard OU), got %d", f.Count)
	}
	if len(f.AffectedEntities) != 1 || f.AffectedEntities[0].DN != rogueDC.DN {
		t.Fatalf("expected only %q flagged, got %+v", rogueDC.DN, f.AffectedEntities)
	}

	// The description must not overclaim full DCShadow forensic coverage -
	// it should disclose which MITRE-documented evidence classes are NOT
	// checked by this LDAP-snapshot-only heuristic.
	if !strings.Contains(f.Description, "T1207") {
		t.Fatalf("description does not cite MITRE ATT&CK T1207: %q", f.Description)
	}
	descLower := strings.ToLower(f.Description)
	if !strings.Contains(descLower, "does not") {
		t.Fatalf("description does not disclose the detector's partial coverage: %q", f.Description)
	}
}

// TestDCShadow_DoesNotFlagWhenAllDCsInStandardOU covers the negative case:
// no finding should be raised when every DC is correctly placed.
func TestDCShadow_DoesNotFlagWhenAllDCsInStandardOU(t *testing.T) {
	dc := types.Computer{
		DN:                 "CN=DC02,OU=Domain Controllers,DC=example,DC=com",
		UserAccountControl: uacServerTrustAccountFlag,
	}
	data := &audit.DetectorData{
		IncludeDetails:    true,
		DomainControllers: []types.Computer{dc},
		Computers:         []types.Computer{dc},
	}

	findings := NewDCShadowDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0, got %d (%+v)", findings[0].Count, findings[0].AffectedEntities)
	}
}

// TestDCShadow_MutationCoverage kills removal of the
// `!isInDomainControllersOU(dn)` guard on the Computers loop. Unlike the two
// tests above, it builds its fixtures with a hard-coded 0x2000 instead of the
// package constant uacServerTrustAccountFlag - a constant drift (e.g. the
// LAPS GUID incident) could not fail those tests structurally, since fixture
// and detector would still agree. It also sets DistinguishedName (not DN),
// the field the detector reads first, which the two tests above never
// exercise.
func TestDCShadow_MutationCoverage(t *testing.T) {
	t.Run("ComputerInStandardOU_NoFinding", func(t *testing.T) {
		data := &audit.DetectorData{
			IncludeDetails: true,
			Computers: []types.Computer{
				{
					DistinguishedName:  "CN=DC01,OU=Domain Controllers,DC=example,DC=com",
					UserAccountControl: 0x2000,
				},
			},
		}

		findings := NewDCShadowDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 0 {
			t.Fatalf("expected Count=0 (SERVER_TRUST_ACCOUNT computer inside the standard OU), got %d (%+v)", findings[0].Count, findings[0].AffectedEntities)
		}
	})

	t.Run("ComputerOutsideStandardOU_Fires", func(t *testing.T) {
		data := &audit.DetectorData{
			IncludeDetails: true,
			Computers: []types.Computer{
				{
					DistinguishedName:  "CN=EVIL02,CN=Computers,DC=example,DC=com",
					UserAccountControl: 0x2000,
				},
			},
		}

		findings := NewDCShadowDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 1 {
			t.Fatalf("expected Count=1 (SERVER_TRUST_ACCOUNT computer outside the standard OU), got %d (%+v)", findings[0].Count, findings[0].AffectedEntities)
		}
	})
}

// TestDCShadow_DisabledExcluded_DomainControllersLoop is the mutation kill
// for the DomainControllers loop's state guard: a disabled, misplaced DC
// must not fire here - it is reported instead, at Medium, by
// DCShadowOnDisabledAccountDetector. Isolates the DomainControllers loop
// (Computers left empty).
func TestDCShadow_DisabledExcluded_DomainControllersLoop(t *testing.T) {
	disabled := types.Computer{
		DN:                 "CN=DC70,CN=Computers,DC=example,DC=com",
		UserAccountControl: uacServerTrustAccountFlag,
		Disabled:           true,
	}
	data := &audit.DetectorData{DomainControllers: []types.Computer{disabled}}

	findings := NewDCShadowDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a disabled DC in the DomainControllers loop must not fire in the active detector", findings[0].Count)
	}
}

// TestDCShadow_DisabledExcluded_ComputersLoop is the mutation kill for the
// Computers loop's state guard: a disabled computer with the
// SERVER_TRUST_ACCOUNT bit, outside the standard OU, must not fire here.
// Isolates the Computers loop (DomainControllers left empty).
func TestDCShadow_DisabledExcluded_ComputersLoop(t *testing.T) {
	disabled := types.Computer{
		DN:                 "CN=DC71,CN=Computers,DC=example,DC=com",
		UserAccountControl: uacServerTrustAccountFlag,
		Disabled:           true,
	}
	data := &audit.DetectorData{Computers: []types.Computer{disabled}}

	findings := NewDCShadowDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a disabled computer in the Computers loop must not fire in the active detector", findings[0].Count)
	}
}

// TestDCShadow_OUSubterm_DistinguishedNameField is the mutation kill for
// the FIRST subterm of the DomainControllers loop's OU test
// (!isInDomainControllersOU(dc.DistinguishedName)): an active DC whose
// DistinguishedName field IS inside the standard OU, but whose DN field is
// NOT, must not fire - the DistinguishedName field alone is sufficient to
// mark it conforming.
func TestDCShadow_OUSubterm_DistinguishedNameField(t *testing.T) {
	dc := types.Computer{
		DistinguishedName:  "CN=DC80,OU=Domain Controllers,DC=example,DC=com",
		DN:                 "CN=DC80,CN=Computers,DC=example,DC=com",
		UserAccountControl: uacServerTrustAccountFlag,
	}
	data := &audit.DetectorData{DomainControllers: []types.Computer{dc}}

	findings := NewDCShadowDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: DistinguishedName field inside the DC OU must mark the object conforming", findings[0].Count)
	}
}

// TestDCShadow_OUSubterm_DNField is the mutation kill for the SECOND
// subterm of the DomainControllers loop's OU test
// (!isInDomainControllersOU(dc.DN)): an active DC whose DN field IS inside
// the standard OU, but whose DistinguishedName field is NOT (empty), must
// not fire.
func TestDCShadow_OUSubterm_DNField(t *testing.T) {
	dc := types.Computer{
		DistinguishedName:  "",
		DN:                 "CN=DC81,OU=Domain Controllers,DC=example,DC=com",
		UserAccountControl: uacServerTrustAccountFlag,
	}
	data := &audit.DetectorData{DomainControllers: []types.Computer{dc}}

	findings := NewDCShadowDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: DN field inside the DC OU must mark the object conforming", findings[0].Count)
	}
}

// TestDCShadow_BitAbsentNotCounted is the mutation kill for the Computers
// loop's SERVER_TRUST_ACCOUNT bit filter: an active computer WITHOUT the
// bit, outside any OU, must not be counted.
func TestDCShadow_BitAbsentNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:                 "CN=PC90,CN=Computers,DC=example,DC=com",
				UserAccountControl: 0,
			},
		},
	}

	findings := NewDCShadowDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a computer without the SERVER_TRUST_ACCOUNT bit must not be counted", findings[0].Count)
	}
}

// TestDCShadow_Dedup is the mutation kill for the `seen` deduplication: the
// same active, misplaced object present in BOTH DomainControllers and
// Computers must be counted exactly once.
func TestDCShadow_Dedup(t *testing.T) {
	dc := types.Computer{
		DN:                 "CN=EVIL91,CN=Computers,DC=example,DC=com",
		UserAccountControl: uacServerTrustAccountFlag,
	}
	data := &audit.DetectorData{
		DomainControllers: []types.Computer{dc},
		Computers:         []types.Computer{dc},
	}

	findings := NewDCShadowDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: the same object in both collections must be deduplicated", findings[0].Count)
	}
}

// TestDCShadow_SeverityIsCritical locks the active detector's severity
// (unchanged by this split - only the Disabled guard and the new twin are
// added).
func TestDCShadow_SeverityIsCritical(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:                 "CN=EVIL92,CN=Computers,DC=example,DC=com",
				UserAccountControl: uacServerTrustAccountFlag,
			},
		},
	}

	findings := NewDCShadowDetector().Detect(context.Background(), data)
	if findings[0].Severity != types.SeverityCritical {
		t.Fatalf("Severity = %q, want Critical", findings[0].Severity)
	}
}

// TestDCShadow_IncludeDetailsFalse_NoAffectedEntities is the mutation kill
// for the first IncludeDetails subterm: with IncludeDetails=false,
// AffectedEntities must stay nil even though an object is affected.
func TestDCShadow_IncludeDetailsFalse_NoAffectedEntities(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: false,
		Computers: []types.Computer{
			{
				DN:                 "CN=EVIL93,CN=Computers,DC=example,DC=com",
				UserAccountControl: uacServerTrustAccountFlag,
			},
		},
	}

	findings := NewDCShadowDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
	if findings[0].AffectedEntities != nil {
		t.Fatalf("AffectedEntities = %+v, want nil when IncludeDetails=false", findings[0].AffectedEntities)
	}
}

// TestDCShadow_IncludeDetailsTrue_NoAffected_NilEntities is the mutation
// kill for the second IncludeDetails subterm: with IncludeDetails=true but
// no affected object, AffectedEntities must stay nil (not a non-nil empty
// slice).
func TestDCShadow_IncludeDetailsTrue_NoAffected_NilEntities(t *testing.T) {
	data := &audit.DetectorData{IncludeDetails: true}

	findings := NewDCShadowDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
	if findings[0].AffectedEntities != nil {
		t.Fatalf("AffectedEntities = %+v, want nil when nothing is affected", findings[0].AffectedEntities)
	}
}

// TestDCShadow_OUCaseInsensitive_SubOU covers two shapes of
// isInDomainControllersOU not exercised by the existing tests above (which
// only use lowercase, exact-OU fixtures): an uppercase OU name, and a
// sub-OU of Domain Controllers, both accepted as conforming.
func TestDCShadow_OUCaseInsensitive_SubOU(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:                 "CN=DC94,OU=DOMAIN CONTROLLERS,DC=example,DC=com",
				UserAccountControl: uacServerTrustAccountFlag,
			},
			{
				DN:                 "CN=DC95,OU=Branch,OU=Domain Controllers,DC=example,DC=com",
				UserAccountControl: uacServerTrustAccountFlag,
			},
		},
	}

	findings := NewDCShadowDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: uppercase OU and a sub-OU of Domain Controllers must both be accepted as conforming", findings[0].Count)
	}
}
