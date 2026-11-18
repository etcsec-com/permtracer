package other

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestDCShadowOnDisabledAccount_DisabledMisplacedDCFires covers the nominal
// case: a DISABLED computer with the SERVER_TRUST_ACCOUNT flag, outside the
// standard OU, must be flagged here - mirrored across both the
// DomainControllers and Computers collections.
func TestDCShadowOnDisabledAccount_DisabledMisplacedDCFires(t *testing.T) {
	rogue := types.Computer{
		DN:                 "CN=EVIL01,CN=Computers,DC=example,DC=com",
		UserAccountControl: uacServerTrustAccountFlag,
		Disabled:           true,
	}
	data := &audit.DetectorData{
		IncludeDetails:    true,
		DomainControllers: []types.Computer{rogue},
		Computers:         []types.Computer{rogue},
	}

	findings := NewDCShadowOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (deduplicated across both collections)", f.Count)
	}
	if len(f.AffectedEntities) != 1 || f.AffectedEntities[0].DN != rogue.DN {
		t.Fatalf("expected only %q flagged, got %+v", rogue.DN, f.AffectedEntities)
	}
	if f.Severity != types.SeverityMedium {
		t.Errorf("severity = %q, want medium", f.Severity)
	}
}

// TestDCShadowOnDisabledAccount_ActiveExcluded_DomainControllersLoop is the
// guard's mutation kill on the DomainControllers loop: an ACTIVE DC with
// the exact same misplaced DN a disabled true positive would have must not
// fire here - it is reported instead, at Critical, by DCShadowDetector.
// Isolates the DomainControllers loop (Computers left empty).
func TestDCShadowOnDisabledAccount_ActiveExcluded_DomainControllersLoop(t *testing.T) {
	active := types.Computer{
		DN:                 "CN=DC10,CN=Computers,DC=example,DC=com",
		UserAccountControl: uacServerTrustAccountFlag,
	}
	data := &audit.DetectorData{
		IncludeDetails:    true,
		DomainControllers: []types.Computer{active},
	}

	findings := NewDCShadowOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: an active DC in the DomainControllers loop must not fire here", findings[0].Count)
	}
}

// TestDCShadowOnDisabledAccount_ActiveExcluded_ComputersLoop is the guard's
// mutation kill on the Computers loop: an ACTIVE computer with the
// SERVER_TRUST_ACCOUNT bit, outside the standard OU, must not fire here.
// Isolates the Computers loop (DomainControllers left empty).
func TestDCShadowOnDisabledAccount_ActiveExcluded_ComputersLoop(t *testing.T) {
	active := types.Computer{
		DN:                 "CN=DC11,CN=Computers,DC=example,DC=com",
		UserAccountControl: uacServerTrustAccountFlag,
	}
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers:      []types.Computer{active},
	}

	findings := NewDCShadowOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: an active computer in the Computers loop must not fire here", findings[0].Count)
	}
}

// TestDCShadowOnDisabledAccount_DisabledDCInOUNotFlagged covers the
// negative case: a disabled DC object correctly placed in the Domain
// Controllers OU must not fire.
func TestDCShadowOnDisabledAccount_DisabledDCInOUNotFlagged(t *testing.T) {
	dc := types.Computer{
		DN:                 "CN=DC04,OU=Domain Controllers,DC=example,DC=com",
		UserAccountControl: uacServerTrustAccountFlag,
		Disabled:           true,
	}
	data := &audit.DetectorData{
		IncludeDetails:    true,
		DomainControllers: []types.Computer{dc},
		Computers:         []types.Computer{dc},
	}

	findings := NewDCShadowOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a disabled DC correctly placed in the DC OU must not fire", findings[0].Count)
	}
}

// TestDCShadowOnDisabledAccount_OUSubterm_DistinguishedNameField is the
// mutation kill for the FIRST subterm of the DomainControllers loop's OU
// test (!isInDomainControllersOU(dc.DistinguishedName)): a disabled DC
// whose DistinguishedName field IS inside the standard OU, but whose DN
// field is NOT, must not fire - the DistinguishedName field alone is
// sufficient to mark it conforming.
func TestDCShadowOnDisabledAccount_OUSubterm_DistinguishedNameField(t *testing.T) {
	dc := types.Computer{
		DistinguishedName:  "CN=DC20,OU=Domain Controllers,DC=example,DC=com",
		DN:                 "CN=DC20,CN=Computers,DC=example,DC=com",
		UserAccountControl: uacServerTrustAccountFlag,
		Disabled:           true,
	}
	data := &audit.DetectorData{DomainControllers: []types.Computer{dc}}

	findings := NewDCShadowOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: DistinguishedName field inside the DC OU must mark the object conforming", findings[0].Count)
	}
}

// TestDCShadowOnDisabledAccount_OUSubterm_DNField is the mutation kill for
// the SECOND subterm of the DomainControllers loop's OU test
// (!isInDomainControllersOU(dc.DN)): a disabled DC whose DN field IS inside
// the standard OU, but whose DistinguishedName field is NOT (empty), must
// not fire.
func TestDCShadowOnDisabledAccount_OUSubterm_DNField(t *testing.T) {
	dc := types.Computer{
		DistinguishedName:  "",
		DN:                 "CN=DC21,OU=Domain Controllers,DC=example,DC=com",
		UserAccountControl: uacServerTrustAccountFlag,
		Disabled:           true,
	}
	data := &audit.DetectorData{DomainControllers: []types.Computer{dc}}

	findings := NewDCShadowOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: DN field inside the DC OU must mark the object conforming", findings[0].Count)
	}
}

// TestDCShadowOnDisabledAccount_BitAbsentNotCounted is the mutation kill
// for the Computers loop's SERVER_TRUST_ACCOUNT bit filter: a disabled
// computer WITHOUT the bit, outside any OU, must not be counted.
func TestDCShadowOnDisabledAccount_BitAbsentNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:                 "CN=PC30,CN=Computers,DC=example,DC=com",
				UserAccountControl: 0,
				Disabled:           true,
			},
		},
	}

	findings := NewDCShadowOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a disabled computer without the SERVER_TRUST_ACCOUNT bit must not be counted", findings[0].Count)
	}
}

// TestDCShadowOnDisabledAccount_ComputersLoop_OUSubterm is the mutation
// kill for the Computers loop's OU test (!isInDomainControllersOU(dn)): a
// disabled computer with the bit, correctly placed in the standard OU,
// must not be counted.
func TestDCShadowOnDisabledAccount_ComputersLoop_OUSubterm(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DistinguishedName:  "CN=DC31,OU=Domain Controllers,DC=example,DC=com",
				UserAccountControl: uacServerTrustAccountFlag,
				Disabled:           true,
			},
		},
	}

	findings := NewDCShadowOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a disabled SERVER_TRUST_ACCOUNT computer inside the standard OU must not be counted", findings[0].Count)
	}
}

// TestDCShadowOnDisabledAccount_Dedup is the mutation kill for the `seen`
// deduplication: the same disabled, misplaced object present in BOTH
// DomainControllers and Computers must be counted exactly once.
func TestDCShadowOnDisabledAccount_Dedup(t *testing.T) {
	dc := types.Computer{
		DN:                 "CN=EVIL40,CN=Computers,DC=example,DC=com",
		UserAccountControl: uacServerTrustAccountFlag,
		Disabled:           true,
	}
	data := &audit.DetectorData{
		DomainControllers: []types.Computer{dc},
		Computers:         []types.Computer{dc},
	}

	findings := NewDCShadowOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: the same object in both collections must be deduplicated", findings[0].Count)
	}
}

// TestDCShadowOnDisabledAccount_SeverityIsMedium locks the D1/D2-grid
// severity: the SERVER_TRUST_ACCOUNT bit keeps a domain-level privilege
// (DCSync-equivalent replication, native Domain Controllers group
// membership) attached to the object, exercisable again on re-enabling -
// see SPLIT.md.
func TestDCShadowOnDisabledAccount_SeverityIsMedium(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:                 "CN=EVIL41,CN=Computers,DC=example,DC=com",
				UserAccountControl: uacServerTrustAccountFlag,
				Disabled:           true,
			},
		},
	}

	findings := NewDCShadowOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Severity != types.SeverityMedium {
		t.Fatalf("Severity = %q, want Medium", findings[0].Severity)
	}
}

// TestDCShadowOnDisabledAccount_IncludeDetailsFalse_NoAffectedEntities is
// the mutation kill for the first IncludeDetails subterm: with
// IncludeDetails=false, AffectedEntities must stay nil even though an
// object is affected.
func TestDCShadowOnDisabledAccount_IncludeDetailsFalse_NoAffectedEntities(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: false,
		Computers: []types.Computer{
			{
				DN:                 "CN=EVIL42,CN=Computers,DC=example,DC=com",
				UserAccountControl: uacServerTrustAccountFlag,
				Disabled:           true,
			},
		},
	}

	findings := NewDCShadowOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
	if findings[0].AffectedEntities != nil {
		t.Fatalf("AffectedEntities = %+v, want nil when IncludeDetails=false", findings[0].AffectedEntities)
	}
}

// TestDCShadowOnDisabledAccount_IncludeDetailsTrue_NoAffected_NilEntities is
// the mutation kill for the second IncludeDetails subterm: with
// IncludeDetails=true but no affected object, AffectedEntities must stay
// nil (not a non-nil empty slice).
func TestDCShadowOnDisabledAccount_IncludeDetailsTrue_NoAffected_NilEntities(t *testing.T) {
	data := &audit.DetectorData{IncludeDetails: true}

	findings := NewDCShadowOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
	if findings[0].AffectedEntities != nil {
		t.Fatalf("AffectedEntities = %+v, want nil when nothing is affected", findings[0].AffectedEntities)
	}
}

// TestDCShadowOnDisabledAccount_OUCaseInsensitive_SubOU covers the two
// uncovered OU-matching shapes carried over from the active detector's
// test d'OU (same isInDomainControllersOU helper): an uppercase OU name,
// and a sub-OU of Domain Controllers, both accepted as conforming.
func TestDCShadowOnDisabledAccount_OUCaseInsensitive_SubOU(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:                 "CN=DC50,OU=DOMAIN CONTROLLERS,DC=example,DC=com",
				UserAccountControl: uacServerTrustAccountFlag,
				Disabled:           true,
			},
			{
				DN:                 "CN=DC51,OU=Branch,OU=Domain Controllers,DC=example,DC=com",
				UserAccountControl: uacServerTrustAccountFlag,
				Disabled:           true,
			},
		},
	}

	findings := NewDCShadowOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: uppercase OU and a sub-OU of Domain Controllers must both be accepted as conforming", findings[0].Count)
	}
}

// TestDCShadow_PartitionIsExhaustive covers both detectors together,
// against the condition evaluated with no Disabled guard at all: a
// matching object (SERVER_TRUST_ACCOUNT bit, outside the DC OU) is counted
// by exactly one of the two - active or disabled - never both, never
// neither.
func TestDCShadow_PartitionIsExhaustive(t *testing.T) {
	computers := []types.Computer{
		{DN: "CN=DC60,CN=Computers,DC=example,DC=com", UserAccountControl: uacServerTrustAccountFlag},
		{DN: "CN=DC61,CN=Computers,DC=example,DC=com", UserAccountControl: uacServerTrustAccountFlag, Disabled: true},
		{DN: "CN=DC62,OU=Domain Controllers,DC=example,DC=com", UserAccountControl: uacServerTrustAccountFlag},
		{DN: "CN=DC63,OU=Domain Controllers,DC=example,DC=com", UserAccountControl: uacServerTrustAccountFlag, Disabled: true},
		{DN: "CN=PC64,CN=Computers,DC=example,DC=com"},
	}
	data := &audit.DetectorData{Computers: computers, IncludeDetails: true}

	wantTotal := 2 // DC60 (active, misplaced), DC61 (disabled, misplaced)

	active := NewDCShadowDetector().Detect(context.Background(), data)
	disabled := NewDCShadowOnDisabledAccountDetector().Detect(context.Background(), data)

	if active[0].Count != 1 {
		t.Fatalf("active half: want 1 (DC60), got %d", active[0].Count)
	}
	if disabled[0].Count != 1 {
		t.Fatalf("disabled half: want 1 (DC61), got %d", disabled[0].Count)
	}
	if got := active[0].Count + disabled[0].Count; got != wantTotal {
		t.Fatalf("active + disabled = %d, want %d (exact partition of the ungated condition)", got, wantTotal)
	}
}
