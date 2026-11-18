package organization

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestDCInventory_NoDomainControllers_ReturnsNil covers the empty-population
// branch: no DC collected, no finding emitted.
func TestDCInventory_NoDomainControllers_ReturnsNil(t *testing.T) {
	data := &audit.DetectorData{}

	findings := NewDomainControllerInventoryDetector().Detect(context.Background(), data)
	if findings != nil {
		t.Fatalf("expected nil findings for empty DC population, got %#v", findings)
	}
}

// TestDCInventory_IncludeDetails_PopulatesAffectedEntities covers the
// IncludeDetails branch: AffectedEntities stays absent when the flag is
// false, and is populated with exactly one entity when it is true.
func TestDCInventory_IncludeDetails_PopulatesAffectedEntities(t *testing.T) {
	dc := types.Computer{
		DN:             "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com",
		SAMAccountName: "DC01$",
	}

	withoutDetails := &audit.DetectorData{
		DomainControllers: []types.Computer{dc},
		IncludeDetails:    false,
	}
	findings := NewDomainControllerInventoryDetector().Detect(context.Background(), withoutDetails)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
	if findings[0].AffectedEntities != nil {
		t.Fatalf("expected AffectedEntities absent when IncludeDetails=false, got %#v", findings[0].AffectedEntities)
	}

	withDetails := &audit.DetectorData{
		DomainControllers: []types.Computer{dc},
		IncludeDetails:    true,
	}
	findings = NewDomainControllerInventoryDetector().Detect(context.Background(), withDetails)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if len(findings[0].AffectedEntities) != 1 {
		t.Fatalf("expected 1 AffectedEntity when IncludeDetails=true, got %d", len(findings[0].AffectedEntities))
	}
}

// TestDCInventory_DCInfoMissing_EntityHasEmptyMetadata covers the DCInfo
// branch: when DCInfo is nil, or has no entry for the DC's DN, the entity
// still carries stable empty-slice FSMORoles/ReplicationPartners - never nil.
func TestDCInventory_DCInfoMissing_EntityHasEmptyMetadata(t *testing.T) {
	dc := types.Computer{
		DN:             "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com",
		SAMAccountName: "DC01$",
	}

	noDCInfoMap := &audit.DetectorData{
		DomainControllers: []types.Computer{dc},
		IncludeDetails:    true,
		DCInfo:            nil,
	}
	findings := NewDomainControllerInventoryDetector().Detect(context.Background(), noDCInfoMap)
	ent := findings[0].AffectedEntities[0]
	if ent.FSMORoles == nil || len(ent.FSMORoles) != 0 {
		t.Fatalf("expected empty non-nil FSMORoles when DCInfo is nil, got %#v", ent.FSMORoles)
	}
	if ent.ReplicationPartners == nil || len(ent.ReplicationPartners) != 0 {
		t.Fatalf("expected empty non-nil ReplicationPartners when DCInfo is nil, got %#v", ent.ReplicationPartners)
	}

	noEntryForDN := &audit.DetectorData{
		DomainControllers: []types.Computer{dc},
		IncludeDetails:    true,
		DCInfo:            map[string]*audit.DCMetadata{"CN=OTHER,DC=contoso,DC=com": {}},
	}
	findings = NewDomainControllerInventoryDetector().Detect(context.Background(), noEntryForDN)
	ent = findings[0].AffectedEntities[0]
	if ent.FSMORoles == nil || len(ent.FSMORoles) != 0 {
		t.Fatalf("expected empty non-nil FSMORoles when DCInfo has no entry for the DN, got %#v", ent.FSMORoles)
	}
	if ent.ReplicationPartners == nil || len(ent.ReplicationPartners) != 0 {
		t.Fatalf("expected empty non-nil ReplicationPartners when DCInfo has no entry for the DN, got %#v", ent.ReplicationPartners)
	}
}

// TestDCInventory_FSMORoles_CopiedWhenPresent covers the FSMORoles branch:
// a non-empty FSMORoles slice from DCInfo is copied onto the entity, and an
// empty one leaves the stable empty-slice default in place.
func TestDCInventory_FSMORoles_CopiedWhenPresent(t *testing.T) {
	dn := "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com"
	dc := types.Computer{DN: dn, SAMAccountName: "DC01$"}

	present := &audit.DetectorData{
		DomainControllers: []types.Computer{dc},
		IncludeDetails:    true,
		DCInfo:            map[string]*audit.DCMetadata{dn: {FSMORoles: []string{"PDC", "RID"}}},
	}
	findings := NewDomainControllerInventoryDetector().Detect(context.Background(), present)
	ent := findings[0].AffectedEntities[0]
	if len(ent.FSMORoles) != 2 || ent.FSMORoles[0] != "PDC" || ent.FSMORoles[1] != "RID" {
		t.Fatalf("expected FSMORoles=[PDC RID] copied from DCInfo, got %#v", ent.FSMORoles)
	}

	absent := &audit.DetectorData{
		DomainControllers: []types.Computer{dc},
		IncludeDetails:    true,
		DCInfo:            map[string]*audit.DCMetadata{dn: {FSMORoles: []string{}}},
	}
	findings = NewDomainControllerInventoryDetector().Detect(context.Background(), absent)
	ent = findings[0].AffectedEntities[0]
	if len(ent.FSMORoles) != 0 {
		t.Fatalf("expected empty FSMORoles when DCInfo.FSMORoles is empty, got %#v", ent.FSMORoles)
	}
}

// TestDCInventory_ReplicationPartners_CopiedWhenPresent covers the
// ReplicationPartners branch: a non-empty slice from DCInfo is copied onto
// the entity, and an empty one leaves the stable empty-slice default.
func TestDCInventory_ReplicationPartners_CopiedWhenPresent(t *testing.T) {
	dn := "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com"
	dc := types.Computer{DN: dn, SAMAccountName: "DC01$"}

	present := &audit.DetectorData{
		DomainControllers: []types.Computer{dc},
		IncludeDetails:    true,
		DCInfo:            map[string]*audit.DCMetadata{dn: {ReplicationPartners: []string{"DC02", "DC03"}}},
	}
	findings := NewDomainControllerInventoryDetector().Detect(context.Background(), present)
	ent := findings[0].AffectedEntities[0]
	if len(ent.ReplicationPartners) != 2 || ent.ReplicationPartners[0] != "DC02" || ent.ReplicationPartners[1] != "DC03" {
		t.Fatalf("expected ReplicationPartners=[DC02 DC03] copied from DCInfo, got %#v", ent.ReplicationPartners)
	}

	absent := &audit.DetectorData{
		DomainControllers: []types.Computer{dc},
		IncludeDetails:    true,
		DCInfo:            map[string]*audit.DCMetadata{dn: {ReplicationPartners: []string{}}},
	}
	findings = NewDomainControllerInventoryDetector().Detect(context.Background(), absent)
	ent = findings[0].AffectedEntities[0]
	if len(ent.ReplicationPartners) != 0 {
		t.Fatalf("expected empty ReplicationPartners when DCInfo.ReplicationPartners is empty, got %#v", ent.ReplicationPartners)
	}
}

// TestDCInventory_IsRODC_SetsIsReadOnlyDC covers the IsReadOnlyDC branch:
// DCInfo.IsRODC=true must surface as AffectedEntity.IsReadOnlyDC=true.
func TestDCInventory_IsRODC_SetsIsReadOnlyDC(t *testing.T) {
	dn := "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com"
	dc := types.Computer{DN: dn, SAMAccountName: "DC01$"}

	data := &audit.DetectorData{
		DomainControllers: []types.Computer{dc},
		IncludeDetails:    true,
		DCInfo:            map[string]*audit.DCMetadata{dn: {IsRODC: true}},
	}
	findings := NewDomainControllerInventoryDetector().Detect(context.Background(), data)
	if !findings[0].AffectedEntities[0].IsReadOnlyDC {
		t.Fatalf("expected IsReadOnlyDC=true when DCInfo.IsRODC=true")
	}
}

// TestDCInventory_SAMAccountNameWithTrailingDollar_StripsSuffix covers the
// TrimSuffix branch: a computer-account SAMAccountName ("DC01$") must yield
// Name="DC01" with the trailing "$" stripped, not the raw account name.
func TestDCInventory_SAMAccountNameWithTrailingDollar_StripsSuffix(t *testing.T) {
	dc := types.Computer{
		DN:             "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com",
		SAMAccountName: "DC01$",
	}

	data := &audit.DetectorData{
		DomainControllers: []types.Computer{dc},
		IncludeDetails:    true,
	}
	findings := NewDomainControllerInventoryDetector().Detect(context.Background(), data)
	ent := findings[0].AffectedEntities[0]
	if ent.Name != "DC01" {
		t.Fatalf("Name = %q, want %q (trailing \"$\" stripped)", ent.Name, "DC01")
	}
}

// TestDCInventory_SAMAccountNameEmpty_FallsBackToDNSHostName covers the
// name-fallback branch: when SAMAccountName is empty, Name falls back to
// DNSHostName instead of staying blank.
func TestDCInventory_SAMAccountNameEmpty_FallsBackToDNSHostName(t *testing.T) {
	dc := types.Computer{
		DN:             "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com",
		SAMAccountName: "",
		DNSHostName:    "dc01.contoso.com",
	}

	data := &audit.DetectorData{
		DomainControllers: []types.Computer{dc},
		IncludeDetails:    true,
	}
	findings := NewDomainControllerInventoryDetector().Detect(context.Background(), data)
	ent := findings[0].AffectedEntities[0]
	if ent.Name != "dc01.contoso.com" {
		t.Fatalf("Name = %q, want fallback to DNSHostName %q", ent.Name, "dc01.contoso.com")
	}
}
