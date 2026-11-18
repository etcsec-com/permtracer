package network

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func detectDnsWildcard(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewDnsWildcardDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

// Cas 1 (ANALYSE.md §5.1) : une zone unique dont WildcardRecords est non vide
// doit produire Count=1 et peupler Details["affectedZones"].
func TestDnsWildcard_Cas1_SingleZoneWildcardPresent(t *testing.T) {
	f := detectDnsWildcard(t, &audit.DetectorData{
		IncludeDetails: true,
		DNSZones: []types.DNSZone{
			{Name: "zone-a.test", WildcardRecords: []string{"*.zone-a.test"}},
		},
	})
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (one zone carries a wildcard node)", f.Count)
	}
	zones, _ := f.Details["affectedZones"].([]string)
	if len(zones) != 1 || zones[0] != "zone-a.test" {
		t.Errorf("expected affectedZones=[zone-a.test], got %v", f.Details["affectedZones"])
	}
	if len(f.AffectedEntities) != 1 || f.AffectedEntities[0].Name != "zone-a.test" || f.AffectedEntities[0].Type != types.EntityTypeDNSZone {
		t.Errorf("expected AffectedEntities populated with zone-a.test when IncludeDetails=true and Count>0, got %v", f.AffectedEntities)
	}
}

// Cas 2 (ANALYSE.md §5.2) : une zone unique sans WildcardRecords (nil ou vide)
// doit produire Count=0 et aucun Details.
func TestDnsWildcard_Cas2_SingleZoneNoWildcard(t *testing.T) {
	tests := []struct {
		name            string
		wildcardRecords []string
	}{
		{"nil_slice", nil},
		{"empty_slice", []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := detectDnsWildcard(t, &audit.DetectorData{
				DNSZones: []types.DNSZone{
					{Name: "zone-b.test", WildcardRecords: tt.wildcardRecords},
				},
			})
			if f.Count != 0 {
				t.Fatalf("Count = %d, want 0 (zone has no wildcard node)", f.Count)
			}
			if f.Details != nil {
				t.Errorf("expected Details=nil, got %v", f.Details)
			}
		})
	}
}

// Cas 3 (ANALYSE.md §5.3) : data.DNSZones vide (nil ou []types.DNSZone{})
// déclenche le retour anticipé de dns-wildcard.go:46-48, Count=0.
func TestDnsWildcard_Cas3_NoZonesAtAll(t *testing.T) {
	tests := []struct {
		name string
		data *audit.DetectorData
	}{
		{"nil_DNSZones", &audit.DetectorData{}},
		{"empty_DNSZones_slice", &audit.DetectorData{DNSZones: []types.DNSZone{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := detectDnsWildcard(t, tt.data)
			if f.Count != 0 {
				t.Fatalf("Count = %d, want 0 (early return on empty DNSZones)", f.Count)
			}
			if f.Details != nil {
				t.Errorf("expected Details=nil on early return, got %v", f.Details)
			}
		})
	}
}

// Cas 4 (ANALYSE.md §5.4) : plusieurs zones, certaines affectées, d'autres
// non. Count doit être le nombre exact de zones affectées (2), jamais le
// nombre total de zones (3) : régression sur la sémantique de comptage.
func TestDnsWildcard_Cas4_MixedZonesCountIsAffectedNotTotal(t *testing.T) {
	f := detectDnsWildcard(t, &audit.DetectorData{
		DNSZones: []types.DNSZone{
			{Name: "zone-c.test", WildcardRecords: []string{"*.zone-c.test"}},
			{Name: "zone-d.test"},
			{Name: "zone-e.test", WildcardRecords: []string{"*.zone-e.test"}},
		},
	})
	if f.Count != 2 {
		t.Fatalf("Count = %d, want 2 (exactly 2 of the 3 zones are affected, not the total zone count)", f.Count)
	}
	zones, _ := f.Details["affectedZones"].([]string)
	if len(zones) != 2 {
		t.Fatalf("expected 2 affectedZones entries, got %v", zones)
	}
	want := map[string]bool{"zone-c.test": true, "zone-e.test": true}
	for _, z := range zones {
		if !want[z] {
			t.Errorf("unexpected zone in affectedZones: %s", z)
		}
	}
}

// Cas 5 (ANALYSE.md §5.5) : deux objets dnsZone distincts partageant le même
// Name, tous deux affectés, doivent compter Count=2 et afficher la même
// chaîne deux fois dans affectedZones (comportement figé, pas de dédup par
// nom - voir §1 de l'analyse).
func TestDnsWildcard_Cas5_DuplicateZoneNameBothAffectedCountsTwice(t *testing.T) {
	f := detectDnsWildcard(t, &audit.DetectorData{
		DNSZones: []types.DNSZone{
			{DN: "CN=dup-zone-domain,DC=corp,DC=com", Name: "dup-zone.test", WildcardRecords: []string{"*.dup-zone.test"}},
			{DN: "CN=dup-zone-forest,DC=contoso,DC=com", Name: "dup-zone.test", WildcardRecords: []string{"*.dup-zone.test"}},
		},
	})
	if f.Count != 2 {
		t.Fatalf("Count = %d, want 2 (two distinct dnsZone objects, no dedup by Name)", f.Count)
	}
	zones, _ := f.Details["affectedZones"].([]string)
	if len(zones) != 2 || zones[0] != "dup-zone.test" || zones[1] != "dup-zone.test" {
		t.Errorf("expected affectedZones=[dup-zone.test dup-zone.test], got %v", zones)
	}
}

// Cas 6 (ANALYSE.md §5.6) : IncludeDetails=false avec Count>0 doit laisser
// AffectedEntities à nil tout en peuplant Details - les deux champs sont
// conditionnés différemment (dns-wildcard.go:59-65).
func TestDnsWildcard_Cas6_IncludeDetailsFalseKeepsDetailsDropsEntities(t *testing.T) {
	f := detectDnsWildcard(t, &audit.DetectorData{
		IncludeDetails: false,
		DNSZones: []types.DNSZone{
			{Name: "zone-f.test", WildcardRecords: []string{"*.zone-f.test"}},
		},
	})
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1", f.Count)
	}
	if f.Details == nil {
		t.Error("expected Details to stay populated when IncludeDetails=false")
	}
	if f.AffectedEntities != nil {
		t.Errorf("expected AffectedEntities=nil when IncludeDetails=false, got %v", f.AffectedEntities)
	}
}

// Cas 7 (ANALYSE.md §5.7) : IncludeDetails=true avec Count=0 (aucune zone
// affectée) doit laisser AffectedEntities à nil, pas un slice vide non-nil,
// car le bloc :57-66 n'est jamais exécuté.
func TestDnsWildcard_Cas7_IncludeDetailsTrueNoAffectedZonesEntitiesStayNil(t *testing.T) {
	f := detectDnsWildcard(t, &audit.DetectorData{
		IncludeDetails: true,
		DNSZones: []types.DNSZone{
			{Name: "zone-g.test"},
		},
	})
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0", f.Count)
	}
	if f.AffectedEntities != nil {
		t.Errorf("expected AffectedEntities=nil (not an empty non-nil slice) when no zone is affected, got %v", f.AffectedEntities)
	}
}

// Cas 8 (ANALYSE.md §5.8) : Severity reste toujours Medium, verrou de
// non-régression (aucune autre valeur possible dans le code actuel).
func TestDnsWildcard_Cas8_SeverityAlwaysMedium(t *testing.T) {
	f := detectDnsWildcard(t, &audit.DetectorData{
		DNSZones: []types.DNSZone{
			{Name: "zone-h.test", WildcardRecords: []string{"*.zone-h.test"}},
		},
	})
	if f.Severity != types.SeverityMedium {
		t.Errorf("Severity = %q, want %q", f.Severity, types.SeverityMedium)
	}
}
