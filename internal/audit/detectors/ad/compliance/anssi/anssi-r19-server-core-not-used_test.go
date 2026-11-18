package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestR19ServerCoreNotUsed_NoDomainControllers_NoFinding pins branch 1: when
// data.DomainControllers is empty, the detector returns no finding at all
// (not even a Count=0 finding).
func TestR19ServerCoreNotUsed_NoDomainControllers_NoFinding(t *testing.T) {
	data := &audit.DetectorData{}
	findings := NewR19ServerCoreNotUsedDetector().Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding when there are no domain controllers, got %+v", findings)
	}
}

// TestR19ServerCoreNotUsed_OneDomainController_CountIsOne pins branch 2 with
// a single DC: an unconditional Info finding is emitted, with Count equal to
// the number of domain controllers.
func TestR19ServerCoreNotUsed_OneDomainController_CountIsOne(t *testing.T) {
	data := &audit.DetectorData{
		DomainControllers: []types.Computer{
			{DN: "CN=DC01,OU=Domain Controllers,DC=example,DC=com", SAMAccountName: "DC01$"},
		},
	}
	findings := NewR19ServerCoreNotUsedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityInfo {
		t.Errorf("Severity = %q, want %q", findings[0].Severity, types.SeverityInfo)
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1", findings[0].Count)
	}
}

// TestR19ServerCoreNotUsed_TwoDomainControllers_CountIsTwo pins branch 2 with
// several DCs: Count tracks len(data.DomainControllers) exactly, as a
// topology count, not a violation count.
func TestR19ServerCoreNotUsed_TwoDomainControllers_CountIsTwo(t *testing.T) {
	data := &audit.DetectorData{
		DomainControllers: []types.Computer{
			{DN: "CN=DC01,OU=Domain Controllers,DC=example,DC=com", SAMAccountName: "DC01$"},
			{DN: "CN=DC02,OU=Domain Controllers,DC=example,DC=com", SAMAccountName: "DC02$"},
		},
	}
	findings := NewR19ServerCoreNotUsedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 2 {
		t.Errorf("Count = %d, want 2", findings[0].Count)
	}
}

// TestR19ServerCoreNotUsed_TitleAndDescriptionNotEmpty pins the finding's
// text content: Title and Description must not be empty fragments, and the
// description must actually report the domain controller count it was built
// from (fmt.Sprintf with len(dcs)).
func TestR19ServerCoreNotUsed_TitleAndDescriptionNotEmpty(t *testing.T) {
	data := &audit.DetectorData{
		DomainControllers: []types.Computer{
			{DN: "CN=DC01,OU=Domain Controllers,DC=example,DC=com", SAMAccountName: "DC01$"},
			{DN: "CN=DC02,OU=Domain Controllers,DC=example,DC=com", SAMAccountName: "DC02$"},
			{DN: "CN=DC03,OU=Domain Controllers,DC=example,DC=com", SAMAccountName: "DC03$"},
		},
	}
	findings := NewR19ServerCoreNotUsedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if strings.TrimSpace(findings[0].Title) == "" {
		t.Error("Title must not be empty")
	}
	if strings.TrimSpace(findings[0].Description) == "" {
		t.Error("Description must not be empty")
	}
	if !strings.Contains(findings[0].Description, "3 Domain Controller") {
		t.Errorf("Description should report the domain controller count (3), got %q", findings[0].Description)
	}
}

// TestR19ServerCoreNotUsed_IncludeDetailsTrue_AffectedEntitiesPopulated pins
// branch 5: with IncludeDetails=true, AffectedEntities is populated from the
// domain controllers via computersToEntities.
func TestR19ServerCoreNotUsed_IncludeDetailsTrue_AffectedEntitiesPopulated(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		DomainControllers: []types.Computer{
			{DN: "CN=DC01,OU=Domain Controllers,DC=example,DC=com", SAMAccountName: "DC01$"},
		},
	}
	findings := NewR19ServerCoreNotUsedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].DN != "CN=DC01,OU=Domain Controllers,DC=example,DC=com" {
		t.Errorf("expected AffectedEntities to contain the DC, got %+v", findings[0].AffectedEntities)
	}
}

// TestR19ServerCoreNotUsed_IncludeDetailsFalse_AffectedEntitiesNil pins the
// other side of branch 5: with IncludeDetails=false, no AffectedEntities are
// attached even though the finding (and its Count) is otherwise identical.
func TestR19ServerCoreNotUsed_IncludeDetailsFalse_AffectedEntitiesNil(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: false,
		DomainControllers: []types.Computer{
			{DN: "CN=DC01,OU=Domain Controllers,DC=example,DC=com", SAMAccountName: "DC01$"},
		},
	}
	findings := NewR19ServerCoreNotUsedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if len(findings[0].AffectedEntities) != 0 {
		t.Errorf("expected no AffectedEntities when IncludeDetails is false, got %+v", findings[0].AffectedEntities)
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1 (unaffected by IncludeDetails)", findings[0].Count)
	}
}

// TestR19ServerCoreNotUsed_Reproducibility_Populated pins that the
// reproduction recipe (LDAP filter/attrs) is attached to the finding, since
// it is the mechanism an ANSSI auditor uses to replay the query.
func TestR19ServerCoreNotUsed_Reproducibility_Populated(t *testing.T) {
	data := &audit.DetectorData{
		DomainControllers: []types.Computer{
			{DN: "CN=DC01,OU=Domain Controllers,DC=example,DC=com", SAMAccountName: "DC01$"},
		},
	}
	findings := NewR19ServerCoreNotUsedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Reproducibility == nil || findings[0].Reproducibility.LDAPFilter == "" {
		t.Errorf("expected a non-empty LDAP reproduction filter, got %+v", findings[0].Reproducibility)
	}
}
