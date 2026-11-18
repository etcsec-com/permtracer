package membership

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestPreWindows2000Access_LocalizedNameFoundBySID_Counts proves the group is
// found by its well-known SID even when its CN/SAMAccountName are localized
// and never contain the English name "Pre-Windows 2000 Compatible Access".
// Fails on the pre-fix code, which matched by English name substring only
// and would report Count 0 here.
func TestPreWindows2000Access_LocalizedNameFoundBySID_Counts(t *testing.T) {
	d := NewPreWindows2000AccessDetector()
	data := &audit.DetectorData{
		Groups: []types.Group{
			{
				DN:             "CN=Accès compatible pré-Windows 2000,DC=contoso,DC=com",
				CN:             "Accès compatible pré-Windows 2000",
				SAMAccountName: "Accès compatible pré-Windows 2000",
				ObjectSID:      "S-1-5-32-554",
				Members:        []string{"CN=u1,DC=contoso,DC=com", "CN=u2,DC=contoso,DC=com"},
			},
		},
	}
	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 2 {
		t.Fatalf("Count = %d, want 2 (localized group found by its well-known SID S-1-5-32-554)", findings[0].Count)
	}
}

// TestPreWindows2000Access_HomonymWithDifferentSID_NotCounted proves a
// homonym group - same English name, a different SID - is not the real
// built-in group. Fails on the pre-fix code, which matched by name alone
// and would report Count 1 here.
func TestPreWindows2000Access_HomonymWithDifferentSID_NotCounted(t *testing.T) {
	d := NewPreWindows2000AccessDetector()
	data := &audit.DetectorData{
		Groups: []types.Group{
			{
				DN:             "CN=Pre-Windows 2000 Compatible Access,DC=contoso,DC=com",
				CN:             "Pre-Windows 2000 Compatible Access",
				SAMAccountName: "Pre-Windows 2000 Compatible Access",
				ObjectSID:      "S-1-5-21-1-1-1-9999",
				Members:        []string{"CN=u1,DC=contoso,DC=com"},
			},
		},
	}
	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (a homonym group with a different SID is not the real built-in group)", findings[0].Count)
	}
}

// TestPreWindows2000Access_RealSIDNoMembers_NotCounted proves the real group,
// found by SID, with no members does not fire.
func TestPreWindows2000Access_RealSIDNoMembers_NotCounted(t *testing.T) {
	d := NewPreWindows2000AccessDetector()
	data := &audit.DetectorData{
		Groups: []types.Group{
			{
				DN:             "CN=Pre-Windows 2000 Compatible Access,DC=contoso,DC=com",
				CN:             "Pre-Windows 2000 Compatible Access",
				SAMAccountName: "Pre-Windows 2000 Compatible Access",
				ObjectSID:      "S-1-5-32-554",
			},
		},
	}
	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (the real group exists but has no members)", findings[0].Count)
	}
}

// TestPreWindows2000Access_IncludeDetails_PopulatesAffectedEntities proves
// that with IncludeDetails=true and the real group carrying one member,
// AffectedEntities carries the group's DN. The other tests in this file
// assert only Count, never AffectedEntities, so an inverted
// data.IncludeDetails guard would pass them silently. This test fails on
// that inverted guard.
func TestPreWindows2000Access_IncludeDetails_PopulatesAffectedEntities(t *testing.T) {
	d := NewPreWindows2000AccessDetector()
	groupDN := "CN=Pre-Windows 2000 Compatible Access,DC=example,DC=com"
	data := &audit.DetectorData{
		IncludeDetails: true,
		Groups: []types.Group{
			{
				DN:             groupDN,
				CN:             "Pre-Windows 2000 Compatible Access",
				SAMAccountName: "Pre-Windows 2000 Compatible Access",
				ObjectSID:      "S-1-5-32-554",
				Members:        []string{"CN=u1,DC=example,DC=com"},
			},
		},
	}
	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].DN != groupDN {
		t.Fatalf("AffectedEntities = %+v, want exactly one entity with DN %q (IncludeDetails=true must populate AffectedEntities)", findings[0].AffectedEntities, groupDN)
	}
}

// TestPreWindows2000Access_NoDetails_NoAffectedEntities proves that with
// IncludeDetails=false, AffectedEntities stays empty even though the real
// group has a member and Count fires. Fails on an inverted
// data.IncludeDetails guard, which would populate AffectedEntities here.
func TestPreWindows2000Access_NoDetails_NoAffectedEntities(t *testing.T) {
	d := NewPreWindows2000AccessDetector()
	data := &audit.DetectorData{
		IncludeDetails: false,
		Groups: []types.Group{
			{
				DN:             "CN=Pre-Windows 2000 Compatible Access,DC=example,DC=com",
				CN:             "Pre-Windows 2000 Compatible Access",
				SAMAccountName: "Pre-Windows 2000 Compatible Access",
				ObjectSID:      "S-1-5-32-554",
				Members:        []string{"CN=u1,DC=example,DC=com"},
			},
		},
	}
	findings := d.Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 0 {
		t.Fatalf("AffectedEntities = %+v, want empty (IncludeDetails=false must not populate AffectedEntities)", findings[0].AffectedEntities)
	}
}
