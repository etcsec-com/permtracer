package dangerous

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// Cause confirmée : engine.go/le detecteur filtraient sur
// "CN=Master Root Keys,CN=System,<baseDN>", un DN qui n'existe dans aucun
// AD (BCKUPKEY_* vivent directement sous CN=System, GUID-suffixed). Le
// détecteur restait donc muet (Count=0) dans tout domaine réel. Ce test
// prouve la réparation : les ACEs réelles arrivent désormais via
// DomainInfo.DPAPIBackupKeyACLs (rempli par le provider ldap sur les vrais
// objets BCKUPKEY_*).
const dpapiDomainDN = "DC=example,DC=com"

func dpapiData(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo: &types.DomainInfo{
			DomainDN:           dpapiDomainDN,
			DomainSID:          "S-1-5-21-1111111111-2222222222-3333333333",
			DPAPIBackupKeyACLs: aces,
		},
	}
}

// TestDPAPIKeyACL_NonPrivilegedAccessFires is RED on today's code: the
// detector filters data.ACLEntries (empty here - the real fix path) by a
// dead DN, so it never sees these ACEs no matter where they are attached.
// After the patch it reads DomainInfo.DPAPIBackupKeyACLs directly and must
// fire.
func TestDPAPIKeyACL_NonPrivilegedAccessFires(t *testing.T) {
	ace := types.ACLEntry{
		ObjectDN:   "CN=BCKUPKEY_PREFERRED,CN=System," + dpapiDomainDN,
		Trustee:    "S-1-5-21-1111111111-2222222222-3333333333-1105", // ordinary user, not privileged
		AceType:    "ACCESS_ALLOWED_ACE_TYPE",
		AccessMask: types.MaskGenericAll,
	}
	data := dpapiData(ace)

	d := NewDPAPIKeyACLDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for non-default DPAPI backup key access, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1, got %d", findings[0].Count)
	}
}

// TestDPAPIKeyACL_NoFindingWhenNoACLData covers the doctrine "un détecteur
// qui devine est pire qu'un contrôle absent": with no DomainInfo (provider
// didn't run / LDAP denied), the detector must emit nothing, not guess.
func TestDPAPIKeyACL_NoFindingWhenNoACLData(t *testing.T) {
	d := NewDPAPIKeyACLDetector()
	findings := d.Detect(context.Background(), &audit.DetectorData{})
	if len(findings) != 0 {
		t.Fatalf("expected no finding with nil DomainInfo, got %d", len(findings))
	}
}

// TestDPAPIKeyACL_BuiltinAdministratorsExcluded is RED on today's code: the
// hand-rolled privilegedSIDs set only ever held SYSTEM/CreatorOwner/SELF plus
// each domain-RID-suffixed SID, never the built-in BUILTIN\Administrators SID
// (S-1-5-32-544), which is domain-independent. A real-domain witness showed
// all 4 real BCKUPKEY_* objects counted solely because of this gap. After the
// patch, audit.IsBuiltinAdminTrustee covers S-1-5-32-544 and the ACE must be
// excluded.
func TestDPAPIKeyACL_BuiltinAdministratorsExcluded(t *testing.T) {
	ace := types.ACLEntry{
		ObjectDN:   "CN=BCKUPKEY_PREFERRED,CN=System," + dpapiDomainDN,
		Trustee:    "S-1-5-32-544", // BUILTIN\Administrators
		AceType:    "ACCESS_ALLOWED_ACE_TYPE",
		AccessMask: types.MaskGenericAll,
	}
	data := dpapiData(ace)

	d := NewDPAPIKeyACLDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding for BUILTIN\\Administrators GenericAll, got %d finding(s)", len(findings))
	}
}

// TestDPAPIKeyACL_EnterpriseDomainControllersExcluded is RED on today's code:
// the hand-rolled privileged set never included S-1-5-9 (Enterprise Domain
// Controllers), unlike audit.IsBuiltinAdminTrustee (wellknown_sids.go:16).
// ANALYSE.md flags this as écart #2, the most operationally significant one.
func TestDPAPIKeyACL_EnterpriseDomainControllersExcluded(t *testing.T) {
	ace := types.ACLEntry{
		ObjectDN:   "CN=BCKUPKEY_PREFERRED,CN=System," + dpapiDomainDN,
		Trustee:    "S-1-5-9", // Enterprise Domain Controllers
		AceType:    "ACCESS_ALLOWED_ACE_TYPE",
		AccessMask: types.MaskGenericAll,
	}
	data := dpapiData(ace)

	d := NewDPAPIKeyACLDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding for Enterprise Domain Controllers GenericAll, got %d finding(s)", len(findings))
	}
}

// TestDPAPIKeyACL_GenericWriteCounted is RED on today's code: dangerousMask
// omitted types.MaskGenericWrite, unlike the identical mask used by this
// package's CROSS_DOMAIN_SID_DANGEROUS_ACE/ORPHANED_SID_DANGEROUS_ACE
// (ANALYSE.md écart #3). An ordinary trustee holding ONLY GenericWrite on a
// BCKUPKEY_* object must now be counted.
func TestDPAPIKeyACL_GenericWriteCounted(t *testing.T) {
	ace := types.ACLEntry{
		ObjectDN:   "CN=BCKUPKEY_PREFERRED,CN=System," + dpapiDomainDN,
		Trustee:    "S-1-5-21-1111111111-2222222222-3333333333-1105", // ordinary user, not privileged
		AceType:    "ACCESS_ALLOWED_ACE_TYPE",
		AccessMask: types.MaskGenericWrite,
	}
	data := dpapiData(ace)

	d := NewDPAPIKeyACLDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for ordinary trustee GenericWrite, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1, got %d", findings[0].Count)
	}
}

// TestDPAPIKeyACL_GenericAllStillCounted guards against a regression where
// swapping in the shared helpers would silently stop counting the mask's
// original bits: an ordinary trustee's GenericAll must still fire.
func TestDPAPIKeyACL_GenericAllStillCounted(t *testing.T) {
	ace := types.ACLEntry{
		ObjectDN:   "CN=BCKUPKEY_PREFERRED,CN=System," + dpapiDomainDN,
		Trustee:    "S-1-5-21-1111111111-2222222222-3333333333-1105", // ordinary user, not privileged
		AceType:    "ACCESS_ALLOWED_ACE_TYPE",
		AccessMask: types.MaskGenericAll,
	}
	data := dpapiData(ace)

	d := NewDPAPIKeyACLDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for ordinary trustee GenericAll, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1, got %d", findings[0].Count)
	}
}

// TestDPAPIKeyACL_MixedCaseAccessAllowedCounted is RED on today's code: the
// hand-rolled gate strings.Contains(ace.AceType, "ALLOWED") is case-sensitive,
// unlike audit.IsGrantACE which upper-cases first (ANALYSE.md écart #1).
func TestDPAPIKeyACL_MixedCaseAccessAllowedCounted(t *testing.T) {
	ace := types.ACLEntry{
		ObjectDN:   "CN=BCKUPKEY_PREFERRED,CN=System," + dpapiDomainDN,
		Trustee:    "S-1-5-21-1111111111-2222222222-3333333333-1105", // ordinary user, not privileged
		AceType:    "access_allowed_ace_type",
		AccessMask: types.MaskGenericAll,
	}
	data := dpapiData(ace)

	d := NewDPAPIKeyACLDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for mixed-case ALLOWED ace type, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1, got %d", findings[0].Count)
	}
}

// TestDPAPIKeyACL_DenyACENotCounted guards against removal of
// "if !audit.IsGrantACE(...)". aclentry.go's IsGrantACE matches only AceType
// strings containing "ALLOWED" (case-insensitive) - ACCESS_DENIED_ACE_TYPE and
// ACCESS_DENIED_OBJECT_ACE_TYPE contain "DENIED", never "ALLOWED", so both must
// be rejected regardless of how dangerous their AccessMask is.
func TestDPAPIKeyACL_DenyACENotCounted(t *testing.T) {
	aces := []types.ACLEntry{
		{
			ObjectDN:   "CN=BCKUPKEY_PREFERRED,CN=System," + dpapiDomainDN,
			Trustee:    "S-1-5-21-1111111111-2222222222-3333333333-1105", // ordinary user, not privileged
			AceType:    "ACCESS_DENIED_ACE_TYPE",
			AccessMask: types.MaskGenericAll,
		},
		{
			ObjectDN:   "CN=BCKUPKEY_PREFERRED,CN=System," + dpapiDomainDN,
			Trustee:    "S-1-5-21-1111111111-2222222222-3333333333-1106", // ordinary user, not privileged
			AceType:    "ACCESS_DENIED_OBJECT_ACE_TYPE",
			AccessMask: types.MaskGenericAll,
		},
	}
	data := dpapiData(aces...)

	d := NewDPAPIKeyACLDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding for DENY-type ACEs, got %d finding(s)", len(findings))
	}
}

// TestDPAPIKeyACL_NonDangerousMaskNotCounted guards against removal of the
// dangerousMask guard. An ALLOW ACE held by an ordinary
// trustee but carrying only MaskReadProperty (read-only property access, none
// of GenericAll/GenericWrite/WriteDACL/WriteOwner/ControlAccess) must not be
// counted.
func TestDPAPIKeyACL_NonDangerousMaskNotCounted(t *testing.T) {
	ace := types.ACLEntry{
		ObjectDN:   "CN=BCKUPKEY_PREFERRED,CN=System," + dpapiDomainDN,
		Trustee:    "S-1-5-21-1111111111-2222222222-3333333333-1105", // ordinary user, not privileged
		AceType:    "ACCESS_ALLOWED_ACE_TYPE",
		AccessMask: types.MaskReadProperty,
	}
	data := dpapiData(ace)

	d := NewDPAPIKeyACLDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding for non-dangerous ReadProperty-only mask, got %d finding(s)", len(findings))
	}
}

// TestDPAPIKeyACL_TotalInstances guards against the TotalInstances assignment
// being removed, or being made unconditional. It checks both directions: two
// dangerous ACEs on the SAME object must yield Count=1 but TotalInstances=2
// (a removed assignment would fail this), and a single ACE must leave
// TotalInstances at its zero value because totalInstances == len(uniqueObjects)
// (an unconditional assignment would fail this).
func TestDPAPIKeyACL_TotalInstances(t *testing.T) {
	sameObjectDN := "CN=BCKUPKEY_PREFERRED,CN=System," + dpapiDomainDN

	twoACEs := []types.ACLEntry{
		{
			ObjectDN:   sameObjectDN,
			Trustee:    "S-1-5-21-1111111111-2222222222-3333333333-1105", // ordinary user, not privileged
			AceType:    "ACCESS_ALLOWED_ACE_TYPE",
			AccessMask: types.MaskGenericAll,
		},
		{
			ObjectDN:   sameObjectDN,
			Trustee:    "S-1-5-21-1111111111-2222222222-3333333333-1106", // ordinary user, not privileged
			AceType:    "ACCESS_ALLOWED_ACE_TYPE",
			AccessMask: types.MaskGenericAll,
		},
	}
	d := NewDPAPIKeyACLDetector()
	findings := d.Detect(context.Background(), dpapiData(twoACEs...))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for 2 dangerous ACEs on the same object, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 for 2 ACEs on 1 object, got %d", findings[0].Count)
	}
	if findings[0].TotalInstances != 2 {
		t.Fatalf("expected TotalInstances=2 for 2 ACEs on 1 object, got %d", findings[0].TotalInstances)
	}

	oneACE := []types.ACLEntry{
		{
			ObjectDN:   sameObjectDN,
			Trustee:    "S-1-5-21-1111111111-2222222222-3333333333-1105", // ordinary user, not privileged
			AceType:    "ACCESS_ALLOWED_ACE_TYPE",
			AccessMask: types.MaskGenericAll,
		},
	}
	findings = d.Detect(context.Background(), dpapiData(oneACE...))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for 1 dangerous ACE, got %d", len(findings))
	}
	if findings[0].TotalInstances != 0 {
		t.Fatalf("expected TotalInstances=0 (unset) when totalInstances == uniqueObjects, got %d", findings[0].TotalInstances)
	}
}

// TestDPAPIKeyACL_AffectedEntitiesOnlyWithDetails guards against the
// IncludeDetails block being removed, or made unconditional. With
// IncludeDetails=true, AffectedEntities must be populated; with
// IncludeDetails=false, it must stay nil - a caller that disabled details must
// not get entity data back regardless.
func TestDPAPIKeyACL_AffectedEntitiesOnlyWithDetails(t *testing.T) {
	ace := types.ACLEntry{
		ObjectDN:   "CN=BCKUPKEY_PREFERRED,CN=System," + dpapiDomainDN,
		Trustee:    "S-1-5-21-1111111111-2222222222-3333333333-1105", // ordinary user, not privileged
		AceType:    "ACCESS_ALLOWED_ACE_TYPE",
		AccessMask: types.MaskGenericAll,
	}
	d := NewDPAPIKeyACLDetector()

	withDetails := &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo: &types.DomainInfo{
			DomainDN:           dpapiDomainDN,
			DomainSID:          "S-1-5-21-1111111111-2222222222-3333333333",
			DPAPIBackupKeyACLs: []types.ACLEntry{ace},
		},
	}
	findings := d.Detect(context.Background(), withDetails)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if len(findings[0].AffectedEntities) == 0 {
		t.Fatalf("expected non-empty AffectedEntities when IncludeDetails=true, got %v", findings[0].AffectedEntities)
	}

	withoutDetails := &audit.DetectorData{
		IncludeDetails: false,
		DomainInfo: &types.DomainInfo{
			DomainDN:           dpapiDomainDN,
			DomainSID:          "S-1-5-21-1111111111-2222222222-3333333333",
			DPAPIBackupKeyACLs: []types.ACLEntry{ace},
		},
	}
	findings = d.Detect(context.Background(), withoutDetails)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].AffectedEntities != nil {
		t.Fatalf("expected nil AffectedEntities when IncludeDetails=false, got %v", findings[0].AffectedEntities)
	}
}

// TestDPAPIKeyACL_WriteDACLCounted guards against removal of MaskWriteDACL
// from dangerousMask. An ALLOW ACE held by an ordinary trustee
// with ONLY the WriteDACL bit set must be counted.
func TestDPAPIKeyACL_WriteDACLCounted(t *testing.T) {
	ace := types.ACLEntry{
		ObjectDN:   "CN=BCKUPKEY_PREFERRED,CN=System," + dpapiDomainDN,
		Trustee:    "S-1-5-21-1111111111-2222222222-3333333333-1105", // ordinary user, not privileged
		AceType:    "ACCESS_ALLOWED_ACE_TYPE",
		AccessMask: types.MaskWriteDACL,
	}
	data := dpapiData(ace)

	d := NewDPAPIKeyACLDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for ordinary trustee WriteDACL-only, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1, got %d", findings[0].Count)
	}
}

// TestDPAPIKeyACL_WriteOwnerCounted guards against removal of MaskWriteOwner
// from dangerousMask. An ALLOW ACE held by an ordinary trustee
// with ONLY the WriteOwner bit set must be counted.
func TestDPAPIKeyACL_WriteOwnerCounted(t *testing.T) {
	ace := types.ACLEntry{
		ObjectDN:   "CN=BCKUPKEY_PREFERRED,CN=System," + dpapiDomainDN,
		Trustee:    "S-1-5-21-1111111111-2222222222-3333333333-1105", // ordinary user, not privileged
		AceType:    "ACCESS_ALLOWED_ACE_TYPE",
		AccessMask: types.MaskWriteOwner,
	}
	data := dpapiData(ace)

	d := NewDPAPIKeyACLDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for ordinary trustee WriteOwner-only, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1, got %d", findings[0].Count)
	}
}

// TestDPAPIKeyACL_ControlAccessCounted guards against removal of
// MaskControlAccess from dangerousMask. An ALLOW ACE held by an ordinary
// trustee with ONLY the ControlAccess (extended right) bit set must be
// counted.
func TestDPAPIKeyACL_ControlAccessCounted(t *testing.T) {
	ace := types.ACLEntry{
		ObjectDN:   "CN=BCKUPKEY_PREFERRED,CN=System," + dpapiDomainDN,
		Trustee:    "S-1-5-21-1111111111-2222222222-3333333333-1105", // ordinary user, not privileged
		AceType:    "ACCESS_ALLOWED_ACE_TYPE",
		AccessMask: types.MaskControlAccess,
	}
	data := dpapiData(ace)

	d := NewDPAPIKeyACLDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for ordinary trustee ControlAccess-only, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1, got %d", findings[0].Count)
	}
}
