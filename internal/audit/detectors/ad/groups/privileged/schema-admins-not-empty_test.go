package privileged

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestSchemaAdminsNotEmpty_NoFabricatedANSSICitation covers the fact that
// PA-099 v1.0 has no recommendation about Schema/Enterprise Admins
// membership: R17 (p.35) is Tier 0 patch timeliness, R23 (p.40) is about
// permissions applied TO Tier 0 objects, not their own membership. The
// finding text used to claim "ANSSI PA-099 R17", which is false and
// verifiable in thirty seconds by anyone with the PDF. This test fails
// against that old description and passes once the citation is Microsoft's
// own guidance instead.
func TestSchemaAdminsNotEmpty_NoFabricatedANSSICitation(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "Schema Admins", Members: []string{"CN=svc-schema,CN=Users,DC=corp,DC=local"}},
		},
		IncludeDetails: true,
	}

	findings := NewSchemaAdminsNotEmptyDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	desc := findings[0].Description

	if strings.Contains(desc, "ANSSI") {
		t.Fatalf("description must not attribute this check to ANSSI PA-099 (no such recommendation exists), got %q", desc)
	}
	if !strings.Contains(desc, "Microsoft") {
		t.Fatalf("description should cite Microsoft's guidance on Schema/Enterprise Admins membership, got %q", desc)
	}
}

const schemaAdminsTestDomainSID = "S-1-5-21-7777777777-8888888888-9999999999"

func TestSchemaAdminsNotEmpty_CountsBothGroups(t *testing.T) {
	schemaDN := "CN=Schema Admins,CN=Users,DC=corp,DC=local"
	enterpriseDN := "CN=Enterprise Admins,CN=Users,DC=corp,DC=local"
	domainAdminsDN := "CN=Domain Admins,CN=Users,DC=corp,DC=local"
	schemaSID := schemaAdminsTestDomainSID + "-518"
	enterpriseSID := schemaAdminsTestDomainSID + "-519"
	domainAdminsSID := schemaAdminsTestDomainSID + "-512"

	data := &audit.DetectorData{
		Groups: []types.Group{
			{DN: schemaDN, SAMAccountName: "Schema Admins", Members: []string{"u1"}},
			{DN: enterpriseDN, SAMAccountName: "Enterprise Admins", Members: []string{"u2", "u3"}},
			{DN: domainAdminsDN, SAMAccountName: "Domain Admins", Members: []string{"u4"}},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			schemaSID:       {DN: schemaDN, SID: schemaSID, EntityType: types.EntityTypeGroup},
			enterpriseSID:   {DN: enterpriseDN, SID: enterpriseSID, EntityType: types.EntityTypeGroup},
			domainAdminsSID: {DN: domainAdminsDN, SID: domainAdminsSID, EntityType: types.EntityTypeGroup},
		},
		IncludeDetails: true,
	}

	findings := NewSchemaAdminsNotEmptyDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 3 {
		t.Fatalf("Count = %d, want 3 (1 Schema Admins RID -518 + 2 Enterprise Admins RID -519, Domain Admins RID -512 excluded)", findings[0].Count)
	}
}

// TestSchemaAdminsNotEmpty_LocalizedSchemaAdminsRID518Counted proves the SID
// fix for RID -518: a localized forest's Schema Admins group (French name,
// real RID -518) is still recognized as a target group, even though its
// SAMAccountName is not the English "schema admins" string the old
// strings.ToLower(name) == "schema admins" match required. The old code can
// never find this group by name, so it is never counted even though it has a
// member here.
func TestSchemaAdminsNotEmpty_LocalizedSchemaAdminsRID518Counted(t *testing.T) {
	groupSID := schemaAdminsTestDomainSID + "-518"
	groupDN := "CN=Administrateurs du schéma,CN=Users,DC=corp,DC=local"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{DN: groupDN, SAMAccountName: "Administrateurs du schéma", Members: []string{"CN=Alice,CN=Users,DC=corp,DC=local"}},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
		IncludeDetails: true,
	}

	f := NewSchemaAdminsNotEmptyDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (localized Schema Admins CN, real RID -518, HAS a member - old name match never finds this group)", f.Count)
	}
}

// TestSchemaAdminsNotEmpty_LocalizedEnterpriseAdminsRID519Counted is the same
// proof for RID -519 (Enterprise Admins), French name "Administrateurs de
// l'entreprise".
func TestSchemaAdminsNotEmpty_LocalizedEnterpriseAdminsRID519Counted(t *testing.T) {
	groupSID := schemaAdminsTestDomainSID + "-519"
	groupDN := "CN=Administrateurs de l'entreprise,CN=Users,DC=corp,DC=local"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{DN: groupDN, SAMAccountName: "Administrateurs de l'entreprise", Members: []string{"CN=Bob,CN=Users,DC=corp,DC=local"}},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			groupSID: {DN: groupDN, SID: groupSID, EntityType: types.EntityTypeGroup},
		},
		IncludeDetails: true,
	}

	f := NewSchemaAdminsNotEmptyDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (localized Enterprise Admins CN, real RID -519, HAS a member - old name match never finds this group)", f.Count)
	}
}

// TestSchemaAdminsNotEmpty_EnglishHomonymDifferentSIDNotCounted proves the
// homonym fix: a group named exactly "Schema Admins" in English but carrying
// a different, non-518/-519 RID is not the real Schema Admins group. The old
// code's strings.ToLower(name) == "schema admins" match counts this homonym
// by name alone; the SID-based match must not.
func TestSchemaAdminsNotEmpty_EnglishHomonymDifferentSIDNotCounted(t *testing.T) {
	homonymSID := schemaAdminsTestDomainSID + "-3002"
	homonymDN := "CN=Schema Admins,OU=Legacy,DC=corp,DC=local"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{DN: homonymDN, SAMAccountName: "Schema Admins", Members: []string{"CN=Carol,CN=Users,DC=corp,DC=local"}},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			homonymSID: {DN: homonymDN, SID: homonymSID, EntityType: types.EntityTypeGroup},
		},
		IncludeDetails: true,
	}

	f := NewSchemaAdminsNotEmptyDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("Count = %d, want 0 (homonym named exactly \"Schema Admins\" under a different SID -3002 must not be mistaken for the real RID -518/-519 groups)", f.Count)
	}
}

// TestSchemaAdminsNotEmpty_EmptyTargetGroupNotListed specifies that an empty
// target group (RID -518, no members) is not listed alongside a non-empty
// one (RID -519, 1 member): only the group that actually has a member is
// counted and appears among AffectedEntities. This kills a mutation that
// removes the `if len(Members) > 0` guard, which would also append the
// empty Schema Admins group to matched, growing AffectedEntities to 2 even
// though Count itself stays 1.
func TestSchemaAdminsNotEmpty_EmptyTargetGroupNotListed(t *testing.T) {
	schemaDN := "CN=Schema Admins,CN=Users,DC=example,DC=com"
	enterpriseDN := "CN=Enterprise Admins,CN=Users,DC=example,DC=com"
	schemaSID := schemaAdminsTestDomainSID + "-518"
	enterpriseSID := schemaAdminsTestDomainSID + "-519"

	data := &audit.DetectorData{
		Groups: []types.Group{
			{DN: schemaDN, SAMAccountName: "Schema Admins", Members: []string{}},
			{DN: enterpriseDN, SAMAccountName: "Enterprise Admins", Members: []string{"CN=Dave,CN=Users,DC=example,DC=com"}},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			schemaSID:     {DN: schemaDN, SID: schemaSID, EntityType: types.EntityTypeGroup},
			enterpriseSID: {DN: enterpriseDN, SID: enterpriseSID, EntityType: types.EntityTypeGroup},
		},
		IncludeDetails: true,
	}

	f := NewSchemaAdminsNotEmptyDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (only Enterprise Admins RID -519 has a member; the empty Schema Admins RID -518 group contributes nothing)", f.Count)
	}
	if len(f.AffectedEntities) != 1 {
		t.Fatalf("len(AffectedEntities) = %d, want 1 (the empty Schema Admins RID -518 group must not be listed alongside the non-empty Enterprise Admins RID -519 group)", len(f.AffectedEntities))
	}
}

// TestSchemaAdminsNotEmpty_SharedMemberCountedPerGroup specifies the current,
// documented double-counting behavior: a DN that is a member of both target
// groups (RID -518 and RID -519) is counted once per group membership, not
// deduplicated across groups. Count is the sum of membership counts, as the
// finding's own Description says ("%d total member(s) across %d group(s)").
// This kills a mutation that deduplicates members across groups, which
// would otherwise collapse this Count from 2 to 1.
func TestSchemaAdminsNotEmpty_SharedMemberCountedPerGroup(t *testing.T) {
	schemaDN := "CN=Schema Admins,CN=Users,DC=example,DC=com"
	enterpriseDN := "CN=Enterprise Admins,CN=Users,DC=example,DC=com"
	sharedMemberDN := "CN=Eve,CN=Users,DC=example,DC=com"
	schemaSID := schemaAdminsTestDomainSID + "-518"
	enterpriseSID := schemaAdminsTestDomainSID + "-519"

	data := &audit.DetectorData{
		Groups: []types.Group{
			{DN: schemaDN, SAMAccountName: "Schema Admins", Members: []string{sharedMemberDN}},
			{DN: enterpriseDN, SAMAccountName: "Enterprise Admins", Members: []string{sharedMemberDN}},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			schemaSID:     {DN: schemaDN, SID: schemaSID, EntityType: types.EntityTypeGroup},
			enterpriseSID: {DN: enterpriseDN, SID: enterpriseSID, EntityType: types.EntityTypeGroup},
		},
		IncludeDetails: true,
	}

	f := NewSchemaAdminsNotEmptyDetector().Detect(context.Background(), data)[0]
	if f.Count != 2 {
		t.Fatalf("Count = %d, want 2 (CN=Eve is a member of both RID -518 and RID -519; it is counted once per group membership, not deduplicated across groups)", f.Count)
	}
}
