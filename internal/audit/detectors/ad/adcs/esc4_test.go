package adcs

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

const (
	esc4DomainDN  = "DC=example,DC=com"
	esc4DomainSID = "S-1-5-21-1234567890-1111111111-2222222222"
	esc4Attacker  = esc4DomainSID + "-93801"
	esc4ConfigDN  = "CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com"
	esc4CADN      = "CN=CorpCA,CN=Enrollment Services," + esc4ConfigDN
)

// esc4PublishingCA returns a single enterprise CA that publishes every name
// in names - the baseline every pre-existing test now needs since ESC4 only
// counts a template that is actually requestable (published on an enterprise
// CA).
func esc4PublishingCA(names ...string) []types.CertAuthority {
	return []types.CertAuthority{
		{DN: esc4CADN, Name: "CorpCA", PublishedTemplates: names},
	}
}

// TestESC4_EntityOrderIsDeterministic: affectedTemplates
// is a map keyed by template DN, so ranging it directly to build entities
// would give a randomized order per process. With several vulnerable
// templates, an unsorted range would very rarely land in DN order by chance
// across repeated calls - asserting the exact expected order pins the sort.
func TestESC4_EntityOrderIsDeterministic(t *testing.T) {
	names := []string{"Zeta", "Alpha", "Mike", "Bravo"}
	var templates []types.CertTemplate
	var aces []types.ACLEntry
	for _, n := range names {
		dn := "CN=" + n + "," + esc4ConfigDN
		templates = append(templates, types.CertTemplate{DN: dn, Name: n})
		aces = append(aces, types.ACLEntry{
			ObjectDN: dn, Trustee: esc4Attacker, AccessMask: GenericAll, AceType: "ACCESS_ALLOWED",
		})
	}

	want := []string{"CN=Alpha," + esc4ConfigDN, "CN=Bravo," + esc4ConfigDN, "CN=Mike," + esc4ConfigDN, "CN=Zeta," + esc4ConfigDN}

	data := &audit.DetectorData{
		IncludeDetails:  true,
		DomainInfo:      &types.DomainInfo{DomainDN: esc4DomainDN, DomainSID: esc4DomainSID},
		CertTemplates:   templates,
		ACLEntries:      aces,
		CertAuthorities: esc4PublishingCA(names...),
	}

	for i := 0; i < 5; i++ {
		findings := NewESC4Detector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("run %d: expected exactly 1 finding, got %d", i, len(findings))
		}
		ents := findings[0].AffectedEntities
		if len(ents) != len(want) {
			t.Fatalf("run %d: expected %d entities, got %d", i, len(want), len(ents))
		}
		for j, ent := range ents {
			if ent.DN != want[j] {
				t.Fatalf("run %d: entity order not deterministic - position %d = %q, want %q", i, j, ent.DN, want[j])
			}
		}
	}
}

// TestESC4_ScopedWritePropertyNotFlagged_UnscopedIs covers the ecart: an
// ACCESS_ALLOWED_OBJECT WriteProperty ACE with an ObjectType GUID grants write
// access to a single attribute only, not to the whole template. Per
// SpecterOps, Certify wiki, ESC4 ("Vulnerable Certificate Template Access
// Control"), the dangerous "Write Property" case is described as "generic
// write on the object [that] can edit any property" - i.e. only an ACE with
// no ObjectType restriction (empty string here) is equivalent to that. Before
// the fix, isDangerousAccessMask ignored ObjectType entirely, so a template
// whose only non-admin grant was a single scoped attribute write was
// incorrectly reported as vulnerable - exactly the "default ACL noise" this
// ecart flagged.
func TestESC4_ScopedWritePropertyNotFlagged_UnscopedIs(t *testing.T) {
	scopedDN := "CN=Scoped," + esc4ConfigDN
	unscopedDN := "CN=Unscoped," + esc4ConfigDN

	data := &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DomainDN: esc4DomainDN, DomainSID: esc4DomainSID},
		CertTemplates: []types.CertTemplate{
			{DN: scopedDN, Name: "Scoped"},
			{DN: unscopedDN, Name: "Unscoped"},
		},
		CertAuthorities: esc4PublishingCA("Scoped", "Unscoped"),
		ACLEntries: []types.ACLEntry{
			// WriteProperty scoped to a single, unrelated attribute - must NOT count.
			{ObjectDN: scopedDN, Trustee: esc4Attacker, AccessMask: WriteProperty, AceType: "ACCESS_ALLOWED", ObjectType: "bf967a86-0de6-11d0-a285-00aa003049e2"},
			// WriteProperty with no ObjectType restriction - grants write to every property, must count.
			{ObjectDN: unscopedDN, Trustee: esc4Attacker, AccessMask: WriteProperty, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewESC4Detector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("count = %d, want 1 (only the unscoped WriteProperty template should be flagged)", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].DN != unscopedDN {
		t.Fatalf("affected entities = %+v, want only %q", findings[0].AffectedEntities, unscopedDN)
	}
}

// TestESC4_GenericWriteIsDangerous covers the ecart: GenericWrite was declared
// as a constant and named in this detector's own remediation text
// ("Remove GenericAll, GenericWrite, WriteDACL, ...") but isDangerousAccessMask
// never actually tested the mask against it - a template whose only non-admin
// ACE granted GenericWrite (and nothing else) was silently never reported, a
// real under-reporting bug independent of any external source.
func TestESC4_GenericWriteIsDangerous(t *testing.T) {
	dn := "CN=GW," + esc4ConfigDN
	data := &audit.DetectorData{
		DomainInfo:      &types.DomainInfo{DomainDN: esc4DomainDN, DomainSID: esc4DomainSID},
		CertTemplates:   []types.CertTemplate{{DN: dn, Name: "GW"}},
		CertAuthorities: esc4PublishingCA("GW"),
		ACLEntries: []types.ACLEntry{
			{ObjectDN: dn, Trustee: esc4Attacker, AccessMask: GenericWrite, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewESC4Detector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("a GenericWrite-only ACE on a non-admin principal should be flagged as dangerous; got findings=%+v", findings)
	}
}

// TestESC4_ServerOperatorsExcluded covers the ecart: the previous admin
// exclusion list (isAdminSID) only covered Domain/Enterprise/Schema Admins,
// built-in Administrators, SYSTEM and Account Operators. Server Operators is
// a well-known BUILTIN privileged group; a default/expected grant to it on a
// certificate template was incorrectly reported as an ESC4 finding. The
// detector now reuses audit.IsPrivilegedSID, the same canonical exclusion
// list every other ACL detector in this codebase relies on, which also
// covers Server/Print/Backup Operators and Key Admins.
func TestESC4_ServerOperatorsExcluded(t *testing.T) {
	dn := "CN=SO," + esc4ConfigDN
	const serverOperators = "S-1-5-32-549" // BUILTIN\Server Operators

	data := &audit.DetectorData{
		DomainInfo:      &types.DomainInfo{DomainDN: esc4DomainDN, DomainSID: esc4DomainSID},
		CertTemplates:   []types.CertTemplate{{DN: dn, Name: "SO"}},
		CertAuthorities: esc4PublishingCA("SO"),
		ACLEntries: []types.ACLEntry{
			{ObjectDN: dn, Trustee: serverOperators, AccessMask: GenericAll, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewESC4Detector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("Server Operators holding GenericAll should be excluded as a default privileged grant; got findings=%+v", findings)
	}
}

// TestESC4_DeniedGenericAllNotCounted covers V8 ecart 1 (ANALYSE.md, Ecart a
// arbitrer, point 1): esc4.go used `strings.ToLower(acl.AceType) == "deny"`
// to skip deny ACEs, but the parser never produces a bare "deny" AceType (it
// emits ACCESS_ALLOWED/ACCESS_ALLOWED_OBJECT/ACCESS_DENIED/...), so that
// comparison could never be true and a dangerous ACCESS_DENIED ACE was
// counted as if it granted access. The fix uses !audit.IsGrantACE(AceType).
func TestESC4_DeniedGenericAllNotCounted(t *testing.T) {
	dn := "CN=Denied," + esc4ConfigDN

	data := &audit.DetectorData{
		DomainInfo:      &types.DomainInfo{DomainDN: esc4DomainDN, DomainSID: esc4DomainSID},
		CertTemplates:   []types.CertTemplate{{DN: dn, Name: "Denied"}},
		CertAuthorities: esc4PublishingCA("Denied"),
		ACLEntries: []types.ACLEntry{
			{ObjectDN: dn, Trustee: esc4Attacker, AccessMask: GenericAll, AceType: "ACCESS_DENIED"},
		},
	}

	findings := NewESC4Detector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("an ACCESS_DENIED GenericAll ACE from a standard user must not be counted; got findings=%+v", findings)
	}
}

// TestESC4_SelfCreatorOwnerEnterpriseDCExcluded covers V8 ecart 2 (ANALYSE.md,
// Ecart a arbitrer, point 2): the old isAdminSID(sid, domainSID) only checked
// sid == "S-1-5-18" (SYSTEM) and audit.IsPrivilegedSID, so an ACE granted to
// SELF (S-1-5-10), CREATOR OWNER (S-1-3-0) or Enterprise Domain Controllers
// (S-1-5-9) - all built-in principals AD itself grants broad rights to by
// design - was still counted. The fix uses audit.IsBuiltinAdminTrustee, whose
// builtinAdminSIDs table covers all three.
func TestESC4_SelfCreatorOwnerEnterpriseDCExcluded(t *testing.T) {
	cases := []struct {
		name string
		sid  string
	}{
		{"SELF", "S-1-5-10"},
		{"CREATOR_OWNER", "S-1-3-0"},
		{"ENTERPRISE_DOMAIN_CONTROLLERS", "S-1-5-9"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dn := "CN=" + tc.name + "," + esc4ConfigDN
			data := &audit.DetectorData{
				DomainInfo:      &types.DomainInfo{DomainDN: esc4DomainDN, DomainSID: esc4DomainSID},
				CertTemplates:   []types.CertTemplate{{DN: dn, Name: tc.name}},
				CertAuthorities: esc4PublishingCA(tc.name),
				ACLEntries: []types.ACLEntry{
					{ObjectDN: dn, Trustee: tc.sid, AccessMask: GenericAll, AceType: "ACCESS_ALLOWED"},
				},
			}

			findings := NewESC4Detector().Detect(context.Background(), data)
			if len(findings) != 1 || findings[0].Count != 0 {
				t.Fatalf("GenericAll granted to %s (%s) must not be counted; got findings=%+v", tc.name, tc.sid, findings)
			}
		})
	}
}

// TestESC4_NonAdminOwnerCounted covers V8 ecart 3 (ANALYSE.md, Ecart a
// arbitrer, point 3): the Description advertises "Owner-equivalent" as a
// counted condition, but data.ObjectOwners was only read for display
// (helpers.CertTemplateToAffectedEntityWithACL), never to decide Count. A
// template whose owner is a standard, non-admin principal must now be
// counted even with no dangerous ACE at all.
func TestESC4_NonAdminOwnerCounted(t *testing.T) {
	dn := "CN=OwnedByUser," + esc4ConfigDN

	data := &audit.DetectorData{
		DomainInfo:      &types.DomainInfo{DomainDN: esc4DomainDN, DomainSID: esc4DomainSID},
		CertTemplates:   []types.CertTemplate{{DN: dn, Name: "OwnedByUser"}},
		CertAuthorities: esc4PublishingCA("OwnedByUser"),
		ObjectOwners:    map[string]string{dn: esc4Attacker},
	}

	findings := NewESC4Detector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("a template owned by a non-admin principal must be counted even without a dangerous ACE; got findings=%+v", findings)
	}
}

// TestESC4_AdminOwnerNotCounted is the control for TestESC4_NonAdminOwnerCounted:
// a template owned by Domain Admins (a built-in administrative principal) must
// not be counted on ownership alone.
func TestESC4_AdminOwnerNotCounted(t *testing.T) {
	dn := "CN=OwnedByAdmins," + esc4ConfigDN
	domainAdmins := esc4DomainSID + "-512"

	data := &audit.DetectorData{
		DomainInfo:      &types.DomainInfo{DomainDN: esc4DomainDN, DomainSID: esc4DomainSID},
		CertTemplates:   []types.CertTemplate{{DN: dn, Name: "OwnedByAdmins"}},
		CertAuthorities: esc4PublishingCA("OwnedByAdmins"),
		ObjectOwners:    map[string]string{dn: domainAdmins},
	}

	findings := NewESC4Detector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("a template owned by Domain Admins must not be counted on ownership alone; got findings=%+v", findings)
	}
}

// TestESC4_DangerousACEAndNonAdminOwnerCountedOnce covers the overlap of V8
// ecart 3: a template that has both a dangerous ACE AND a non-admin owner
// must still be counted exactly once, not twice.
func TestESC4_DangerousACEAndNonAdminOwnerCountedOnce(t *testing.T) {
	dn := "CN=Both," + esc4ConfigDN

	data := &audit.DetectorData{
		DomainInfo:      &types.DomainInfo{DomainDN: esc4DomainDN, DomainSID: esc4DomainSID},
		CertTemplates:   []types.CertTemplate{{DN: dn, Name: "Both"}},
		CertAuthorities: esc4PublishingCA("Both"),
		ObjectOwners:    map[string]string{dn: esc4Attacker},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: dn, Trustee: esc4Attacker, AccessMask: GenericAll, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewESC4Detector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("a template flagged by both a dangerous ACE and a non-admin owner must be counted once; got findings=%+v", findings)
	}
}

// TestESC4_SilentWhenTemplateNotPublished covers the V8 ecart a: a
// template not published on ANY enterprise CA is not requestable by anyone,
// so a dangerous ACE on it must not be counted. Before the fix, ESC4 never
// checked data.CertAuthorities at all and would have counted this.
func TestESC4_SilentWhenTemplateNotPublished(t *testing.T) {
	dn := "CN=NotPublished," + esc4ConfigDN

	data := &audit.DetectorData{
		DomainInfo:      &types.DomainInfo{DomainDN: esc4DomainDN, DomainSID: esc4DomainSID},
		CertTemplates:   []types.CertTemplate{{DN: dn, Name: "NotPublished"}},
		CertAuthorities: esc4PublishingCA("SomeOtherTemplate"),
		ACLEntries: []types.ACLEntry{
			{ObjectDN: dn, Trustee: esc4Attacker, AccessMask: GenericAll, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewESC4Detector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("a template not published on any CA is not requestable and must not be counted; got findings=%+v", findings)
	}
}

// TestESC4_SilentWhenNoCertAuthorities covers the V8 ecart a: with no
// CertAuthorities collected at all, no template can be considered published,
// so ESC4 must not count any template regardless of its ACEs.
func TestESC4_SilentWhenNoCertAuthorities(t *testing.T) {
	dn := "CN=NoCA," + esc4ConfigDN

	data := &audit.DetectorData{
		DomainInfo:    &types.DomainInfo{DomainDN: esc4DomainDN, DomainSID: esc4DomainSID},
		CertTemplates: []types.CertTemplate{{DN: dn, Name: "NoCA"}},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: dn, Trustee: esc4Attacker, AccessMask: GenericAll, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewESC4Detector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("with no CertAuthorities collected, no template is requestable and none must be counted; got findings=%+v", findings)
	}
}
