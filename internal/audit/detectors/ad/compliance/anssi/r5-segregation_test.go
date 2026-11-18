package anssi

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestR5Segregation_BackupOperatorsSpecialPrincipal covers the fact that Backup
// Operators is a domain-local Builtin group, so Everyone/Authenticated Users
// can be a member of it without that membership ever appearing in any real
// user's memberOf (Windows computes it at logon time, it never writes a
// per-user back-link). A user with exactly one OTHER privileged-group
// membership must now also be flagged once Backup Operators is open to
// everyone - before the fix, that case was structurally invisible no matter
// the real state of the domain.
func TestR5Segregation_BackupOperatorsSpecialPrincipal(t *testing.T) {
	const domainDN = "DC=example,DC=com"
	const r5BOTestDomainSID = "S-1-5-21-4444444444-5555555555-6666666666"
	accountOperatorsDN := "CN=Account Operators,CN=Builtin," + domainDN
	backupOperatorsDN := "CN=Backup Operators,CN=Builtin," + domainDN

	user := types.User{
		SAMAccountName: "svc.one",
		Disabled:       false, // enabled
		MemberOf:       []string{accountOperatorsDN},
	}

	tests := []struct {
		name          string
		groups        []types.Group
		wantFindCount int
	}{
		{
			name:          "no group data at all - one privileged group only, not flagged",
			groups:        nil,
			wantFindCount: 0,
		},
		{
			name: "Backup Operators has NO special principal member - still not flagged",
			groups: []types.Group{
				{DN: backupOperatorsDN, Members: []string{"CN=some.other.user," + domainDN}},
			},
			wantFindCount: 0,
		},
		{
			name: "Backup Operators open to Everyone (S-1-1-0) - now flagged",
			groups: []types.Group{
				{DN: backupOperatorsDN, Members: []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals," + domainDN}},
			},
			wantFindCount: 1,
		},
		{
			name: "Backup Operators open to Authenticated Users (S-1-5-11) - now flagged",
			groups: []types.Group{
				{DN: backupOperatorsDN, Members: []string{"CN=S-1-5-11,CN=ForeignSecurityPrincipals," + domainDN}},
			},
			wantFindCount: 1,
		},
		{
			name: "Backup Operators member is S-1-5-110 (unrelated, longer SID) - not Authenticated Users, not flagged",
			groups: []types.Group{
				{DN: backupOperatorsDN, Members: []string{"CN=S-1-5-110,CN=ForeignSecurityPrincipals," + domainDN}},
			},
			wantFindCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objectBySID := map[string]*audit.ObjectMeta{
				r5BOTestDomainSID + "-548": {DN: accountOperatorsDN, SID: r5BOTestDomainSID + "-548", EntityType: types.EntityTypeGroup},
			}
			if len(tt.groups) > 0 {
				objectBySID[r5BOTestDomainSID+"-551"] = &audit.ObjectMeta{DN: backupOperatorsDN, SID: r5BOTestDomainSID + "-551", EntityType: types.EntityTypeGroup}
			}
			data := &audit.DetectorData{
				Users:       []types.User{user},
				Groups:      tt.groups,
				ObjectBySID: objectBySID,
			}
			findings := NewR5SegregationDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding wrapper, got %d", len(findings))
			}
			if findings[0].Count != tt.wantFindCount {
				t.Errorf("Count = %d, want %d", findings[0].Count, tt.wantFindCount)
			}
		})
	}
}

// TestR5Segregation_HomonymPrivilegedGroupNotCounted proves the homonym
// fix: a user whose memberOf contains two groups bearing the exact English
// privileged-group names ("Domain Admins", "Schema Admins") but under RIDs
// that are NOT -512/-518 must not be treated as holding two privileged-Tier
// memberships. Main's strings.Contains(memberOf, "domain admins") (etc.)
// false-positives on this homonym pair.
func TestR5Segregation_HomonymPrivilegedGroupNotCounted(t *testing.T) {
	const domainSID = "S-1-5-21-7777777777-8888888888-9999999999"
	daHomonymDN := "CN=Domain Admins,OU=Decommissioned,DC=test,DC=local"
	saHomonymDN := "CN=Schema Admins,OU=Decommissioned,DC=test,DC=local"

	data := &audit.DetectorData{
		Users: []types.User{
			{
				SAMAccountName: "svc.homonym",
				Disabled:       false,
				MemberOf:       []string{daHomonymDN, saHomonymDN},
			},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			domainSID + "-3001": {DN: daHomonymDN, SID: domainSID + "-3001", EntityType: types.EntityTypeGroup},
			domainSID + "-3002": {DN: saHomonymDN, SID: domainSID + "-3002", EntityType: types.EntityTypeGroup},
		},
	}

	findings := NewR5SegregationDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected the two homonym groups (non-privileged RIDs) to NOT be counted as privileged, got %+v", findings)
	}
}

// TestR5Segregation_LocalizedPrivilegedGroupCounted proves the SID fix: a
// user who is a member of a localized-CN Domain Admins group (real -512
// RID) AND a real Schema Admins group must be flagged for holding two
// privileged-Tier memberships, even though main's CN-substring match can
// never recognize the localized CN.
func TestR5Segregation_LocalizedPrivilegedGroupCounted(t *testing.T) {
	const domainSID = "S-1-5-21-1212121212-3434343434-5656565656"
	localizedDADN := "CN=Admins du domaine,CN=Users,DC=corp,DC=local"
	schemaAdminsDN := "CN=Schema Admins,CN=Users,DC=corp,DC=local"

	data := &audit.DetectorData{
		Users: []types.User{
			{
				SAMAccountName: "admin.localise",
				Disabled:       false,
				MemberOf:       []string{localizedDADN, schemaAdminsDN},
			},
		},
		ObjectBySID: map[string]*audit.ObjectMeta{
			domainSID + "-512": {DN: localizedDADN, SID: domainSID + "-512", EntityType: types.EntityTypeGroup},
			domainSID + "-518": {DN: schemaAdminsDN, SID: domainSID + "-518", EntityType: types.EntityTypeGroup},
		},
	}

	findings := NewR5SegregationDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected the localized Domain Admins + Schema Admins membership to be flagged, got %+v", findings)
	}
}

// TestR5Segregation_EnterpriseAdminsCountsAsTier proves Enterprise Admins
// (-519) is itself one of the privileged-Tier groups: a user who is a member
// of BOTH Enterprise Admins and Domain Admins must be flagged for holding two
// privileged-Tier memberships, while a user who is a member of Enterprise
// Admins alone must not be flagged.
func TestR5Segregation_EnterpriseAdminsCountsAsTier(t *testing.T) {
	const domainSID = "S-1-5-21-1357913579-2468024680-1122334455"
	enterpriseAdminsDN := "CN=Enterprise Admins,CN=Users,DC=example,DC=com"
	domainAdminsDN := "CN=Domain Admins,CN=Users,DC=example,DC=com"

	objectBySID := map[string]*audit.ObjectMeta{
		domainSID + "-519": {DN: enterpriseAdminsDN, SID: domainSID + "-519", EntityType: types.EntityTypeGroup},
		domainSID + "-512": {DN: domainAdminsDN, SID: domainSID + "-512", EntityType: types.EntityTypeGroup},
	}

	tests := []struct {
		name          string
		memberOf      []string
		wantFindCount int
	}{
		{
			name:          "member of Enterprise Admins and Domain Admins - flagged",
			memberOf:      []string{enterpriseAdminsDN, domainAdminsDN},
			wantFindCount: 1,
		},
		{
			name:          "member of Enterprise Admins alone - not flagged",
			memberOf:      []string{enterpriseAdminsDN},
			wantFindCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &audit.DetectorData{
				Users: []types.User{
					{
						SAMAccountName: "svc.enterprise",
						Disabled:       false,
						MemberOf:       tt.memberOf,
					},
				},
				ObjectBySID: objectBySID,
			}
			findings := NewR5SegregationDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding wrapper, got %d", len(findings))
			}
			if findings[0].Count != tt.wantFindCount {
				t.Errorf("Count = %d, want %d", findings[0].Count, tt.wantFindCount)
			}
		})
	}
}

// TestR5Segregation_DisabledAccountExcluded proves the Enabled() guard: a
// DISABLED account holding direct membership in both Domain Admins (-512)
// and Enterprise Admins (-519) must not be flagged (Count 0), while the same
// account, enabled, with the exact same dual membership must be flagged
// (Count 1). Backup Operators is not open to any special principal in this
// fixture, so the disabled/enabled distinction is isolated to the Enabled()
// guard alone.
func TestR5Segregation_DisabledAccountExcluded(t *testing.T) {
	const domainSID = "S-1-5-21-1928374655-8172635940-5647382910"
	domainAdminsDN := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	enterpriseAdminsDN := "CN=Enterprise Admins,CN=Users,DC=example,DC=com"

	objectBySID := map[string]*audit.ObjectMeta{
		domainSID + "-512": {DN: domainAdminsDN, SID: domainSID + "-512", EntityType: types.EntityTypeGroup},
		domainSID + "-519": {DN: enterpriseAdminsDN, SID: domainSID + "-519", EntityType: types.EntityTypeGroup},
	}

	tests := []struct {
		name          string
		disabled      bool
		uac           int
		wantFindCount int
	}{
		{
			name:          "disabled account in both Tier groups - not flagged",
			disabled:      true,
			uac:           types.UACAccountDisabled,
			wantFindCount: 0,
		},
		{
			name:          "same account enabled - flagged",
			disabled:      false,
			uac:           0,
			wantFindCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &audit.DetectorData{
				Users: []types.User{
					{
						SAMAccountName:     "svc.tier-overlap",
						Disabled:           tt.disabled,
						UserAccountControl: tt.uac,
						MemberOf:           []string{domainAdminsDN, enterpriseAdminsDN},
					},
				},
				ObjectBySID: objectBySID,
			}
			findings := NewR5SegregationDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding wrapper, got %d", len(findings))
			}
			if findings[0].Count != tt.wantFindCount {
				t.Errorf("Count = %d, want %d", findings[0].Count, tt.wantFindCount)
			}
		})
	}
}

// TestR5Segregation_AdminCountAloneNotFlagged: a prior second
// check flagged any user with AdminCount=true and no SPN as a "standard user
// with admin privileges" once more than 20 such users existed. That check
// was internally contradictory - adminSDHolder sets AdminCount=true
// precisely because an account IS/WAS privileged (PA-099 p.40 footnote 16),
// never because it is a standard user - and had no ANSSI source for the >20
// threshold, so it was removed. Before the fix, 21 enabled AdminCount users
// with a single, non-overlapping privileged-group membership each produced
// Count=1 via that check alone; after the fix it must produce Count=0.
func TestR5Segregation_AdminCountAloneNotFlagged(t *testing.T) {
	const domainSID = "S-1-5-21-2222222222-3333333333-4444444444"
	daDN := "CN=Domain Admins,CN=Users,DC=example,DC=com"

	var users []types.User
	for i := 0; i < 21; i++ {
		users = append(users, types.User{
			SAMAccountName: "priv.user",
			Disabled:       false,
			AdminCount:     true,
			MemberOf:       []string{daDN},
		})
	}

	data := &audit.DetectorData{
		Users: users,
		ObjectBySID: map[string]*audit.ObjectMeta{
			domainSID + "-512": {DN: daDN, SID: domainSID + "-512", EntityType: types.EntityTypeGroup},
		},
	}
	findings := NewR5SegregationDetector().Detect(context.Background(), data)

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding wrapper, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Errorf("Count = %d, want 0 (AdminCount alone must not be flagged as a standard-user violation)", findings[0].Count)
	}
}

// TestR5Segregation_SpecialPrincipalOnlyCountsInBackupOperators proves that
// groupOpenToSpecialPrincipal only credits a group open to Everyone/
// Authenticated Users toward the Backup-Operators-open signal when that
// group actually resolves (via groupDNs) to Backup Operators itself. An
// ordinary group that happens to list Everyone as a raw member must not
// make the detector treat Backup Operators as open.
func TestR5Segregation_SpecialPrincipalOnlyCountsInBackupOperators(t *testing.T) {
	const domainSID = "S-1-5-21-2020202020-3030303030-4040404040"
	domainAdminsDN := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	backupOperatorsDN := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
	ordinaryGroupDN := "CN=Project Reviewers,OU=Groups,DC=example,DC=com"

	objectBySID := map[string]*audit.ObjectMeta{
		domainSID + "-512": {DN: domainAdminsDN, SID: domainSID + "-512", EntityType: types.EntityTypeGroup},
		domainSID + "-551": {DN: backupOperatorsDN, SID: domainSID + "-551", EntityType: types.EntityTypeGroup},
	}

	tests := []struct {
		name          string
		groups        []types.Group
		wantFindCount int
	}{
		{
			name: "ordinary group open to Everyone, Backup Operators closed, account only in -512 - clean",
			groups: []types.Group{
				{DN: ordinaryGroupDN, Members: []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=example,DC=com"}},
				{DN: backupOperatorsDN, Members: []string{"CN=some.other.user,DC=example,DC=com"}},
			},
			wantFindCount: 0,
		},
		{
			name: "Backup Operators open to Everyone, account only in -512 - flagged",
			groups: []types.Group{
				{DN: backupOperatorsDN, Members: []string{"CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=example,DC=com"}},
			},
			wantFindCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &audit.DetectorData{
				Users: []types.User{
					{
						SAMAccountName: "svc.dnfilter",
						Disabled:       false,
						MemberOf:       []string{domainAdminsDN},
					},
				},
				Groups:      tt.groups,
				ObjectBySID: objectBySID,
			}
			findings := NewR5SegregationDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding wrapper, got %d", len(findings))
			}
			if findings[0].Count != tt.wantFindCount {
				t.Errorf("Count = %d, want %d", findings[0].Count, tt.wantFindCount)
			}
		})
	}
}

// TestR5Segregation_DirectBackupOperatorsMemberCounted proves that a user's
// own, direct membership in Backup Operators (resolved by SID -551, as in
// TestR5Segregation_SpecialPrincipalOnlyCountsInBackupOperators) is counted
// toward the Tier-overlap total even when Backup Operators is NOT open to
// any special principal (backupOpsOpenToAll stays false): that credit comes
// only from the per-user IsMemberOfAny(u.MemberOf, backupOpsDNs) check.
func TestR5Segregation_DirectBackupOperatorsMemberCounted(t *testing.T) {
	const domainSID = "S-1-5-21-1111222233-4444555566-7777888899"
	domainAdminsDN := "CN=Domain Admins,CN=Users,DC=example,DC=com"
	backupOperatorsDN := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"

	objectBySID := map[string]*audit.ObjectMeta{
		domainSID + "-512": {DN: domainAdminsDN, SID: domainSID + "-512", EntityType: types.EntityTypeGroup},
		domainSID + "-551": {DN: backupOperatorsDN, SID: domainSID + "-551", EntityType: types.EntityTypeGroup},
	}
	// Backup Operators closed: no special-principal member at all.
	closedBackupOps := []types.Group{
		{DN: backupOperatorsDN, Members: []string{"CN=some.other.user,DC=example,DC=com"}},
	}

	tests := []struct {
		name          string
		disabled      bool
		memberOf      []string
		wantFindCount int
	}{
		{
			name:          "active account in Domain Admins and Backup Operators - flagged",
			disabled:      false,
			memberOf:      []string{domainAdminsDN, backupOperatorsDN},
			wantFindCount: 1,
		},
		{
			name:          "active account in Backup Operators alone - not flagged",
			disabled:      false,
			memberOf:      []string{backupOperatorsDN},
			wantFindCount: 0,
		},
		{
			name:          "active account in Domain Admins alone, not a Backup Operators member - not flagged",
			disabled:      false,
			memberOf:      []string{domainAdminsDN},
			wantFindCount: 0,
		},
		{
			name:          "disabled account in Domain Admins and Backup Operators - not flagged",
			disabled:      true,
			memberOf:      []string{domainAdminsDN, backupOperatorsDN},
			wantFindCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &audit.DetectorData{
				Users: []types.User{
					{
						SAMAccountName: "svc.directbackupops",
						Disabled:       tt.disabled,
						MemberOf:       tt.memberOf,
					},
				},
				Groups:      closedBackupOps,
				ObjectBySID: objectBySID,
			}
			findings := NewR5SegregationDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding wrapper, got %d", len(findings))
			}
			if findings[0].Count != tt.wantFindCount {
				t.Errorf("Count = %d, want %d", findings[0].Count, tt.wantFindCount)
			}
		})
	}
}

// TestR5Segregation_RIDSuffixRequiresDash proves that privilegedTierSIDSuffixes
// matches are anchored on the dash: a group whose SID merely ends in the same
// digits as a privileged RID (e.g. "...-96519" for Enterprise Admins' "-519",
// or "...-96518" for Schema Admins' "-518") without the group actually being
// that privileged group must not be counted as a Tier membership.
func TestR5Segregation_RIDSuffixRequiresDash(t *testing.T) {
	const domainSID = "S-1-5-21-5050505050-6060606060-7070707070"
	domainAdminsDN := "CN=Domain Admins,CN=Users,DC=example,DC=com"

	tests := []struct {
		name        string
		lookalikeDN string
		ridSuffix   string
	}{
		{
			name:        "group SID ends in -96519, not Enterprise Admins' -519",
			lookalikeDN: "CN=Regional Approvers,OU=Groups,DC=example,DC=com",
			ridSuffix:   "-96519",
		},
		{
			name:        "group SID ends in -96518, not Schema Admins' -518",
			lookalikeDN: "CN=Change Reviewers,OU=Groups,DC=example,DC=com",
			ridSuffix:   "-96518",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookalikeSID := domainSID + tt.ridSuffix
			data := &audit.DetectorData{
				Users: []types.User{
					{
						SAMAccountName: "svc.ridsuffix",
						Disabled:       false,
						MemberOf:       []string{domainAdminsDN, tt.lookalikeDN},
					},
				},
				ObjectBySID: map[string]*audit.ObjectMeta{
					domainSID + "-512": {DN: domainAdminsDN, SID: domainSID + "-512", EntityType: types.EntityTypeGroup},
					lookalikeSID:        {DN: tt.lookalikeDN, SID: lookalikeSID, EntityType: types.EntityTypeGroup},
				},
			}
			findings := NewR5SegregationDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding wrapper, got %d", len(findings))
			}
			if findings[0].Count != 0 {
				t.Errorf("Count = %d, want 0 (RID suffix match must require the dash)", findings[0].Count)
			}
		})
	}
}

// TestR5Segregation_MemberSIDWithoutComma kills the surviving, non-equivalent
// mutation of the comma guard at r5-segregation.go:167
// (`if idx := strings.IndexByte(member, ','); idx >= 0 { first = member[:idx] }`).
// Replacing it with the unconditional, compiling form
// `idx0 := strings.IndexByte(member, ','); first = member[:idx0]` passes
// every pre-existing test (every fixture's raw member already carries a
// comma) but panics ("slice bounds out of range [:-1]") the moment memberSID
// is given a value with no comma at all, because IndexByte then returns -1
// and member[:-1] is an invalid negative slice index. A member without a
// comma must instead fall through unchanged (optionally stripped of a
// leading "attr=").
func TestR5Segregation_MemberSIDWithoutComma(t *testing.T) {
	tests := []struct {
		name   string
		member string
		want   string
	}{
		{name: "raw SID, no comma, no equals sign", member: "S-1-1-0", want: "S-1-1-0"},
		{name: "attr=value, no comma", member: "CN=S-1-5-11", want: "S-1-5-11"},
		{name: "raw SID, no comma, padded with spaces", member: " S-1-1-0 ", want: "S-1-1-0"},
		{name: "attr=value WITH comma (regression, existing shape)", member: "CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=example,DC=com", want: "S-1-1-0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := memberSID(tt.member)
			if got != tt.want {
				t.Errorf("memberSID(%q) = %q, want %q", tt.member, got, tt.want)
			}
		})
	}

	t.Run("detector: Backup Operators member without a comma still opens it to Everyone, no panic", func(t *testing.T) {
		const domainSID = "S-1-5-21-3141592653-5897932384-6264338327"
		domainAdminsDN := "CN=Domain Admins,CN=Users,DC=example,DC=com"
		backupOperatorsDN := "CN=Backup Operators,CN=Builtin,DC=example,DC=com"

		objectBySID := map[string]*audit.ObjectMeta{
			domainSID + "-512": {DN: domainAdminsDN, SID: domainSID + "-512", EntityType: types.EntityTypeGroup},
			domainSID + "-551": {DN: backupOperatorsDN, SID: domainSID + "-551", EntityType: types.EntityTypeGroup},
		}
		data := &audit.DetectorData{
			Users: []types.User{
				{
					SAMAccountName: "svc.nocommamember",
					Disabled:       false,
					MemberOf:       []string{domainAdminsDN},
				},
			},
			Groups: []types.Group{
				{DN: backupOperatorsDN, Members: []string{"S-1-1-0"}},
			},
			ObjectBySID: objectBySID,
		}

		findings := NewR5SegregationDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding wrapper, got %d", len(findings))
		}
		if findings[0].Count != 1 {
			t.Errorf("Count = %d, want 1 (Backup Operators open to Everyone via a raw, comma-less member, on top of the Domain Admins membership)", findings[0].Count)
		}
	})
}
