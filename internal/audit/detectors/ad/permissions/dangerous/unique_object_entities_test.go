package dangerous

import (
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestGetUniqueObjectEntities_DedupSameObjectDN pins the deduplication
// guard: two ACEs targeting the same ObjectDN must collapse into a single
// entity, not two.
func TestGetUniqueObjectEntities_DedupSameObjectDN(t *testing.T) {
	dn := "CN=srv02,OU=Servers,DC=example,DC=com"
	entries := []types.ACLEntry{
		{ObjectDN: dn, Trustee: "S-1-5-21-1-2-3-9020"},
		{ObjectDN: dn, Trustee: "S-1-5-21-1-2-3-9021"},
	}

	entities := audit.GetUniqueObjectEntities(entries, nil)
	if len(entities) != 1 {
		t.Fatalf("len(entities) = %d, want 1: two ACEs on the same ObjectDN must dedupe to one entity", len(entities))
	}
}

// TestGetUniqueObjectEntities_EmptyObjectDNIgnored pins the empty-DN guard:
// an ACE with no ObjectDN carries no resolvable target and must be skipped
// entirely, not emitted as an entity.
func TestGetUniqueObjectEntities_EmptyObjectDNIgnored(t *testing.T) {
	entries := []types.ACLEntry{
		{ObjectDN: "", Trustee: "S-1-5-21-1-2-3-9022"},
	}

	entities := audit.GetUniqueObjectEntities(entries, nil)
	if len(entities) != 0 {
		t.Fatalf("len(entities) = %d, want 0: an ACE with an empty ObjectDN must be ignored", len(entities))
	}
}

// TestGetUniqueObjectEntities_ResolvedViaByDN pins the byDN resolution
// path: when the ObjectDN is present in the cache, the entity must carry
// the typed fields from ObjectMeta (not the Unresolved principal fallback).
func TestGetUniqueObjectEntities_ResolvedViaByDN(t *testing.T) {
	dn := "CN=jdoe,OU=Users,DC=example,DC=com"
	entries := []types.ACLEntry{
		{ObjectDN: dn, Trustee: "S-1-5-21-1-2-3-9023"},
	}
	byDN := map[string]*audit.ObjectMeta{
		dn: {
			DN:             dn,
			SAMAccountName: "jdoe",
			Name:           "Jane Doe",
			EntityType:     types.EntityTypeUser,
		},
	}

	entities := audit.GetUniqueObjectEntities(entries, byDN)
	if len(entities) != 1 {
		t.Fatalf("len(entities) = %d, want 1", len(entities))
	}
	got := entities[0]
	if got.Unresolved {
		t.Fatalf("Unresolved = true, want false: ObjectDN is present in byDN")
	}
	if got.Type != types.EntityTypeUser {
		t.Fatalf("Type = %q, want %q", got.Type, types.EntityTypeUser)
	}
	if got.SAMAccountName != "jdoe" {
		t.Fatalf("SAMAccountName = %q, want %q", got.SAMAccountName, "jdoe")
	}
	if got.Name != "Jane Doe" {
		t.Fatalf("Name = %q, want %q", got.Name, "Jane Doe")
	}
}
