package monitoring

import (
	"context"
	"testing"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func TestAnonymousLdapAccess_NilDomainInfoNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: nil,
	}
	findings := NewAnonymousLdapAccessDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 when DomainInfo is nil", findings[0].Count)
	}
}

func TestAnonymousLdapAccess_BlockedNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{
			DomainDN:             "DC=example,DC=com",
			AnonymousLDAPAllowed: false,
		},
	}
	findings := NewAnonymousLdapAccessDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 when AnonymousLDAPAllowed is false", findings[0].Count)
	}
}

func TestAnonymousLdapAccess_AllowedFlagged(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{
			DomainDN:             "DC=example,DC=com",
			AnonymousLDAPAllowed: true,
		},
	}
	findings := NewAnonymousLdapAccessDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 when AnonymousLDAPAllowed is true", f.Count)
	}
	if f.Type != "ANONYMOUS_LDAP_ACCESS" {
		t.Fatalf("Type = %q, want %q", f.Type, "ANONYMOUS_LDAP_ACCESS")
	}
	if f.Severity != types.SeverityMedium {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityMedium)
	}
	if f.Category != "advanced" {
		t.Fatalf("Category = %q, want %q", f.Category, "advanced")
	}
}

func TestAnonymousLdapAccess_DetailsOnlyWhenRequested(t *testing.T) {
	t.Run("IncludeDetails false: no entities, no details", func(t *testing.T) {
		data := &audit.DetectorData{
			DomainInfo: &types.DomainInfo{
				DomainDN:             "DC=example,DC=com",
				AnonymousLDAPAllowed: true,
			},
			IncludeDetails: false,
		}
		findings := NewAnonymousLdapAccessDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		f := findings[0]
		if len(f.AffectedEntities) != 0 {
			t.Fatalf("AffectedEntities = %v, want none when IncludeDetails is false", f.AffectedEntities)
		}
		if f.Details != nil {
			t.Fatalf("Details = %v, want nil when IncludeDetails is false", f.Details)
		}
	})

	t.Run("IncludeDetails true: one domain entity", func(t *testing.T) {
		data := &audit.DetectorData{
			DomainInfo: &types.DomainInfo{
				DomainDN:             "DC=example,DC=com",
				AnonymousLDAPAllowed: true,
			},
			IncludeDetails: true,
		}
		findings := NewAnonymousLdapAccessDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		f := findings[0]
		if len(f.AffectedEntities) != 1 {
			t.Fatalf("AffectedEntities = %v, want exactly 1 entity when IncludeDetails is true", f.AffectedEntities)
		}
		if f.AffectedEntities[0].Type != types.EntityTypeDomain {
			t.Fatalf("AffectedEntities[0].Type = %q, want %q", f.AffectedEntities[0].Type, types.EntityTypeDomain)
		}
	})
}
