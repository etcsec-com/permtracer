package ldap

import (
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/etcsec-com/permtracer/pkg/types"
)

// TestApplyDomainPolicyAttrs_IntegerFieldsAndAliases uses three distinct
// literal values so that swapping either alias assignment, or swapping the
// lockoutThreshold getter for another attribute's getter, produces a visibly
// wrong field instead of one that happens to match by coincidence.
func TestApplyDomainPolicyAttrs_IntegerFieldsAndAliases(t *testing.T) {
	entry := ldap.NewEntry("CN=contoso,DC=contoso,DC=com", map[string][]string{
		"minPwdLength":     {"12"},
		"pwdHistoryLength": {"24"},
		"lockoutThreshold": {"5"},
	})

	info := &types.DomainInfo{}
	applyDomainPolicyAttrs(info, entry)

	if info.MinPasswordLength != 12 {
		t.Fatalf("MinPasswordLength = %d, want 12", info.MinPasswordLength)
	}
	if info.MinPwdLength != 12 {
		t.Fatalf("MinPwdLength (alias) = %d, want 12", info.MinPwdLength)
	}
	if info.PasswordHistoryLength != 24 {
		t.Fatalf("PasswordHistoryLength = %d, want 24", info.PasswordHistoryLength)
	}
	if info.PwdHistoryLength != 24 {
		t.Fatalf("PwdHistoryLength (alias) = %d, want 24", info.PwdHistoryLength)
	}
	if info.LockoutThreshold != 5 {
		t.Fatalf("LockoutThreshold = %d, want 5", info.LockoutThreshold)
	}
}

// TestApplyDomainPolicyAttrs_MaxAndMinPwdAge_NegativeUsualValue covers the
// usual case for both maxPwdAge and minPwdAge: a negative FILETIME interval
// of exactly one day (-864000000000) must convert to the literal day count
// 1, which pins both the sign and the divisor (86400) of the minPwdAge
// conversion.
func TestApplyDomainPolicyAttrs_MaxAndMinPwdAge_NegativeUsualValue(t *testing.T) {
	entry := ldap.NewEntry("CN=contoso,DC=contoso,DC=com", map[string][]string{
		"maxPwdAge": {"-864000000000"},
		"minPwdAge": {"-864000000000"},
	})

	info := &types.DomainInfo{}
	applyDomainPolicyAttrs(info, entry)

	if info.MaxPasswordAge != 1 {
		t.Fatalf("MaxPasswordAge = %d, want 1", info.MaxPasswordAge)
	}
	if info.MaxPwdAge != 1 {
		t.Fatalf("MaxPwdAge (alias) = %d, want 1", info.MaxPwdAge)
	}
	if info.MinPwdAge != 1 {
		t.Fatalf("MinPwdAge = %d, want 1 (sign and divisor 86400 both correct)", info.MinPwdAge)
	}
}

// TestApplyDomainPolicyAttrs_MaxAndMinPwdAge_PositiveLeavesZero covers the
// unusual-but-possible positive case: both guards are "< 0", so a positive
// value must leave the field at its zero default. This kills an inversion
// of either guard to "> 0".
func TestApplyDomainPolicyAttrs_MaxAndMinPwdAge_PositiveLeavesZero(t *testing.T) {
	entry := ldap.NewEntry("CN=contoso,DC=contoso,DC=com", map[string][]string{
		"maxPwdAge": {"864000000000"},
		"minPwdAge": {"864000000000"},
	})

	info := &types.DomainInfo{}
	applyDomainPolicyAttrs(info, entry)

	if info.MaxPasswordAge != 0 {
		t.Fatalf("MaxPasswordAge = %d, want 0 for a positive maxPwdAge", info.MaxPasswordAge)
	}
	if info.MaxPwdAge != 0 {
		t.Fatalf("MaxPwdAge (alias) = %d, want 0 for a positive maxPwdAge", info.MaxPwdAge)
	}
	if info.MinPwdAge != 0 {
		t.Fatalf("MinPwdAge = %d, want 0 for a positive minPwdAge", info.MinPwdAge)
	}
}

// TestApplyDomainPolicyAttrs_LockoutDuration_Negative converts a negative
// FILETIME interval to minutes against a literal.
func TestApplyDomainPolicyAttrs_LockoutDuration_Negative(t *testing.T) {
	entry := ldap.NewEntry("CN=contoso,DC=contoso,DC=com", map[string][]string{
		"lockoutDuration": {"-18000000000"},
	})

	info := &types.DomainInfo{}
	applyDomainPolicyAttrs(info, entry)

	if info.LockoutDuration != 30 {
		t.Fatalf("LockoutDuration = %d, want 30", info.LockoutDuration)
	}
}

// TestApplyDomainPolicyAttrs_AbsentOrNonNumeric_FieldsZero covers an entry
// with none of the policy attributes set, and one with a non-numeric value:
// every converted field must stay at its zero default.
func TestApplyDomainPolicyAttrs_AbsentOrNonNumeric_FieldsZero(t *testing.T) {
	entry := ldap.NewEntry("CN=contoso,DC=contoso,DC=com", map[string][]string{
		"maxPwdAge": {"not-a-number"},
	})

	info := &types.DomainInfo{}
	applyDomainPolicyAttrs(info, entry)

	if info.MinPasswordLength != 0 {
		t.Fatalf("MinPasswordLength = %d, want 0", info.MinPasswordLength)
	}
	if info.MinPwdLength != 0 {
		t.Fatalf("MinPwdLength = %d, want 0", info.MinPwdLength)
	}
	if info.PasswordHistoryLength != 0 {
		t.Fatalf("PasswordHistoryLength = %d, want 0", info.PasswordHistoryLength)
	}
	if info.PwdHistoryLength != 0 {
		t.Fatalf("PwdHistoryLength = %d, want 0", info.PwdHistoryLength)
	}
	if info.LockoutThreshold != 0 {
		t.Fatalf("LockoutThreshold = %d, want 0", info.LockoutThreshold)
	}
	if info.MaxPasswordAge != 0 {
		t.Fatalf("MaxPasswordAge = %d, want 0 for a non-numeric maxPwdAge", info.MaxPasswordAge)
	}
	if info.MaxPwdAge != 0 {
		t.Fatalf("MaxPwdAge = %d, want 0 for a non-numeric maxPwdAge", info.MaxPwdAge)
	}
	if info.MinPwdAge != 0 {
		t.Fatalf("MinPwdAge = %d, want 0", info.MinPwdAge)
	}
	if info.LockoutDuration != 0 {
		t.Fatalf("LockoutDuration = %d, want 0", info.LockoutDuration)
	}
}
