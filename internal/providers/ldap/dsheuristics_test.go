package ldap

import "testing"

func TestAnonymousLDAPAllowed(t *testing.T) {
	tests := []struct {
		name         string
		dsHeuristics string
		want         bool
	}{
		{"empty", "", false},
		{"six chars no panic", "000000", false},
		{"seventh char 2", "0000002", true},
		{"seventh char 1", "0000001", false},
		{"seventh char 0", "0000000", false},
		{"seventh char 3", "0000003", false},
		{"longer string seventh char 2", "00000020000001", true},
		{"seventh char 2 sixth char 1", "0000012", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := anonymousLDAPAllowed(tt.dsHeuristics)
			if got != tt.want {
				t.Errorf("anonymousLDAPAllowed(%q) = %v, want %v", tt.dsHeuristics, got, tt.want)
			}
		})
	}
}
