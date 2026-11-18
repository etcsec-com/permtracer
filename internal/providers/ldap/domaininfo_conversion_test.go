package ldap

import (
	"math"
	"testing"
)

// TestFiletimeMaxPwdAgeToDays_NeverExpiresSentinel_LiteralValue asserts the
// sentinel day count against a literal, not the maxPwdAgeNeverExpiresDays
// symbol: a test that builds its expectation from the very same constant it
// is checking can never detect a change to that constant's value.
func TestFiletimeMaxPwdAgeToDays_NeverExpiresSentinel_LiteralValue(t *testing.T) {
	got := filetimeMaxPwdAgeToDays(math.MinInt64)
	if got != 999999 {
		t.Fatalf("got %d, want 999999 (literal, not the maxPwdAgeNeverExpiresDays symbol)", got)
	}
}

// TestFiletimeMaxPwdAgeToDays_Zero: a maxPwdAge of exactly 0 is not the
// MinInt64 sentinel, so it takes the ordinary -maxPwdAge/divisor path.
func TestFiletimeMaxPwdAgeToDays_Zero(t *testing.T) {
	got := filetimeMaxPwdAgeToDays(0)
	if got != 0 {
		t.Fatalf("got %d, want 0", got)
	}
}

// TestFiletimeMaxPwdAgeToDays_NegativeUsualValues converts ordinary
// negative FILETIME intervals to whole days, against literal day counts.
func TestFiletimeMaxPwdAgeToDays_NegativeUsualValues(t *testing.T) {
	tests := []struct {
		name      string
		maxPwdAge int64
		want      int
	}{
		{"42 days", -36288000000000, 42},
		{"1 day", -864000000000, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filetimeMaxPwdAgeToDays(tt.maxPwdAge)
			if got != tt.want {
				t.Fatalf("got %d, want %d", got, tt.want)
			}
		})
	}
}
