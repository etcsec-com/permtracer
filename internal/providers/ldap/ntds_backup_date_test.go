package ldap

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLatestNTDSWhenChanged_MultipleDatesMostRecentWinsRegardlessOfOrder(t *testing.T) {
	ascending := []string{"20240101000000.0Z", "20240615000000.0Z", "20241231235959.0Z"}
	descending := []string{"20241231235959.0Z", "20240615000000.0Z", "20240101000000.0Z"}
	want := time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC)

	gotAscending := latestNTDSWhenChanged(ascending)
	if assert.NotNil(t, gotAscending) {
		assert.True(t, gotAscending.Equal(want), "ascending order: got %v, want %v", gotAscending, want)
	}

	gotDescending := latestNTDSWhenChanged(descending)
	if assert.NotNil(t, gotDescending) {
		assert.True(t, gotDescending.Equal(want), "descending order: got %v, want %v", gotDescending, want)
	}
}

func TestLatestNTDSWhenChanged_EmptyOrUnreadableValueIgnored(t *testing.T) {
	want := time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC)
	values := []string{"", "not-a-timestamp", "20240615000000.0Z"}

	got := latestNTDSWhenChanged(values)
	if assert.NotNil(t, got) {
		assert.True(t, got.Equal(want), "got %v, want %v", got, want)
	}
}

func TestLatestNTDSWhenChanged_AllEmptyReturnsNil(t *testing.T) {
	got := latestNTDSWhenChanged([]string{"", "", "garbage"})
	assert.Nil(t, got)
}

func TestLatestNTDSWhenChanged_NoValuesReturnsNil(t *testing.T) {
	got := latestNTDSWhenChanged(nil)
	assert.Nil(t, got)
}

func TestLatestNTDSWhenChanged_SingleDate(t *testing.T) {
	want := time.Date(2025, 11, 17, 13, 9, 8, 0, time.UTC)
	got := latestNTDSWhenChanged([]string{"20251117130908.0Z"})
	if assert.NotNil(t, got) {
		assert.True(t, got.Equal(want), "got %v, want %v", got, want)
	}
}

func TestLatestNTDSWhenChanged_TwoEqualDates(t *testing.T) {
	want := time.Date(2025, 5, 1, 12, 0, 0, 0, time.UTC)
	got := latestNTDSWhenChanged([]string{"20250501120000.0Z", "20250501120000.0Z"})
	if assert.NotNil(t, got) {
		assert.True(t, got.Equal(want), "got %v, want %v", got, want)
	}
}

// TestNtdsWhenChangedAttrs_RequestsWhenChanged pins the attribute list sent
// to the LDAP search in block 7 ("Last AD backup date"). GetDomainInfo is
// not unit-testable without a live/mocked LDAP server, so this is the only
// way to catch "whenChanged removed from the query" without lab access.
func TestNtdsWhenChangedAttrs_RequestsWhenChanged(t *testing.T) {
	assert.Equal(t, []string{"whenChanged"}, ntdsWhenChangedAttrs())
}
