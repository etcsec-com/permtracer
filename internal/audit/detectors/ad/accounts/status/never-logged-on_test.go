package status

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/permtracer/internal/audit"
	"github.com/etcsec-com/permtracer/pkg/types"
)

func TestNeverLoggedOn_EnabledNoLogonDates_Counted(t *testing.T) {
	u := types.User{Disabled: false}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewNeverLoggedOnDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("enabled account with no logon date of any kind must be flagged, got Count=%d", f.Count)
	}
}

func TestNeverLoggedOn_DisabledNoLogonDates_NotCounted(t *testing.T) {
	u := types.User{Disabled: true}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewNeverLoggedOnDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("disabled account must NOT be flagged regardless of logon dates, got Count=%d", f.Count)
	}
}

func TestNeverLoggedOn_EnabledWithLastLogonOnly_NotCounted(t *testing.T) {
	u := types.User{
		Disabled:  false,
		LastLogon: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewNeverLoggedOnDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("a non-zero LastLogon alone must count as an AD logon and NOT be flagged, got Count=%d", f.Count)
	}
}

func TestNeverLoggedOn_EnabledWithLastLogonTimestampOnly_NotCounted(t *testing.T) {
	u := types.User{
		Disabled:           false,
		LastLogonTimestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewNeverLoggedOnDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("a non-zero LastLogonTimestamp alone must count as an AD logon and NOT be flagged, got Count=%d", f.Count)
	}
}

func TestNeverLoggedOn_EnabledWithAzureLastSignInOnly_NotCounted(t *testing.T) {
	signIn := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	u := types.User{
		Disabled:                false,
		AzureLastSignInDateTime: &signIn,
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewNeverLoggedOnDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("a non-zero AzureLastSignInDateTime alone must count as an Azure logon and NOT be flagged, got Count=%d", f.Count)
	}
}

func TestNeverLoggedOn_EnabledWithAzureLastNonInteractiveSignInOnly_NotCounted(t *testing.T) {
	signIn := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	u := types.User{
		Disabled:                              false,
		AzureLastNonInteractiveSignInDateTime: &signIn,
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewNeverLoggedOnDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("a non-zero AzureLastNonInteractiveSignInDateTime alone must count as an Azure logon and NOT be flagged, got Count=%d", f.Count)
	}
}

func TestNeverLoggedOn_AzurePointerZeroValue_Counted(t *testing.T) {
	var zero time.Time
	u := types.User{
		Disabled:                false,
		AzureLastSignInDateTime: &zero,
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewNeverLoggedOnDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("a non-nil Azure sign-in pointer holding the zero time must still be flagged, got Count=%d", f.Count)
	}
}

func TestNeverLoggedOn_ADLogonWithoutAzureLogon_NotCounted(t *testing.T) {
	u := types.User{
		Disabled:           false,
		LastLogonTimestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewNeverLoggedOnDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("an AD logon date with no Azure logon must NOT be flagged (AD alone is sufficient), got Count=%d", f.Count)
	}
}

func TestNeverLoggedOn_AzureLogonWithoutADLogon_NotCounted(t *testing.T) {
	signIn := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	u := types.User{
		Disabled:                false,
		AzureLastSignInDateTime: &signIn,
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewNeverLoggedOnDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("an Azure logon date with no AD logon must NOT be flagged (Azure alone is sufficient), got Count=%d", f.Count)
	}
}
