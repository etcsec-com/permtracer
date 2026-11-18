package smb

import "testing"

const auditCSVHeader = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\n"

// TestParseAuditCSV_ValidRows kills a mutation of the "Setting Value" header
// match (e.g. "Setting Value" -> "Setting Value MUT"): valueCol would stay -1
// and the function would return nil instead of the populated map. Also
// confirms the GUID key is lowercased regardless of the file's own casing.
func TestParseAuditCSV_ValidRows(t *testing.T) {
	data := []byte(auditCSVHeader +
		",System,Audit Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3\n" +
		",System,Audit Credential Validation,{0cce923f-69ae-11d9-bed3-505054503030},Failure,,2\n")

	got := parseAuditCSV(data)

	if got == nil {
		t.Fatal("expected a non-nil map for a file with valid rows")
	}
	if v, ok := got["{0cce9215-69ae-11d9-bed3-505054503030}"]; !ok || v != 3 {
		t.Fatalf("Logon GUID = (%d, %v), want (3, true); GUID must be matched case-insensitively (lowercased)", v, ok)
	}
	if v, ok := got["{0cce923f-69ae-11d9-bed3-505054503030}"]; !ok || v != 2 {
		t.Fatalf("CredentialValidation GUID = (%d, %v), want (2, true)", v, ok)
	}
}

// TestParseAuditCSV_UnknownGUIDStillIncluded confirms parseAuditCSV does not
// filter rows by whether their GUID matches a known subcategory constant: any
// row with a well-formed GUID column and a numeric Setting Value is kept.
func TestParseAuditCSV_UnknownGUIDStillIncluded(t *testing.T) {
	data := []byte(auditCSVHeader +
		",System,Some Unknown Subcategory,{deadbeef-0000-0000-0000-000000000000},Success,,1\n")

	got := parseAuditCSV(data)

	if v, ok := got["{deadbeef-0000-0000-0000-000000000000}"]; !ok || v != 1 {
		t.Fatalf("unknown-subcategory GUID = (%d, %v), want (1, true); parseAuditCSV must not filter by known subcategory", v, ok)
	}
}

// TestParseAuditCSV_InvalidSettingValueRowSkipped: a non-numeric Setting
// Value must drop that row rather than erroring out the whole parse. With
// only one row present, that leaves no data at all, so the result is nil.
func TestParseAuditCSV_InvalidSettingValueRowSkipped(t *testing.T) {
	data := []byte(auditCSVHeader +
		",System,Audit Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,,notanumber\n")

	got := parseAuditCSV(data)

	if got != nil {
		t.Fatalf("expected nil when the only row has a non-numeric Setting Value, got %v", got)
	}
}

// TestParseAuditCSV_MixedValidAndInvalidRows confirms a malformed row is
// skipped individually, without discarding the valid rows alongside it.
func TestParseAuditCSV_MixedValidAndInvalidRows(t *testing.T) {
	data := []byte(auditCSVHeader +
		",System,Audit Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,,3\n" +
		",System,Audit Credential Validation,{0cce923f-69ae-11d9-bed3-505054503030},Success,,notanumber\n")

	got := parseAuditCSV(data)

	if got == nil {
		t.Fatal("expected a non-nil map: one row is valid even though the other has a malformed Setting Value")
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 entry (the malformed row must be skipped, not abort the whole parse), got %d: %v", len(got), got)
	}
	if v, ok := got["{0cce9215-69ae-11d9-bed3-505054503030}"]; !ok || v != 3 {
		t.Fatalf("Logon GUID = (%d, %v), want (3, true)", v, ok)
	}
}

// TestParseAuditCSV_EmptyFileReturnsNil: no rows at all (not even a header).
func TestParseAuditCSV_EmptyFileReturnsNil(t *testing.T) {
	got := parseAuditCSV([]byte(""))
	if got != nil {
		t.Fatalf("expected nil for an empty file, got %v", got)
	}
}

// TestParseAuditCSV_HeaderOnlyReturnsNil: a header row with zero data rows
// beneath it.
func TestParseAuditCSV_HeaderOnlyReturnsNil(t *testing.T) {
	got := parseAuditCSV([]byte(auditCSVHeader))
	if got != nil {
		t.Fatalf("expected nil for a file with only a header row, got %v", got)
	}
}
