package smb

import (
	"encoding/binary"
	"testing"
)

// utf16leZ encodes s as UTF-16LE with a 2-byte null terminator.
func utf16leZ(s string) []byte {
	var b []byte
	for _, r := range s {
		b = append(b, byte(r), byte(r>>8))
	}
	return append(b, 0x00, 0x00)
}

// buildPRegEntry encodes one [key;valueName;type;size;data] Registry.pol entry.
func buildPRegEntry(key, valueName string, typ uint32, data []byte) []byte {
	var b []byte
	b = append(b, 0x5B, 0x00) // '['
	b = append(b, utf16leZ(key)...)
	b = append(b, 0x3B, 0x00) // ';'
	b = append(b, utf16leZ(valueName)...)
	b = append(b, 0x3B, 0x00) // ';'
	typBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(typBuf, typ)
	b = append(b, typBuf...)
	b = append(b, 0x3B, 0x00) // ';'
	sizeBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuf, uint32(len(data)))
	b = append(b, sizeBuf...)
	b = append(b, 0x3B, 0x00) // ';'
	b = append(b, data...)
	b = append(b, 0x5D, 0x00) // ']'
	return b
}

// buildPReg wraps entries with the "PReg" header (magic + version).
func buildPReg(entries ...[]byte) []byte {
	b := append([]byte("PReg"), 0x01, 0x00, 0x00, 0x00)
	for _, e := range entries {
		b = append(b, e...)
	}
	return b
}

func dword(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// TestParseRegistryPol_SMBServerSigning kills the disabled-branch mutation
// on the LanmanServer RequireSecuritySignature (server) case of
// ParseRegistryPol.
func TestParseRegistryPol_SMBServerSigning(t *testing.T) {
	entry := buildPRegEntry(
		`System\CurrentControlSet\Services\LanmanServer\Parameters`,
		"RequireSecuritySignature",
		4,
		dword(1),
	)
	data := buildPReg(entry)

	rs := ParseRegistryPol(data)

	if rs == nil || rs.RequireSMBSigningServer == nil {
		t.Fatal("RequireSMBSigningServer not populated from the LanmanServer RequireSecuritySignature entry")
	}
	if *rs.RequireSMBSigningServer != 1 {
		t.Fatalf("RequireSMBSigningServer = %d, want 1", *rs.RequireSMBSigningServer)
	}
}

// TestParseRegistryPol_SMBClientSigning kills the disabled-branch mutation
// on the LanmanWorkstation RequireSecuritySignature (client) case.
func TestParseRegistryPol_SMBClientSigning(t *testing.T) {
	entry := buildPRegEntry(
		`System\CurrentControlSet\Services\LanmanWorkstation\Parameters`,
		"RequireSecuritySignature",
		4,
		dword(1),
	)
	data := buildPReg(entry)

	rs := ParseRegistryPol(data)

	if rs == nil || rs.RequireSMBSigningClient == nil {
		t.Fatal("RequireSMBSigningClient not populated from the LanmanWorkstation RequireSecuritySignature entry")
	}
	if *rs.RequireSMBSigningClient != 1 {
		t.Fatalf("RequireSMBSigningClient = %d, want 1", *rs.RequireSMBSigningClient)
	}
}

// TestParseRegistryPol_LDAPServerIntegrity kills the disabled-branch
// mutation on the NTDS LDAPServerIntegrity case.
func TestParseRegistryPol_LDAPServerIntegrity(t *testing.T) {
	entry := buildPRegEntry(
		`System\CurrentControlSet\Services\NTDS\Parameters`,
		"LDAPServerIntegrity",
		4,
		dword(2),
	)
	data := buildPReg(entry)

	rs := ParseRegistryPol(data)

	if rs == nil || rs.LDAPServerIntegrity == nil {
		t.Fatal("LDAPServerIntegrity not populated from the NTDS LDAPServerIntegrity entry")
	}
	if *rs.LDAPServerIntegrity != 2 {
		t.Fatalf("LDAPServerIntegrity = %d, want 2", *rs.LDAPServerIntegrity)
	}
}

// TestParseRegistryPol_LDAPChannelBinding kills the disabled-branch
// mutation on the NTDS LdapEnforceChannelBinding case.
func TestParseRegistryPol_LDAPChannelBinding(t *testing.T) {
	entry := buildPRegEntry(
		`System\CurrentControlSet\Services\NTDS\Parameters`,
		"LdapEnforceChannelBinding",
		4,
		dword(2),
	)
	data := buildPReg(entry)

	rs := ParseRegistryPol(data)

	if rs == nil || rs.LDAPChannelBinding == nil {
		t.Fatal("LDAPChannelBinding not populated from the NTDS LdapEnforceChannelBinding entry")
	}
	if *rs.LDAPChannelBinding != 2 {
		t.Fatalf("LDAPChannelBinding = %d, want 2", *rs.LDAPChannelBinding)
	}
}

// TestParseRegistryPol_CredentialGuardLsaCfgFlags_DeviceGuardKey is the
// BP039_CRED_GUARD_LIMITED_SCOPE regression test. The real
// GPO-deployed Credential Guard setting lives at
// SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags - the key
// path contains "deviceguard", not "lsa". The old switch case required
// "lsa" in keyLower, so this entry (the only shape Windows ever writes) was
// silently dropped and rs.LsaCfgFlags stayed nil forever, leaving
// BP039_CRED_GUARD_LIMITED_SCOPE permanently blind (maxCG always -1).
func TestParseRegistryPol_CredentialGuardLsaCfgFlags_DeviceGuardKey(t *testing.T) {
	entry := buildPRegEntry(
		`SOFTWARE\Policies\Microsoft\Windows\DeviceGuard`,
		"LsaCfgFlags",
		4, // REG_DWORD
		dword(1),
	)
	data := buildPReg(entry)

	rs := ParseRegistryPol(data)

	if rs == nil {
		t.Fatal("ParseRegistryPol returned nil for a DeviceGuard\\LsaCfgFlags entry")
	}
	if rs.LsaCfgFlags == nil {
		t.Fatal("LsaCfgFlags not populated for the real DeviceGuard GPO key (registrypol_parser.go only matched a \"lsa\"-in-path key that Windows never writes)")
	}
	if *rs.LsaCfgFlags != 1 {
		t.Fatalf("LsaCfgFlags = %d, want 1", *rs.LsaCfgFlags)
	}
}

// TestParseRegistryPol_CredentialGuardLsaCfgFlags_LsaKeyStillWorks guards
// against a regression on the pre-existing (synthetic but harmless) "lsa"
// path match while broadening the condition to also accept "deviceguard".
func TestParseRegistryPol_CredentialGuardLsaCfgFlags_LsaKeyStillWorks(t *testing.T) {
	entry := buildPRegEntry(
		`System\CurrentControlSet\Control\Lsa`,
		"LsaCfgFlags",
		4,
		dword(2),
	)
	data := buildPReg(entry)

	rs := ParseRegistryPol(data)

	if rs == nil || rs.LsaCfgFlags == nil {
		t.Fatal("LsaCfgFlags not populated for a Lsa-path key")
	}
	if *rs.LsaCfgFlags != 2 {
		t.Fatalf("LsaCfgFlags = %d, want 2", *rs.LsaCfgFlags)
	}
}

// TestParseRegistryPol_CredentialGuardLsaCfgFlags_LsassExcluded guards the
// pre-existing lsass exclusion: Lsass is a different subsystem and must not
// be mistaken for the Lsa\ policy path.
func TestParseRegistryPol_CredentialGuardLsaCfgFlags_LsassExcluded(t *testing.T) {
	entry := buildPRegEntry(
		`System\CurrentControlSet\Control\Lsa\Lsass`,
		"LsaCfgFlags",
		4,
		dword(1),
	)
	data := buildPReg(entry)

	rs := ParseRegistryPol(data)

	if rs != nil && rs.LsaCfgFlags != nil {
		t.Fatalf("LsaCfgFlags should not be populated from an Lsass-path key, got %d", *rs.LsaCfgFlags)
	}
}

// TestParseRegistryPol_CredentialGuardEnabledVBS_DeviceGuardKey covers the
// :356 case (CredentialGuardEnabled, the VBS prerequisite for Credential
// Guard): a DeviceGuard\EnableVirtualizationBasedSecurity DWORD entry must
// populate CredentialGuardEnabled.
func TestParseRegistryPol_CredentialGuardEnabledVBS_DeviceGuardKey(t *testing.T) {
	entry := buildPRegEntry(
		`SOFTWARE\Policies\Microsoft\Windows\DeviceGuard`,
		"EnableVirtualizationBasedSecurity",
		4, // REG_DWORD
		dword(1),
	)
	data := buildPReg(entry)

	rs := ParseRegistryPol(data)

	if rs == nil || rs.CredentialGuardEnabled == nil {
		t.Fatal("CredentialGuardEnabled not populated for the DeviceGuard\\EnableVirtualizationBasedSecurity entry")
	}
	if *rs.CredentialGuardEnabled != 1 {
		t.Fatalf("CredentialGuardEnabled = %d, want 1", *rs.CredentialGuardEnabled)
	}
}

// TestParseRegistryPol_CredentialGuardEnabledVBS_NonDeviceGuardKeyNotSet
// guards the :356 key match: a key that does not contain "deviceguard" must
// not populate CredentialGuardEnabled even with the matching value name.
func TestParseRegistryPol_CredentialGuardEnabledVBS_NonDeviceGuardKeyNotSet(t *testing.T) {
	entry := buildPRegEntry(
		`System\CurrentControlSet\Control\SomeOtherKey`,
		"EnableVirtualizationBasedSecurity",
		4,
		dword(1),
	)
	data := buildPReg(entry)

	rs := ParseRegistryPol(data)

	if rs != nil && rs.CredentialGuardEnabled != nil {
		t.Fatalf("CredentialGuardEnabled should not be populated from a non-DeviceGuard key, got %d", *rs.CredentialGuardEnabled)
	}
}

// TestParseRegistryPol_RestrictSendingNTLMTraffic passes a real binary
// Registry.pol entry for Lsa\MSV1_0\RestrictSendingNTLMTraffic through
// ParseRegistryPol (ANSSI PA-099 R73/R74+ - see
// registrypol_parser.go:464). Without this test, a mutation on the
// "restrictsendingntlmtraffic" string match there went uncaught: on a real
// collection, RestrictSendingNTLMTraffic would never get populated and
// R73/R74 would flag a compliant domain as a permanent false positive.
func TestParseRegistryPol_RestrictSendingNTLMTraffic(t *testing.T) {
	entry := buildPRegEntry(
		`System\CurrentControlSet\Control\Lsa\MSV1_0`,
		"RestrictSendingNTLMTraffic",
		4, // REG_DWORD
		dword(2),
	)
	data := buildPReg(entry)

	rs := ParseRegistryPol(data)

	if rs == nil || rs.RestrictSendingNTLMTraffic == nil {
		t.Fatal("RestrictSendingNTLMTraffic not populated for the real Lsa\\MSV1_0\\RestrictSendingNTLMTraffic GPO key")
	}
	if *rs.RestrictSendingNTLMTraffic != 2 {
		t.Fatalf("RestrictSendingNTLMTraffic = %d, want 2", *rs.RestrictSendingNTLMTraffic)
	}
}

// TestParseRegistryPol_RestrictSendingNTLMTraffic_NonMSV1_0KeyNotSet guards
// the key match: a key outside MSV1_0 bearing the same value name must not
// populate RestrictSendingNTLMTraffic.
func TestParseRegistryPol_RestrictSendingNTLMTraffic_NonMSV1_0KeyNotSet(t *testing.T) {
	entry := buildPRegEntry(
		`System\CurrentControlSet\Control\SomeOtherKey`,
		"RestrictSendingNTLMTraffic",
		4,
		dword(2),
	)
	data := buildPReg(entry)

	rs := ParseRegistryPol(data)

	if rs != nil && rs.RestrictSendingNTLMTraffic != nil {
		t.Fatalf("RestrictSendingNTLMTraffic should not be populated from a non-MSV1_0 key, got %d", *rs.RestrictSendingNTLMTraffic)
	}
}

// TestParseRegistryPol_RestrictReceivingNTLMTraffic_SendingStaysNil passes a
// Registry.pol entry for Lsa\MSV1_0\RestrictReceivingNTLMTraffic ALONE
// through ParseRegistryPol (ANSSI PA-099 R73/R74+ - see
// registrypol_parser.go:469). The Sending case (:464) is listed first and
// matches on the same key prefix; if its value-name guard were weakened, a
// Receiving-only entry would wrongly populate RestrictSendingNTLMTraffic
// instead of RestrictReceivingNTLMTraffic, making R73 flag a compliant
// domain as a permanent false positive while R74 goes blind.
func TestParseRegistryPol_RestrictReceivingNTLMTraffic_SendingStaysNil(t *testing.T) {
	entry := buildPRegEntry(
		`System\CurrentControlSet\Control\Lsa\MSV1_0`,
		"RestrictReceivingNTLMTraffic",
		4, // REG_DWORD
		dword(2),
	)
	data := buildPReg(entry)

	rs := ParseRegistryPol(data)

	if rs == nil || rs.RestrictReceivingNTLMTraffic == nil {
		t.Fatal("RestrictReceivingNTLMTraffic not populated for the real Lsa\\MSV1_0\\RestrictReceivingNTLMTraffic GPO key")
	}
	if *rs.RestrictReceivingNTLMTraffic != 2 {
		t.Fatalf("RestrictReceivingNTLMTraffic = %d, want 2", *rs.RestrictReceivingNTLMTraffic)
	}
	if rs.RestrictSendingNTLMTraffic != nil {
		t.Fatalf("RestrictSendingNTLMTraffic should stay nil when only RestrictReceivingNTLMTraffic is set, got %d", *rs.RestrictSendingNTLMTraffic)
	}
}

// TestParseRegistryPol_RestrictSendingAndReceivingNTLMTraffic_BothSet passes
// both Lsa\MSV1_0\RestrictSendingNTLMTraffic and
// \RestrictReceivingNTLMTraffic under the same key with distinct values and
// requires each field to carry its own value. This kills a Sending/Receiving
// assignment swap between registrypol_parser.go:464 and :469: a swap would
// make this test observe the values crossed over.
func TestParseRegistryPol_RestrictSendingAndReceivingNTLMTraffic_BothSet(t *testing.T) {
	sendingEntry := buildPRegEntry(
		`System\CurrentControlSet\Control\Lsa\MSV1_0`,
		"RestrictSendingNTLMTraffic",
		4,
		dword(1),
	)
	receivingEntry := buildPRegEntry(
		`System\CurrentControlSet\Control\Lsa\MSV1_0`,
		"RestrictReceivingNTLMTraffic",
		4,
		dword(2),
	)
	data := buildPReg(sendingEntry, receivingEntry)

	rs := ParseRegistryPol(data)

	if rs == nil || rs.RestrictSendingNTLMTraffic == nil || rs.RestrictReceivingNTLMTraffic == nil {
		t.Fatal("RestrictSendingNTLMTraffic and RestrictReceivingNTLMTraffic must both be populated when both GPO keys are present")
	}
	if *rs.RestrictSendingNTLMTraffic != 1 {
		t.Fatalf("RestrictSendingNTLMTraffic = %d, want 1", *rs.RestrictSendingNTLMTraffic)
	}
	if *rs.RestrictReceivingNTLMTraffic != 2 {
		t.Fatalf("RestrictReceivingNTLMTraffic = %d, want 2", *rs.RestrictReceivingNTLMTraffic)
	}
}

// TestParseRegistryPol_MSV1_0UnrelatedValueNameNotSetAsReceiving guards the
// value-name match on the Receiving case (registrypol_parser.go:469): an
// MSV1_0 entry whose value name is neither RestrictSendingNTLMTraffic nor
// RestrictReceivingNTLMTraffic must not populate
// RestrictReceivingNTLMTraffic. A second, unrelated entry
// (LanmanServer\RequireSecuritySignature) forces found=true so a nil
// RestrictReceivingNTLMTraffic is observed on a non-nil result rather than
// masked by ParseRegistryPol returning nil entirely.
func TestParseRegistryPol_MSV1_0UnrelatedValueNameNotSetAsReceiving(t *testing.T) {
	unrelatedMSV1_0Entry := buildPRegEntry(
		`System\CurrentControlSet\Control\Lsa\MSV1_0`,
		"NtlmMinServerSec",
		4,
		dword(0x20000000),
	)
	signingEntry := buildPRegEntry(
		`System\CurrentControlSet\Services\LanmanServer\Parameters`,
		"RequireSecuritySignature",
		4,
		dword(1),
	)
	data := buildPReg(unrelatedMSV1_0Entry, signingEntry)

	rs := ParseRegistryPol(data)

	if rs == nil {
		t.Fatal("ParseRegistryPol returned nil despite the LanmanServer RequireSecuritySignature entry")
	}
	if rs.RestrictReceivingNTLMTraffic != nil {
		t.Fatalf("RestrictReceivingNTLMTraffic should not be populated from an unrelated MSV1_0 value name, got %d", *rs.RestrictReceivingNTLMTraffic)
	}
	if rs.RestrictSendingNTLMTraffic != nil {
		t.Fatalf("RestrictSendingNTLMTraffic should not be populated from an unrelated MSV1_0 value name, got %d", *rs.RestrictSendingNTLMTraffic)
	}
}

// TestParseRegistryPol_KerberosArmoringDC_EnableCbacAndArmor covers
// KERBEROS_ARMORING_DC_DISABLED (false positive, allume_a_tort=true): the real
// GPO-deployed "KDC support for claims, compound authentication and
// Kerberos armoring" policy writes the value name EnableCbacAndArmor under
// a Kdc\Parameters-shaped key - the old switch case matched
// SupportedEncTypes/SupportedEncryptionTypes instead, a combination no
// real GPO ever writes, so RegistrySettings.KerberosArmoringDC stayed nil
// on every domain (even a correctly configured one), and the detector
// reported Count=1 unconditionally.
func TestParseRegistryPol_KerberosArmoringDC_EnableCbacAndArmor(t *testing.T) {
	entry := buildPRegEntry(
		`System\CurrentControlSet\Services\Kdc\Parameters`,
		"EnableCbacAndArmor",
		4, // REG_DWORD
		dword(2),
	)
	data := buildPReg(entry)

	rs := ParseRegistryPol(data)

	if rs == nil || rs.KerberosArmoringDC == nil {
		t.Fatal("KerberosArmoringDC not populated for the real EnableCbacAndArmor GPO key")
	}
	if *rs.KerberosArmoringDC != 2 {
		t.Fatalf("KerberosArmoringDC = %d, want 2", *rs.KerberosArmoringDC)
	}
}

// TestParseRegistryPol_ConfigCIPolicyFilePathUnderDeviceGuard is the
// BP039_CCI_NOT_DEPLOYED regression test. The real GPO-deployed "Deploy App
// Control for Business" policy (DeviceGuard.admx, ConfigCIPolicy) writes
// ConfigCIPolicyFilePath under
// SOFTWARE\Policies\Microsoft\Windows\DeviceGuard - a path that never
// contains "codeintegrity". The old switch case required "codeintegrity" in
// keyLower, so this entry (the only shape Windows ever writes) was silently
// dropped and rs.DeviceGuardConfigCIPolicyFilePath stayed nil forever,
// leaving BP039_CCI_NOT_DEPLOYED permanently triggered.
func TestParseRegistryPol_ConfigCIPolicyFilePathUnderDeviceGuard(t *testing.T) {
	t.Run("DeviceGuardKeyWithValue", func(t *testing.T) {
		entry := buildPRegEntry(
			`SOFTWARE\Policies\Microsoft\Windows\DeviceGuard`,
			"ConfigCIPolicyFilePath",
			1, // REG_SZ
			utf16leZ(`C:\Windows\System32\CodeIntegrity\SIPolicy.p7b`),
		)
		data := buildPReg(entry)

		rs := ParseRegistryPol(data)

		if rs == nil || rs.DeviceGuardConfigCIPolicyFilePath == nil {
			t.Fatal("DeviceGuardConfigCIPolicyFilePath not populated for the real DeviceGuard GPO key (registrypol_parser.go only matched a \"codeintegrity\"-in-path key that Windows never writes)")
		}
		if *rs.DeviceGuardConfigCIPolicyFilePath != `C:\Windows\System32\CodeIntegrity\SIPolicy.p7b` {
			t.Fatalf("DeviceGuardConfigCIPolicyFilePath = %q, want the configured path", *rs.DeviceGuardConfigCIPolicyFilePath)
		}
	})

	t.Run("CodeIntegrityKeyStillWorks", func(t *testing.T) {
		entry := buildPRegEntry(
			`SOFTWARE\Policies\Microsoft\Windows\CodeIntegrity`,
			"ConfigCIPolicyFilePath",
			1,
			utf16leZ(`C:\Windows\System32\CodeIntegrity\SIPolicy.p7b`),
		)
		data := buildPReg(entry)

		rs := ParseRegistryPol(data)

		if rs == nil || rs.DeviceGuardConfigCIPolicyFilePath == nil {
			t.Fatal("DeviceGuardConfigCIPolicyFilePath not populated for a CodeIntegrity-path key")
		}
		if *rs.DeviceGuardConfigCIPolicyFilePath != `C:\Windows\System32\CodeIntegrity\SIPolicy.p7b` {
			t.Fatalf("DeviceGuardConfigCIPolicyFilePath = %q, want the configured path", *rs.DeviceGuardConfigCIPolicyFilePath)
		}
	})

	t.Run("EmptyValueNotSet", func(t *testing.T) {
		entry := buildPRegEntry(
			`SOFTWARE\Policies\Microsoft\Windows\DeviceGuard`,
			"ConfigCIPolicyFilePath",
			1,
			utf16leZ(""),
		)
		data := buildPReg(entry)

		rs := ParseRegistryPol(data)

		if rs != nil && rs.DeviceGuardConfigCIPolicyFilePath != nil {
			t.Fatalf("DeviceGuardConfigCIPolicyFilePath should not be populated from an empty value, got %q", *rs.DeviceGuardConfigCIPolicyFilePath)
		}
	})

	t.Run("OtherValueNameUnderDeviceGuardNotSet", func(t *testing.T) {
		entry := buildPRegEntry(
			`SOFTWARE\Policies\Microsoft\Windows\DeviceGuard`,
			"SomeOtherValue",
			1,
			utf16leZ(`C:\Windows\System32\CodeIntegrity\SIPolicy.p7b`),
		)
		data := buildPReg(entry)

		rs := ParseRegistryPol(data)

		if rs != nil && rs.DeviceGuardConfigCIPolicyFilePath != nil {
			t.Fatalf("DeviceGuardConfigCIPolicyFilePath should not be populated from an unrelated value name, got %q", *rs.DeviceGuardConfigCIPolicyFilePath)
		}
	})
}

// TestParseRegistryPol_TerminalServicesRDPEncryption_BothValues is the
// binary-Registry.pol test for ANSSI_R79_RDP_NOT_HARDENED's two
// signals (registrypol_parser.go:476-485): a single Registry.pol with BOTH
// Terminal Services\MinEncryptionLevel=3 and Terminal
// Services\fEncryptRPCTraffic=1 as separate DWORD entries under the same
// key must populate both RDPMinEncryptionLevel and RDPEncryptRPCTraffic.
func TestParseRegistryPol_TerminalServicesRDPEncryption_BothValues(t *testing.T) {
	minEncEntry := buildPRegEntry(
		`Software\Policies\Microsoft\Windows NT\Terminal Services`,
		"MinEncryptionLevel",
		4, // REG_DWORD
		dword(3),
	)
	rpcEntry := buildPRegEntry(
		`Software\Policies\Microsoft\Windows NT\Terminal Services`,
		"fEncryptRPCTraffic",
		4, // REG_DWORD
		dword(1),
	)
	data := buildPReg(minEncEntry, rpcEntry)

	rs := ParseRegistryPol(data)

	if rs == nil {
		t.Fatal("ParseRegistryPol returned nil for a Registry.pol with Terminal Services RDP encryption entries")
	}
	if rs.RDPMinEncryptionLevel == nil {
		t.Fatal("RDPMinEncryptionLevel not populated for the real Terminal Services\\MinEncryptionLevel GPO key")
	}
	if *rs.RDPMinEncryptionLevel != 3 {
		t.Fatalf("RDPMinEncryptionLevel = %d, want 3", *rs.RDPMinEncryptionLevel)
	}
	if rs.RDPEncryptRPCTraffic == nil {
		t.Fatal("RDPEncryptRPCTraffic not populated for the real Terminal Services\\fEncryptRPCTraffic GPO key")
	}
	if *rs.RDPEncryptRPCTraffic != 1 {
		t.Fatalf("RDPEncryptRPCTraffic = %d, want 1", *rs.RDPEncryptRPCTraffic)
	}
}

// TestParseRegistryPol_TerminalServicesMinEncryptionLevel_Alone uses a
// Registry.pol with ONLY the MinEncryptionLevel entry (no other matching
// case in the file), so a mutation that drops `found = true` on that one
// case (:479) cannot hide behind another case's own `found = true`: with no
// other match, `found` would stay false and ParseRegistryPol would return
// nil (:489-492) instead of the populated *audit.RegistrySettings, losing
// RDPMinEncryptionLevel entirely - the combined BothValues test above cannot
// catch this, since its second entry (fEncryptRPCTraffic) sets `found = true`
// on its own.
func TestParseRegistryPol_TerminalServicesMinEncryptionLevel_Alone(t *testing.T) {
	entry := buildPRegEntry(
		`Software\Policies\Microsoft\Windows NT\Terminal Services`,
		"MinEncryptionLevel",
		4, // REG_DWORD
		dword(3),
	)
	data := buildPReg(entry)

	rs := ParseRegistryPol(data)

	if rs == nil || rs.RDPMinEncryptionLevel == nil {
		t.Fatal("RDPMinEncryptionLevel not populated for the sole Terminal Services\\MinEncryptionLevel entry")
	}
	if *rs.RDPMinEncryptionLevel != 3 {
		t.Fatalf("RDPMinEncryptionLevel = %d, want 3", *rs.RDPMinEncryptionLevel)
	}
}

// TestParseRegistryPol_TerminalServicesRPCTraffic_Alone is the symmetric
// case for fEncryptRPCTraffic (:481-484): a Registry.pol with ONLY that
// entry pins its own `found = true` (:484), which the combined BothValues
// test cannot isolate since its MinEncryptionLevel entry also sets
// `found = true` independently.
func TestParseRegistryPol_TerminalServicesRPCTraffic_Alone(t *testing.T) {
	entry := buildPRegEntry(
		`Software\Policies\Microsoft\Windows NT\Terminal Services`,
		"fEncryptRPCTraffic",
		4, // REG_DWORD
		dword(1),
	)
	data := buildPReg(entry)

	rs := ParseRegistryPol(data)

	if rs == nil || rs.RDPEncryptRPCTraffic == nil {
		t.Fatal("RDPEncryptRPCTraffic not populated for the sole Terminal Services\\fEncryptRPCTraffic entry")
	}
	if *rs.RDPEncryptRPCTraffic != 1 {
		t.Fatalf("RDPEncryptRPCTraffic = %d, want 1", *rs.RDPEncryptRPCTraffic)
	}
}

// TestParseRegistryPol_TerminalServicesRDPEncryption_NonTerminalServicesKeyNotSet
// guards the key match on both :476 and :481: a key that does not contain
// "terminal services" must not populate RDPMinEncryptionLevel or
// RDPEncryptRPCTraffic even with the matching value names.
func TestParseRegistryPol_TerminalServicesRDPEncryption_NonTerminalServicesKeyNotSet(t *testing.T) {
	minEncEntry := buildPRegEntry(
		`Software\Policies\Microsoft\Windows NT\SomeOtherFeature`,
		"MinEncryptionLevel",
		4,
		dword(3),
	)
	rpcEntry := buildPRegEntry(
		`Software\Policies\Microsoft\Windows NT\SomeOtherFeature`,
		"fEncryptRPCTraffic",
		4,
		dword(1),
	)
	data := buildPReg(minEncEntry, rpcEntry)

	rs := ParseRegistryPol(data)

	if rs != nil && rs.RDPMinEncryptionLevel != nil {
		t.Fatalf("RDPMinEncryptionLevel should not be populated from a non-Terminal-Services key, got %d", *rs.RDPMinEncryptionLevel)
	}
	if rs != nil && rs.RDPEncryptRPCTraffic != nil {
		t.Fatalf("RDPEncryptRPCTraffic should not be populated from a non-Terminal-Services key, got %d", *rs.RDPEncryptRPCTraffic)
	}
}
