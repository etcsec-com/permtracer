package ldap

// anonymousLDAPAllowed reports whether the 7th character of dSHeuristics
// (fLDAPBlockAnonOps) is '2': any other value, or a string shorter than 7
// characters, means anonymous LDAP operations are not allowed.
func anonymousLDAPAllowed(dsHeuristics string) bool {
	return len(dsHeuristics) >= 7 && dsHeuristics[6] == '2'
}
