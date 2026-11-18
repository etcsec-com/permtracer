package governance

import (
	"strings"

	"github.com/etcsec-com/permtracer/pkg/types"
)

// isGuestUser checks if a user is a guest
func isGuestUser(u types.User) bool {
	return strings.Contains(u.UserPrincipalName, "#EXT#")
}
