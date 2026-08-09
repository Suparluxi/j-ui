package auth

import "regexp"

var administratorUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$`)

// ValidAdministratorUsername limits the single administrator ID to a
// shell- and URL-safe value suitable for installer and recovery workflows.
func ValidAdministratorUsername(username string) bool {
	return administratorUsernamePattern.MatchString(username)
}
