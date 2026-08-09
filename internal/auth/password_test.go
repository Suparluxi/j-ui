package auth

import (
	"strings"
	"testing"
)

func TestPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "correct horse battery staple") {
		t.Fatal("valid password was rejected")
	}
	if VerifyPassword(hash, "wrong password") {
		t.Fatal("invalid password was accepted")
	}
}

func TestPasswordMinimumLength(t *testing.T) {
	if _, err := HashPassword("abc"); err == nil {
		t.Fatal("short password was accepted")
	}
	hash, err := HashPassword("admin")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "admin") {
		t.Fatal("four-character-or-longer password was rejected")
	}
}

func TestPasswordHashRejectsUnsupportedOrUnboundedParameters(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !ValidPasswordHash(hash) {
		t.Fatal("generated hash was not recognized")
	}
	for _, invalid := range []string{
		"not-a-hash",
		strings.Replace(hash, "m=32768", "m=4294967295", 1),
		strings.Replace(hash, "t=3", "t=999999", 1),
		strings.Replace(hash, "p=2", "p=255", 1),
	} {
		if ValidPasswordHash(invalid) || VerifyPassword(invalid, "correct horse battery staple") {
			t.Fatalf("unsafe hash accepted: %s", invalid)
		}
	}
}

func TestValidAdministratorUsername(t *testing.T) {
	for _, username := range []string{"jui-a1b2c3", "admin", "server_01", "ops.user"} {
		if !ValidAdministratorUsername(username) {
			t.Fatalf("valid username rejected: %q", username)
		}
	}
	for _, username := range []string{"", "ab", "-admin", "账号", "name with spaces", strings.Repeat("a", 33)} {
		if ValidAdministratorUsername(username) {
			t.Fatalf("invalid username accepted: %q", username)
		}
	}
}
