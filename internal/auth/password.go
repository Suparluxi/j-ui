package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory           = 32 * 1024
	argonIterations       = 3
	argonParallelism      = 2
	argonKeyLength        = 32
	minimumPasswordLength = 4
)

func HashPassword(password string) (string, error) {
	if len(password) < minimumPasswordLength {
		return "", fmt.Errorf("password must be at least %d characters", minimumPasswordLength)
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLength)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory,
		argonIterations,
		argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func VerifyPassword(encoded, password string) bool {
	memory, iterations, parallelism, salt, expected, ok := parsePasswordHash(encoded)
	if !ok {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func ValidPasswordHash(encoded string) bool {
	_, _, _, _, _, ok := parsePasswordHash(encoded)
	return ok
}

func parsePasswordHash(encoded string) (uint32, uint32, uint8, []byte, []byte, bool) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return 0, 0, 0, nil, nil, false
	}
	var memory uint32
	var iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return 0, 0, 0, nil, nil, false
	}
	if memory != argonMemory || iterations != argonIterations || parallelism != argonParallelism {
		return 0, 0, 0, nil, nil, false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) != 16 {
		return 0, 0, 0, nil, nil, false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) != argonKeyLength {
		return 0, 0, 0, nil, nil, false
	}
	return memory, iterations, parallelism, salt, expected, true
}
