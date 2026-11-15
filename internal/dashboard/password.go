package dashboard

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Passwords are low-entropy secrets, so unlike agent tokens they get a slow,
// salted KDF. PBKDF2-SHA256 is in the standard library; the iteration count
// follows the OWASP recommendation for that algorithm.
const (
	pbkdf2Iterations = 600_000
	saltBytes        = 16
	keyBytes         = 32
	hashScheme       = "pbkdf2-sha256"
)

// MinPasswordLength is enforced when a password is set.
const MinPasswordLength = 12

// ErrWeakPassword is returned for passwords shorter than MinPasswordLength.
var ErrWeakPassword = fmt.Errorf("password must be at least %d characters", MinPasswordLength)

// HashPassword returns an encoded "pbkdf2-sha256$iter$salt$key" string.
func HashPassword(password string) (string, error) {
	if len([]rune(password)) < MinPasswordLength {
		return "", ErrWeakPassword
	}
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return encodeHash(password, salt, pbkdf2Iterations)
}

func encodeHash(password string, salt []byte, iter int) (string, error) {
	key, err := pbkdf2.Key(sha256.New, password, salt, iter, keyBytes)
	if err != nil {
		return "", err
	}
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("%s$%d$%s$%s", hashScheme, iter, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// CheckPassword reports whether password matches encoded, in constant time.
func CheckPassword(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != hashScheme {
		return false, errors.New("dashboard: unknown password hash format")
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 || iter > 10_000_000 {
		return false, errors.New("dashboard: bad password hash iteration count")
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[2])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false, errors.New("dashboard: bad password hash encoding")
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// dummyHash is checked when the username does not exist, so a login attempt
// takes the same time whether or not the account is real.
var dummyHash = func() string {
	h, err := encodeHash("mancar-dummy-password", make([]byte, saltBytes), pbkdf2Iterations)
	if err != nil {
		panic(err)
	}
	return h
}()
