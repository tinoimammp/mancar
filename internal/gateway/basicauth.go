package gateway

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"strings"
	"unicode/utf8"
)

// MinAuthPassword is the shortest password accepted for --auth: the tunnel
// is on the internet and the gateway limits, but cannot stop, guessing.
const MinAuthPassword = 8

// BasicAuthCheck holds the credentials of a tunnel behind a password, as a
// hash only (the password is not kept, not even in memory).
type BasicAuthCheck struct {
	user string
	sum  [32]byte // SHA-256 of user ":" password
}

// NewBasicAuthCheck validates the credentials an agent asked for.
func NewBasicAuthCheck(user, password string) (*BasicAuthCheck, error) {
	switch {
	case user == "" || len(user) > 64 || strings.ContainsAny(user, ":\r\n") || !utf8.ValidString(user):
		return nil, errors.New("auth: the user name must be 1-64 characters without ':'")
	case utf8.RuneCountInString(password) < MinAuthPassword || len(password) > 256 || strings.ContainsAny(password, "\r\n"):
		return nil, errors.New("auth: the password must be at least 8 characters")
	}
	return &BasicAuthCheck{user: user, sum: sha256.Sum256([]byte(user + ":" + password))}, nil
}

// User is the expected user name (for the 401 realm and logs).
func (c *BasicAuthCheck) User() string { return c.user }

// Match reports, in constant time, whether user and password are right.
func (c *BasicAuthCheck) Match(user, password string) bool {
	got := sha256.Sum256([]byte(user + ":" + password))
	return subtle.ConstantTimeCompare(got[:], c.sum[:]) == 1
}
