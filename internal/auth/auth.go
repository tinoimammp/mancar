// Package auth contains credential primitives and the Authenticator
// interface the gateway depends on. Storage lives elsewhere
// (internal/store/postgres) so business logic stays independent of
// infrastructure.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
)

// TokenPrefix marks agent tokens so they are recognisable in secret scanners.
const TokenPrefix = "mc_"

// ErrInvalidToken is returned for unknown, malformed or revoked tokens.
var ErrInvalidToken = errors.New("auth: invalid or revoked token")

// Principal is the authenticated owner of an agent connection.
type Principal struct {
	UserID  string
	TokenID string
}

// Authenticator validates agent tokens.
type Authenticator interface {
	AuthenticateAgent(ctx context.Context, token string) (Principal, error)
}

// NewToken returns a fresh token (256 bits of entropy) and the hash that
// must be stored instead of it.
func NewToken() (plaintext, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	plaintext = TokenPrefix + hex.EncodeToString(b)
	return plaintext, HashToken(plaintext), nil
}

// HashToken derives the storage hash. Tokens are uniformly random 256-bit
// values, so a single SHA-256 is appropriate (a slow KDF is only needed for
// low-entropy secrets such as passwords).
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// WellFormed cheaply rejects strings that cannot be tokens.
func WellFormed(token string) bool {
	return strings.HasPrefix(token, TokenPrefix) && len(token) == len(TokenPrefix)+64
}

// Memory is an in-memory Authenticator for tests and development mode.
type Memory struct {
	mu     sync.RWMutex
	byHash map[string]Principal
}

// NewMemory returns an empty in-memory authenticator.
func NewMemory() *Memory { return &Memory{byHash: map[string]Principal{}} }

// Issue creates a token for userID.
func (m *Memory) Issue(userID string) (string, error) {
	tok, hash, err := NewToken()
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	m.byHash[hash] = Principal{UserID: userID, TokenID: hash[:12]}
	m.mu.Unlock()
	return tok, nil
}

// Add registers an externally supplied token (development mode).
func (m *Memory) Add(token, userID string) {
	m.mu.Lock()
	m.byHash[HashToken(token)] = Principal{UserID: userID, TokenID: "static"}
	m.mu.Unlock()
}

// Revoke removes a token.
func (m *Memory) Revoke(token string) {
	m.mu.Lock()
	delete(m.byHash, HashToken(token))
	m.mu.Unlock()
}

// AuthenticateAgent implements Authenticator.
func (m *Memory) AuthenticateAgent(_ context.Context, token string) (Principal, error) {
	m.mu.RLock()
	p, ok := m.byHash[HashToken(token)]
	m.mu.RUnlock()
	if !ok {
		return Principal{}, ErrInvalidToken
	}
	return p, nil
}
