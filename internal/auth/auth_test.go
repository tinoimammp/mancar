package auth

import (
	"context"
	"errors"
	"testing"
)

func TestTokenLifecycle(t *testing.T) {
	m := NewMemory()
	tok, err := m.Issue("u1")
	if err != nil {
		t.Fatal(err)
	}
	if !WellFormed(tok) {
		t.Fatalf("token not well formed: %q", tok)
	}
	p, err := m.AuthenticateAgent(context.Background(), tok)
	if err != nil || p.UserID != "u1" {
		t.Fatalf("auth: %+v %v", p, err)
	}
	if _, err := m.AuthenticateAgent(context.Background(), tok+"x"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("want ErrInvalidToken, got %v", err)
	}
	m.Revoke(tok)
	if _, err := m.AuthenticateAgent(context.Background(), tok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("revoked token accepted: %v", err)
	}
}

func TestTokensAreUniqueAndHashed(t *testing.T) {
	a, ha, _ := NewToken()
	b, hb, _ := NewToken()
	if a == b || ha == hb {
		t.Fatal("tokens must be unique")
	}
	if ha == a || HashToken(a) != ha {
		t.Fatal("hash mismatch")
	}
}
