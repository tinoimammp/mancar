package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestWellFormed(t *testing.T) {
	tests := []struct {
		name string
		tok  string
		want bool
	}{
		{"valid", TokenPrefix + strings.Repeat("a", 64), true},
		{"empty", "", false},
		{"prefix only", TokenPrefix, false},
		{"missing prefix", strings.Repeat("a", 67), false},
		{"wrong prefix", "xx_" + strings.Repeat("a", 64), false},
		{"upper-case prefix", "MT_" + strings.Repeat("a", 64), false},
		{"too short", TokenPrefix + strings.Repeat("a", 63), false},
		{"too long", TokenPrefix + strings.Repeat("a", 65), false},
		{"bearer included", "Bearer " + TokenPrefix + strings.Repeat("a", 64), false},
	}
	for _, tc := range tests {
		if got := WellFormed(tc.tok); got != tc.want {
			t.Errorf("%s: WellFormed(%q) = %v, want %v", tc.name, tc.tok, got, tc.want)
		}
	}
}

func TestNewToken_FormatAndEntropy(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 200; i++ {
		tok, hash, err := NewToken()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(tok, TokenPrefix) || len(tok) != len(TokenPrefix)+64 {
			t.Fatalf("unexpected token shape %q", tok)
		}
		if !WellFormed(tok) {
			t.Fatalf("NewToken produced a token WellFormed rejects: %q", tok)
		}
		for _, r := range strings.TrimPrefix(tok, TokenPrefix) {
			if !strings.ContainsRune("0123456789abcdef", r) {
				t.Fatalf("token body must be lower-case hex, got %q", tok)
			}
		}
		if len(hash) != 64 || hash == tok {
			t.Fatalf("hash %q looks wrong", hash)
		}
		if _, dup := seen[tok]; dup {
			t.Fatalf("duplicate token %q", tok)
		}
		seen[tok] = struct{}{}
	}
}

func TestHashToken(t *testing.T) {
	// SHA-256("abc") is a published test vector.
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := HashToken("abc"); got != want {
		t.Errorf("HashToken(abc) = %s, want %s", got, want)
	}
	if HashToken("a") == HashToken("b") {
		t.Error("different tokens must hash differently")
	}
	if HashToken("same") != HashToken("same") {
		t.Error("hashing must be deterministic")
	}
	if got := HashToken(""); len(got) != 64 {
		t.Errorf("hash of empty string has length %d", len(got))
	}
}

func TestMemory_UnknownAndEmptyTokensAreRejected(t *testing.T) {
	m := NewMemory()
	for _, tok := range []string{"", "mc_", TokenPrefix + strings.Repeat("0", 64), "garbage"} {
		if _, err := m.AuthenticateAgent(context.Background(), tok); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("AuthenticateAgent(%q) err = %v, want ErrInvalidToken", tok, err)
		}
	}
}

func TestMemory_IssueSetsPrincipal(t *testing.T) {
	m := NewMemory()
	tok, err := m.Issue("alice")
	if err != nil {
		t.Fatal(err)
	}
	p, err := m.AuthenticateAgent(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if p.UserID != "alice" {
		t.Errorf("UserID = %q", p.UserID)
	}
	if want := HashToken(tok)[:12]; p.TokenID != want {
		t.Errorf("TokenID = %q, want %q (hash prefix, never the token)", p.TokenID, want)
	}
	if strings.Contains(p.TokenID, strings.TrimPrefix(tok, TokenPrefix)) {
		t.Error("TokenID must not expose the token")
	}
}

func TestMemory_AddRegistersStaticToken(t *testing.T) {
	m := NewMemory()
	m.Add("dev-token", "dev-user")
	p, err := m.AuthenticateAgent(context.Background(), "dev-token")
	if err != nil {
		t.Fatal(err)
	}
	if p.UserID != "dev-user" || p.TokenID != "static" {
		t.Errorf("principal = %+v", p)
	}
	m.Add("dev-token", "someone-else") // re-adding overwrites
	if p, _ := m.AuthenticateAgent(context.Background(), "dev-token"); p.UserID != "someone-else" {
		t.Errorf("re-added token maps to %q", p.UserID)
	}
}

func TestMemory_TokensAreIsolatedPerUser(t *testing.T) {
	m := NewMemory()
	ta, _ := m.Issue("alice")
	tb, _ := m.Issue("bob")
	ctx := context.Background()

	if p, _ := m.AuthenticateAgent(ctx, ta); p.UserID != "alice" {
		t.Errorf("alice's token resolved to %q", p.UserID)
	}
	if p, _ := m.AuthenticateAgent(ctx, tb); p.UserID != "bob" {
		t.Errorf("bob's token resolved to %q", p.UserID)
	}

	m.Revoke(ta)
	if _, err := m.AuthenticateAgent(ctx, ta); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("revoked token still valid: %v", err)
	}
	if _, err := m.AuthenticateAgent(ctx, tb); err != nil {
		t.Errorf("revoking alice's token broke bob's: %v", err)
	}
}

func TestMemory_RevokeUnknownTokenIsNoop(t *testing.T) {
	m := NewMemory()
	tok, _ := m.Issue("alice")
	m.Revoke("never-issued")
	if _, err := m.AuthenticateAgent(context.Background(), tok); err != nil {
		t.Errorf("unrelated revoke affected valid token: %v", err)
	}
}

func TestMemory_ModifiedTokenIsRejected(t *testing.T) {
	m := NewMemory()
	tok, _ := m.Issue("alice")
	variants := []string{
		tok + " ",
		" " + tok,
		strings.ToUpper(tok),
		tok[:len(tok)-1],
		tok[:len(tok)-1] + "x",
	}
	for _, v := range variants {
		if _, err := m.AuthenticateAgent(context.Background(), v); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("variant %q accepted (err=%v)", v, err)
		}
	}
}

func TestMemory_ConcurrentUse(t *testing.T) {
	m := NewMemory()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			user := fmt.Sprintf("user-%d", i)
			tok, err := m.Issue(user)
			if err != nil {
				t.Errorf("Issue: %v", err)
				return
			}
			p, err := m.AuthenticateAgent(context.Background(), tok)
			if err != nil || p.UserID != user {
				t.Errorf("auth after issue: %+v %v", p, err)
			}
			m.Revoke(tok)
			if _, err := m.AuthenticateAgent(context.Background(), tok); !errors.Is(err, ErrInvalidToken) {
				t.Errorf("token valid after revoke: %v", err)
			}
		}(i)
	}
	wg.Wait()
}
