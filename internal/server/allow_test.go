package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tinoimammp/mancar/internal/gateway"
	"github.com/tinoimammp/mancar/internal/store/postgres"
)

type accounts map[string]postgres.Account

func (a accounts) AccountByLogin(_ context.Context, login string) (postgres.Account, error) {
	if acc, ok := a[login]; ok {
		return acc, nil
	}
	return postgres.Account{}, postgres.ErrNotFound
}

func TestResolveLoginsOnlyConfirmedActiveAccounts(t *testing.T) {
	now := time.Now()
	resolve := resolveLogins(accounts{
		"budi":         {ID: "u1", Username: "budi", Email: "budi@example.com", EmailVerifiedAt: &now},
		"ana":          {ID: "u2", Username: "ana"},                        // no email (made by an admin): counts as confirmed
		"boss@corp.io": {ID: "u3", Username: "eve", Email: "boss@corp.io"}, // signed up, never confirmed
		"off":          {ID: "u4", Username: "off", DisabledAt: &now},
	})
	got, err := resolve(context.Background(), []string{"budi", "ana"})
	if err != nil || got["u1"] != "budi" || got["u2"] != "ana" {
		t.Fatalf("%v %v", got, err)
	}
	for _, login := range []string{"boss@corp.io", "off", "ghost"} {
		if _, err := resolve(context.Background(), []string{"budi", login}); !errors.Is(err, gateway.ErrUnknownUser) {
			t.Errorf("%s: %v", login, err)
		}
	}
	if resolveLogins(adminFinder(nil)) != nil {
		t.Error("without accounts, sharing should be off")
	}
}
