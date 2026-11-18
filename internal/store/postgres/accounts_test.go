package postgres_test

import (
	"context"
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"
	"time"

	"github.com/tinoimammp/mancar/internal/auth"
	"github.com/tinoimammp/mancar/internal/domain"
	"github.com/tinoimammp/mancar/internal/store/postgres"
	"github.com/tinoimammp/mancar/migrations"
)

func TestAccounts_AdminSetListDemote(t *testing.T) {
	st := newStore(t, true)
	ctx := context.Background()
	created, err := st.SetAdmin(ctx, " Root ", "hash1")
	if err != nil || !created {
		t.Fatalf("SetAdmin create: created=%v err=%v", created, err)
	}
	a, err := st.AccountByLogin(ctx, "ROOT")
	if err != nil || a.PasswordHash != "hash1" || !a.IsAdmin() || a.LastLoginAt != nil {
		t.Fatalf("AccountByLogin: %+v %v", a, err)
	}
	time.Sleep(10 * time.Millisecond)
	if created, err := st.SetAdmin(ctx, "root", "hash2"); err != nil || created {
		t.Fatalf("SetAdmin reset: created=%v err=%v", created, err)
	}
	b, _ := st.AccountByID(ctx, a.ID)
	if b.PasswordHash != "hash2" || !b.PasswordChangedAt.After(a.PasswordChangedAt) {
		t.Errorf("reset did not update hash and password_changed_at: %+v", b)
	}
	if err := st.TouchLogin(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if list, err := st.ListAdmins(ctx); err != nil || len(list) != 1 || list[0].LastLoginAt == nil {
		t.Errorf("ListAdmins: %+v %v", list, err)
	}
	if err := st.DeleteAdmin(ctx, "root"); err != nil {
		t.Fatal(err)
	}
	if c, _ := st.AccountByID(ctx, a.ID); c.IsAdmin() {
		t.Error("admin delete left the admin role")
	}
	if err := st.DeleteAdmin(ctx, "root"); !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
}

func TestAccounts_SignupUniqueness(t *testing.T) {
	st := newStore(t, true)
	ctx := context.Background()
	id, err := st.CreateAccount(ctx, postgres.NewAccount{Username: "alice", Email: " Alice@Example.COM ", PasswordHash: "h", SignedUp: true})
	if err != nil {
		t.Fatal(err)
	}
	a, err := st.AccountByLogin(ctx, "alice@example.com")
	if err != nil || a.ID != id || a.Email != "alice@example.com" || a.Verified() || a.Role != postgres.RoleUser {
		t.Fatalf("by email: %+v %v", a, err)
	}
	if a.MaxTokens == nil || *a.MaxTokens != postgres.SignupMaxTokens || a.MaxCustomDomains == nil {
		t.Errorf("sign up limits not set: %+v", a)
	}
	if _, err := st.CreateAccount(ctx, postgres.NewAccount{Username: "alice", Email: "other@example.com", PasswordHash: "h", SignedUp: true}); !errors.Is(err, postgres.ErrUsernameTaken) {
		t.Errorf("same username: %v", err)
	}
	if _, err := st.CreateAccount(ctx, postgres.NewAccount{Username: "alice2", Email: "ALICE@example.com", PasswordHash: "h", SignedUp: true}); !errors.Is(err, postgres.ErrEmailTaken) {
		t.Errorf("same email: %v", err)
	}
	// a token-only user (made by an admin creating a token) cannot be taken
	// over by sign up, but an admin can give it a password
	if _, err := st.EnsureUser(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAccount(ctx, postgres.NewAccount{Username: "bob", Email: "bob@example.com", PasswordHash: "h", SignedUp: true}); !errors.Is(err, postgres.ErrUsernameTaken) {
		t.Errorf("sign up over a token-only user: %v", err)
	}
	if _, err := st.CreateAccount(ctx, postgres.NewAccount{Username: "bob", PasswordHash: "h", Role: postgres.RoleAdmin}); err != nil {
		t.Errorf("admin giving a token-only user a password: %v", err)
	}
	if _, err := st.CreateAccount(ctx, postgres.NewAccount{Username: "bob", PasswordHash: "h2"}); !errors.Is(err, postgres.ErrUsernameTaken) {
		t.Errorf("second takeover of an account with a password: %v", err)
	}
}

func TestAccounts_EmailLinks(t *testing.T) {
	st := newStore(t, true)
	ctx := context.Background()
	id, _ := st.CreateAccount(ctx, postgres.NewAccount{Username: "carol", Email: "carol@example.com", PasswordHash: "h", SignedUp: true})

	first, err := st.CreateEmailLink(ctx, id, postgres.LinkVerify, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := st.CreateEmailLink(ctx, id, postgres.LinkVerify, time.Hour)
	if _, err := st.UseEmailLink(ctx, postgres.LinkVerify, first); !errors.Is(err, postgres.ErrLinkInvalid) {
		t.Errorf("an older link still works: %v", err)
	}
	if _, err := st.UseEmailLink(ctx, postgres.LinkReset, second); !errors.Is(err, postgres.ErrLinkInvalid) {
		t.Errorf("a verify link worked as a reset link: %v", err)
	}
	if got, err := st.UseEmailLink(ctx, postgres.LinkVerify, second); err != nil || got != id {
		t.Fatalf("use: %q %v", got, err)
	}
	if _, err := st.UseEmailLink(ctx, postgres.LinkVerify, second); !errors.Is(err, postgres.ErrLinkInvalid) {
		t.Errorf("a link worked twice: %v", err)
	}
	if n := count(t, st, `SELECT count(*) FROM email_tokens WHERE token_hash LIKE '%' || $1 || '%'`, second); n != 0 {
		t.Error("the link secret is stored in plain text")
	}

	// a link sent to an address the account no longer has is void
	reset, _ := st.CreateEmailLink(ctx, id, postgres.LinkReset, time.Hour)
	if err := st.SetEmail(ctx, id, "new@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UseEmailLink(ctx, postgres.LinkReset, reset); !errors.Is(err, postgres.ErrLinkInvalid) {
		t.Errorf("link to the old address still works: %v", err)
	}
	expired, _ := st.CreateEmailLink(ctx, id, postgres.LinkReset, time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	if _, err := st.UseEmailLink(ctx, postgres.LinkReset, expired); !errors.Is(err, postgres.ErrLinkInvalid) {
		t.Errorf("expired link works: %v", err)
	}
}

func TestAccounts_LastAdminIsKept(t *testing.T) {
	st := newStore(t, true)
	ctx := context.Background()
	st.SetAdmin(ctx, "root", "h")
	root, _ := st.AccountByLogin(ctx, "root")
	if err := st.SetRole(ctx, root.ID, postgres.RoleUser); !errors.Is(err, postgres.ErrLastAdmin) {
		t.Errorf("demoting the last admin: %v", err)
	}
	if err := st.SetDisabled(ctx, root.ID, true); !errors.Is(err, postgres.ErrLastAdmin) {
		t.Errorf("disabling the last admin: %v", err)
	}
	if err := st.DeleteAccount(ctx, root.ID); !errors.Is(err, postgres.ErrLastAdmin) {
		t.Errorf("deleting the last admin: %v", err)
	}
	st.SetAdmin(ctx, "second", "h")
	if err := st.SetRole(ctx, root.ID, postgres.RoleUser); err != nil {
		t.Errorf("demoting one of two admins: %v", err)
	}
	if a, _ := st.AccountByID(ctx, root.ID); a.IsAdmin() {
		t.Error("role unchanged")
	}
}

func TestAccounts_DisabledTokensAreRefused(t *testing.T) {
	st := newStore(t, true)
	ctx := context.Background()
	uid, _ := st.EnsureUser(ctx, "dave")
	tok, _, err := st.CreateAgentToken(ctx, uid, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AuthenticateAgent(ctx, tok); err != nil {
		t.Fatalf("enabled: %v", err)
	}
	if err := st.SetDisabled(ctx, uid, true); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AuthenticateAgent(ctx, tok); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("disabled account's token accepted: %v", err)
	}
	st.SetDisabled(ctx, uid, false)
	if _, err := st.AuthenticateAgent(ctx, tok); err != nil {
		t.Errorf("token after enabling again: %v", err)
	}
	ids, err := st.RevokeUserTokens(ctx, uid)
	if err != nil || len(ids) != 1 {
		t.Errorf("RevokeUserTokens: %v %v", ids, err)
	}
}

func TestAccounts_UsableTokens(t *testing.T) {
	st := newStore(t, true)
	ctx := context.Background()
	ana, _ := st.EnsureUser(ctx, "ana")
	budi, _ := st.EnsureUser(ctx, "budi")
	_, keep, _ := st.CreateAgentToken(ctx, ana, "laptop")
	_, revoked, _ := st.CreateAgentToken(ctx, ana, "old")
	_, disabled, _ := st.CreateAgentToken(ctx, budi, "server")
	if err := st.RevokeAgentToken(ctx, revoked); err != nil {
		t.Fatal(err)
	}
	if err := st.SetDisabled(ctx, budi, true); err != nil {
		t.Fatal(err)
	}
	got, err := st.UsableTokens(ctx, []string{keep, revoked, disabled, "not-a-uuid"})
	if err != nil {
		t.Fatal(err)
	}
	if !got[keep] || got[revoked] || got[disabled] || len(got) != 1 {
		t.Errorf("UsableTokens = %v, want only %s", got, keep)
	}
}

func TestAccounts_CustomDomainLimit(t *testing.T) {
	st := newStore(t, true)
	ctx := context.Background()
	id, _ := st.CreateAccount(ctx, postgres.NewAccount{Username: "erin", Email: "erin@example.com", PasswordHash: "h", SignedUp: true})
	one := 1
	st.SetLimits(ctx, id, nil, &one)
	claim := func(host string) error {
		_, err := st.Claim(ctx, domain.Claim{Hostname: host, OwnerID: id, Kind: domain.KindCustom, TunnelID: "t-" + host})
		return err
	}
	if err := claim("a.example.test"); err != nil {
		t.Fatal(err)
	}
	if err := claim("b.example.test"); !errors.Is(err, domain.ErrLimitReached) {
		t.Errorf("second custom name over a limit of 1: %v", err)
	}
	st.Release(ctx, "a.example.test", "t-a.example.test", time.Hour)
	if err := claim("a.example.test"); err != nil {
		t.Errorf("reclaiming a name already held: %v", err)
	}
	if _, err := st.Claim(ctx, domain.Claim{Hostname: "r.example.test", OwnerID: id, Kind: domain.KindRandom, TunnelID: "t-r"}); err != nil {
		t.Errorf("random names are not limited: %v", err)
	}
	st.SetLimits(ctx, id, nil, nil)
	if err := claim("b.example.test"); err != nil {
		t.Errorf("no limit: %v", err)
	}
}

func TestAccounts_PurgeUnconfirmedAndAudit(t *testing.T) {
	st := newStore(t, true)
	ctx := context.Background()
	stale, _ := st.CreateAccount(ctx, postgres.NewAccount{Username: "stale", Email: "stale@example.com", PasswordHash: "h", SignedUp: true})
	ok, _ := st.CreateAccount(ctx, postgres.NewAccount{Username: "ok", Email: "ok@example.com", PasswordHash: "h", SignedUp: true})
	st.SetEmailVerified(ctx, ok, true)
	st.EnsureUser(ctx, "tokenonly")
	// in use, but unconfirmed again after an admin changed the address
	used, _ := st.CreateAccount(ctx, postgres.NewAccount{Username: "used", Email: "used@example.com", PasswordHash: "h", SignedUp: true})
	st.TouchLogin(ctx, used)
	n, err := st.PurgeUnconfirmed(ctx, time.Now().Add(time.Minute))
	if err != nil || n != 1 {
		t.Fatalf("PurgeUnconfirmed: %d %v", n, err)
	}
	if _, err := st.AccountByID(ctx, stale); !errors.Is(err, postgres.ErrNotFound) {
		t.Error("unconfirmed sign up kept")
	}
	if _, err := st.AccountByID(ctx, used); err != nil {
		t.Errorf("an account that signed in was purged: %v", err)
	}

	st.AddAudit(ctx, postgres.AuditEntry{Actor: "root", Action: "user.disable", Target: "ok"})
	st.AddAudit(ctx, postgres.AuditEntry{Actor: "root", Action: "user.enable", Target: "ok"})
	list, err := st.ListAudit(ctx, 10)
	if err != nil || len(list) != 2 || list[0].Action != "user.enable" {
		t.Errorf("ListAudit: %+v %v", list, err)
	}
}

// Upgrading from v0.3.x: admins move into users; an admin and a user with
// the same name become one admin account that keeps the user's tokens.
func TestMigrate_AdminsMergeIntoUsers(t *testing.T) {
	st := newStore(t, false)
	ctx := context.Background()
	old := fstest.MapFS{}
	all, _ := fs.Glob(migrations.FS, "*.sql")
	for _, name := range all {
		if name < "0006" {
			b, _ := fs.ReadFile(migrations.FS, name)
			old[name] = &fstest.MapFile{Data: b}
		}
	}
	if err := st.Migrate(ctx, old); err != nil {
		t.Fatal(err)
	}
	uid, _ := st.EnsureUser(ctx, "tino")
	st.CreateAgentToken(ctx, uid, "laptop")
	for _, name := range []string{"tino", "root"} {
		if _, err := st.DB.Exec(`INSERT INTO admins (username, password_hash) VALUES ($1, 'pbkdf2-sha256$1$AA$AA')`, name); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Migrate(ctx, migrations.FS); err != nil {
		t.Fatal(err)
	}
	tino, err := st.AccountByLogin(ctx, "tino")
	if err != nil || !tino.IsAdmin() || tino.ID != uid || tino.PasswordHash == "" {
		t.Fatalf("merged tino: %+v %v", tino, err)
	}
	if n := count(t, st, `SELECT count(*) FROM agent_tokens WHERE user_id = $1`, uid); n != 1 {
		t.Errorf("merged admin lost the user's tokens: %d", n)
	}
	if root, err := st.AccountByLogin(ctx, "root"); err != nil || !root.IsAdmin() {
		t.Errorf("root: %+v %v", root, err)
	}
	if n := count(t, st, `SELECT count(*) FROM information_schema.tables WHERE table_name = 'admins' AND table_schema = current_schema()`); n != 0 {
		t.Error("admins table still exists")
	}
}

func TestAccounts_FirstAdminSetup(t *testing.T) {
	st := newStore(t, true)
	ctx := context.Background()
	if ok, err := st.SetupDone(ctx); err != nil || ok {
		t.Fatalf("fresh database: %v %v", ok, err)
	}
	// two setups at once: exactly one wins
	errs := make(chan error, 2)
	for _, name := range []string{"first", "second"} {
		go func() {
			_, err := st.CreateFirstAdmin(ctx, postgres.NewAccount{Username: name, PasswordHash: "h"})
			errs <- err
		}()
	}
	var won, lost int
	for i := 0; i < 2; i++ {
		switch err := <-errs; {
		case err == nil:
			won++
		case errors.Is(err, postgres.ErrSetupDone):
			lost++
		default:
			t.Fatal(err)
		}
	}
	if won != 1 || lost != 1 {
		t.Errorf("won %d, lost %d", won, lost)
	}
	if ok, _ := st.SetupDone(ctx); !ok {
		t.Error("no admin after setup")
	}
	// demoting the last admin must not reopen the public setup page
	a, _ := st.AccountByLogin(ctx, "first")
	if a.ID == "" {
		a, _ = st.AccountByLogin(ctx, "second")
	}
	if err := st.DeleteAdmin(ctx, a.Username); err != nil {
		t.Fatal(err)
	}
	if ok, _ := st.SetupDone(ctx); !ok {
		t.Error("setup reopened after the last admin was demoted")
	}
	if _, err := st.CreateFirstAdmin(ctx, postgres.NewAccount{Username: "intruder", PasswordHash: "h"}); !errors.Is(err, postgres.ErrSetupDone) {
		t.Errorf("CreateFirstAdmin after demotion: %v", err)
	}
}

// "mancard admin set NAME" must not promote an account someone made by
// signing up with that name first: their email could reset the password.
func TestAccounts_AdminSetLeavesSignUpsAlone(t *testing.T) {
	st := newStore(t, true)
	ctx := context.Background()
	if _, err := st.CreateAccount(ctx, postgres.NewAccount{Username: "admin", Email: "eve@example.com", PasswordHash: "h", SignedUp: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetAdmin(ctx, "admin", "new"); !errors.Is(err, postgres.ErrHasEmail) {
		t.Fatalf("SetAdmin on a sign up: %v", err)
	}
	a, err := st.AccountByLogin(ctx, "admin")
	if err != nil || a.Role != postgres.RoleUser || a.PasswordHash != "h" {
		t.Errorf("the sign up was changed: %+v %v", a, err)
	}
	// a token-only user (no email) is still promoted as before
	if _, err := st.EnsureUser(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	if created, err := st.SetAdmin(ctx, "ops", "h2"); err != nil || created {
		t.Errorf("SetAdmin on a token-only user: %v %v", created, err)
	}
}

func TestPendingMigrations(t *testing.T) {
	st := newStore(t, false)
	ctx := context.Background()
	fsys := fstest.MapFS{"0001_a.sql": {Data: []byte("CREATE TABLE a (x int);")}}
	if pending, fresh, err := st.PendingMigrations(ctx, fsys); err != nil || !fresh || len(pending) != 1 {
		t.Fatalf("never migrated: %v %v %v", pending, fresh, err)
	}
	if err := st.Migrate(ctx, fsys); err != nil {
		t.Fatal(err)
	}
	if pending, fresh, err := st.PendingMigrations(ctx, fsys); err != nil || fresh || len(pending) != 0 {
		t.Errorf("up to date: %v %v %v", pending, fresh, err)
	}
	fsys["0002_b.sql"] = &fstest.MapFile{Data: []byte("CREATE TABLE b (x int);")}
	if pending, fresh, err := st.PendingMigrations(ctx, fsys); err != nil || fresh || len(pending) != 1 || pending[0] != "0002_b.sql" {
		t.Errorf("one behind: %v %v %v", pending, fresh, err)
	}
}
