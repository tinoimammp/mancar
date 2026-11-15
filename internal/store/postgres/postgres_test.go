package postgres_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/tinoimammp/mancar/internal/auth"
	"github.com/tinoimammp/mancar/internal/domain"
	"github.com/tinoimammp/mancar/internal/domain/domaintest"
	"github.com/tinoimammp/mancar/internal/inspect"
	"github.com/tinoimammp/mancar/internal/store/postgres"
	"github.com/tinoimammp/mancar/internal/usage"
	"github.com/tinoimammp/mancar/migrations"
)

var (
	_ auth.Authenticator = (*postgres.Store)(nil)
	_ domain.Registry    = (*postgres.Store)(nil)
)

// newStore returns a Store working in a private, throw-away schema of the
// database named by TEST_DATABASE_URL, so tests never see each other's rows.
func newStore(t *testing.T, migrate bool) *postgres.Store {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping PostgreSQL tests")
	}
	admin, err := sql.Open("postgres", base)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	schema := "t_" + hex.EncodeToString(b)
	if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()

	ctx := context.Background()
	st, err := postgres.Open(ctx, u.String(), 10*time.Second)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		st.Close()
		admin.Exec("DROP SCHEMA " + schema + " CASCADE")
		admin.Close()
	})
	if migrate {
		if err := st.Migrate(ctx, migrations.FS); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
	}
	return st
}

func count(t *testing.T, st *postgres.Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := st.DB.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// ---- Open / Ping (no database required) -------------------------------------

func TestOpen_UnreachableDatabaseFailsAfterTheWaitBudget(t *testing.T) {
	start := time.Now()
	_, err := postgres.Open(context.Background(),
		"postgres://u:p@127.0.0.1:1/db?sslmode=disable&connect_timeout=1", 1500*time.Millisecond)
	if err == nil {
		t.Fatal("Open succeeded against a closed port")
	}
	if !strings.Contains(err.Error(), "not reachable") {
		t.Errorf("err = %v", err)
	}
	if strings.Contains(err.Error(), ":p@") {
		t.Errorf("error leaks the database password: %v", err)
	}
	if d := time.Since(start); d > 8*time.Second {
		t.Errorf("Open took %v, want it to give up after the wait budget", d)
	}
}

func TestOpen_CancelledContextReturnsPromptly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err := postgres.Open(ctx, "postgres://u:p@127.0.0.1:1/db?sslmode=disable&connect_timeout=1", time.Minute)
	if err == nil {
		t.Fatal("expected an error")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Open ignored the cancelled context for %v", d)
	}
}

func TestPing(t *testing.T) {
	st := newStore(t, false)
	if err := st.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	st.Close()
	if err := st.Ping(context.Background()); err == nil {
		t.Error("Ping succeeded on a closed store")
	}
}

// ---- migrations -------------------------------------------------------------

func TestMigrate_CreatesSchemaAndIsIdempotent(t *testing.T) {
	st := newStore(t, false)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := st.Migrate(ctx, migrations.FS); err != nil {
			t.Fatalf("Migrate run %d: %v", i+1, err)
		}
	}
	for _, table := range []string{"users", "agent_tokens", "domains", "admins", "captured_requests", "usage_hourly", "usage_daily", "usage_total", "schema_migrations"} {
		if n := count(t, st, `SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1`, table); n != 1 {
			t.Errorf("table %s missing", table)
		}
	}
	if n := count(t, st, `SELECT count(*) FROM schema_migrations`); n < 1 {
		t.Errorf("schema_migrations has %d rows", n)
	}
	if n := count(t, st, `SELECT count(*) FROM schema_migrations WHERE version = '0001_init'`); n != 1 {
		t.Errorf("0001_init recorded %d times, want exactly once", n)
	}
}

func TestMigrate_ConcurrentCallersAreSerialised(t *testing.T) {
	st := newStore(t, false)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- st.Migrate(context.Background(), migrations.FS)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Migrate: %v", err)
		}
	}
	if n := count(t, st, `SELECT count(*) FROM schema_migrations WHERE version = '0001_init'`); n != 1 {
		t.Errorf("0001_init applied %d times under concurrency", n)
	}
}

func TestMigrate_FailedMigrationRollsBackCompletely(t *testing.T) {
	st := newStore(t, false)
	ctx := context.Background()
	fsys := fstest.MapFS{
		"0001_ok.sql":  {Data: []byte(`CREATE TABLE ok_t (id int);`)},
		"0002_bad.sql": {Data: []byte(`CREATE TABLE half_t (id int); SELECT * FROM table_that_does_not_exist;`)},
	}
	err := st.Migrate(ctx, fsys)
	if err == nil || !strings.Contains(err.Error(), "0002_bad") {
		t.Fatalf("err = %v, want a failure naming 0002_bad", err)
	}
	has := func(table string) bool {
		return count(t, st, `SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1`, table) == 1
	}
	if !has("ok_t") {
		t.Error("the successful earlier migration was lost")
	}
	if has("half_t") {
		t.Error("a half-applied migration left half_t behind (not atomic)")
	}
	if n := count(t, st, `SELECT count(*) FROM schema_migrations WHERE version = '0002_bad'`); n != 0 {
		t.Error("a failed migration was recorded as applied")
	}
	if err := st.Migrate(ctx, fsys); err == nil {
		t.Error("the failing migration was silently skipped on the second run")
	}
}

func TestMigrate_LexicalOrderAndIncrementalApplication(t *testing.T) {
	st := newStore(t, false)
	ctx := context.Background()
	v1 := fstest.MapFS{
		"0002_second.sql": {Data: []byte(`INSERT INTO ord (v) VALUES ('b');`)},
		"0001_first.sql":  {Data: []byte(`CREATE TABLE ord (v text); INSERT INTO ord (v) VALUES ('a');`)},
	}
	if err := st.Migrate(ctx, v1); err != nil {
		t.Fatalf("migrations applied out of order: %v", err)
	}
	if n := count(t, st, `SELECT count(*) FROM ord`); n != 2 {
		t.Fatalf("ord has %d rows", n)
	}

	// A later release adds a migration; earlier ones must not run again.
	v2 := fstest.MapFS{
		"0001_first.sql":  v1["0001_first.sql"],
		"0002_second.sql": v1["0002_second.sql"],
		"0003_third.sql":  {Data: []byte(`INSERT INTO ord (v) VALUES ('c');`)},
	}
	if err := st.Migrate(ctx, v2); err != nil {
		t.Fatal(err)
	}
	if n := count(t, st, `SELECT count(*) FROM ord`); n != 3 {
		t.Errorf("ord has %d rows, want 3 (old migrations re-ran or new one missing)", n)
	}
}

// ---- registry ---------------------------------------------------------------

// userMapped lets the shared contract suite, which uses owner names such as
// "alice", run against the real schema where owners are user UUIDs.
type userMapped struct {
	*postgres.Store
	mu  sync.Mutex
	ids map[string]string
	t   *testing.T
}

func (u *userMapped) id(name string) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if id, ok := u.ids[name]; ok {
		return id
	}
	id, err := u.Store.EnsureUser(context.Background(), name)
	if err != nil {
		u.t.Errorf("EnsureUser(%q): %v", name, err)
	}
	u.ids[name] = id
	return id
}

func (u *userMapped) Claim(ctx context.Context, c domain.Claim) (string, error) {
	c.OwnerID = u.id(c.OwnerID)
	return u.Store.Claim(ctx, c)
}

func TestRegistry_SharedContract(t *testing.T) {
	st := newStore(t, true)
	reg := &userMapped{Store: st, ids: map[string]string{}, t: t}
	advance := func(d time.Duration) {
		if _, err := st.DB.Exec(`UPDATE domains SET hold_until = hold_until - make_interval(secs => $1)`, d.Seconds()); err != nil {
			t.Fatal(err)
		}
	}
	domaintest.RunRegistryContract(t, reg, advance)
}

func TestRegistry_ClaimRulesAgainstTheDatabase(t *testing.T) {
	st := newStore(t, true)
	ctx := context.Background()
	alice, _ := st.EnsureUser(ctx, "alice")
	bob, _ := st.EnsureUser(ctx, "bob")
	const host = "app.example.test"

	if k, err := st.Claim(ctx, domain.Claim{Hostname: host, OwnerID: alice, Kind: domain.KindCustom, TunnelID: "t1"}); err != nil || k != domain.KindCustom {
		t.Fatalf("first claim: %q %v", k, err)
	}
	row := func() (owner string, active sql.NullString, kind string) {
		if err := st.DB.QueryRow(`SELECT user_id::text, active_tunnel_id, kind FROM domains WHERE hostname = $1`, host).Scan(&owner, &active, &kind); err != nil {
			t.Fatal(err)
		}
		return
	}
	if owner, active, _ := row(); owner != alice || active.String != "t1" {
		t.Errorf("row after claim: owner=%s active=%v", owner, active)
	}

	if err := st.Release(ctx, host, "t1", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, active, _ := row(); active.Valid {
		t.Error("release left an active tunnel marker")
	}
	var holdSecs float64
	st.DB.QueryRow(`SELECT extract(epoch FROM hold_until - now()) FROM domains WHERE hostname = $1`, host).Scan(&holdSecs)
	if holdSecs < 3500 || holdSecs > 3601 {
		t.Errorf("hold = %.0fs, want about 3600", holdSecs)
	}
	if _, err := st.Claim(ctx, domain.Claim{Hostname: host, OwnerID: bob, Kind: domain.KindCustom, TunnelID: "t2"}); !errors.Is(err, domain.ErrHostnameTaken) {
		t.Errorf("bob during hold: %v", err)
	}
	if n := count(t, st, `SELECT count(*) FROM domains WHERE hostname = $1`, host); n != 1 {
		t.Errorf("%d rows for one hostname", n)
	}
}

func TestRegistry_ConcurrentClaimsAcrossManyHostnames(t *testing.T) {
	st := newStore(t, true)
	ctx := context.Background()
	const users, hosts = 8, 10
	ids := make([]string, users)
	for i := range ids {
		ids[i], _ = st.EnsureUser(ctx, fmt.Sprintf("user%d", i))
	}
	wins := make([]int32, hosts)
	var wg sync.WaitGroup
	for h := 0; h < hosts; h++ {
		for u := 0; u < users; u++ {
			wg.Add(1)
			go func(h, u int) {
				defer wg.Done()
				_, err := st.Claim(ctx, domain.Claim{
					Hostname: fmt.Sprintf("h%d.example.test", h), OwnerID: ids[u],
					Kind: domain.KindCustom, TunnelID: fmt.Sprintf("t-%d-%d", h, u),
				})
				if err == nil {
					atomic.AddInt32(&wins[h], 1)
				} else if !errors.Is(err, domain.ErrHostnameTaken) {
					t.Errorf("unexpected error: %v", err)
				}
			}(h, u)
		}
	}
	wg.Wait()
	for h, w := range wins {
		if w != 1 {
			t.Errorf("hostname %d has %d winners, want exactly 1", h, w)
		}
	}
}

func TestRegistry_ClaimForUnknownUserIsRejectedByForeignKey(t *testing.T) {
	st := newStore(t, true)
	_, err := st.Claim(context.Background(), domain.Claim{
		Hostname: "ghost.example.test", OwnerID: "00000000-0000-0000-0000-000000000000",
		Kind: domain.KindCustom, TunnelID: "t1",
	})
	if err == nil || errors.Is(err, domain.ErrHostnameTaken) {
		t.Fatalf("err = %v, want a foreign-key violation (not 'taken')", err)
	}
}

// ---- users and tokens -------------------------------------------------------

func TestEnsureUser(t *testing.T) {
	st := newStore(t, true)
	ctx := context.Background()
	a, err := st.EnsureUser(ctx, "  Alice ")
	if err != nil || a == "" {
		t.Fatalf("EnsureUser: %q %v", a, err)
	}
	b, err := st.EnsureUser(ctx, "alice")
	if err != nil || a != b {
		t.Errorf("same user got two IDs: %q vs %q (%v)", a, b, err)
	}
	if n := count(t, st, `SELECT count(*) FROM users`); n != 1 {
		t.Errorf("%d user rows, want 1", n)
	}
	for _, bad := range []string{"", "   "} {
		if _, err := st.EnsureUser(ctx, bad); err == nil {
			t.Errorf("EnsureUser(%q) accepted an empty name", bad)
		}
	}
}

func TestTokens_LifecycleAndStorageHygiene(t *testing.T) {
	st := newStore(t, true)
	ctx := context.Background()
	uid, _ := st.EnsureUser(ctx, "alice")

	plain, id, err := st.CreateAgentToken(ctx, uid, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if !auth.WellFormed(plain) {
		t.Fatalf("token %q is not well formed", plain)
	}

	// Only the hash may be stored.
	var stored string
	if err := st.DB.QueryRow(`SELECT token_hash FROM agent_tokens WHERE id::text = $1`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != auth.HashToken(plain) || stored == plain {
		t.Errorf("stored value %q is not the hash of the token", stored)
	}
	if n := count(t, st, `SELECT count(*) FROM agent_tokens WHERE token_hash = $1 OR name = $1`, plain); n != 0 {
		t.Error("the plaintext token is present in the database")
	}

	// Authenticates, records last use, and maps to the right principal.
	p, err := st.AuthenticateAgent(ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	if p.UserID != uid || p.TokenID != id {
		t.Errorf("principal = %+v, want user %s token %s", p, uid, id)
	}
	if n := count(t, st, `SELECT count(*) FROM agent_tokens WHERE id::text = $1 AND last_used_at IS NOT NULL`, id); n != 1 {
		t.Error("last_used_at was not recorded")
	}

	// Revocation is immediate and permanent.
	if err := st.RevokeAgentToken(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AuthenticateAgent(ctx, plain); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("revoked token accepted: %v", err)
	}
	if err := st.RevokeAgentToken(ctx, id); !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("second revoke = %v, want ErrNotFound", err)
	}
}

func TestTokens_UnknownAndMalformedAreRejected(t *testing.T) {
	st := newStore(t, true)
	ctx := context.Background()
	for _, tok := range []string{"", "garbage", auth.TokenPrefix + strings.Repeat("0", 64), "' OR '1'='1", "mc_'; DROP TABLE users;--"} {
		if _, err := st.AuthenticateAgent(ctx, tok); !errors.Is(err, auth.ErrInvalidToken) {
			t.Errorf("AuthenticateAgent(%q) = %v, want ErrInvalidToken", tok, err)
		}
	}
	if n := count(t, st, `SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'users'`); n != 1 {
		t.Error("users table is gone")
	}
	for _, id := range []string{"not-a-uuid", "", "00000000-0000-0000-0000-000000000000", "1' OR '1'='1"} {
		if err := st.RevokeAgentToken(ctx, id); !errors.Is(err, postgres.ErrNotFound) {
			t.Errorf("RevokeAgentToken(%q) = %v, want ErrNotFound", id, err)
		}
	}
}

func TestTokens_OneUsersTokenNeverResolvesToAnother(t *testing.T) {
	st := newStore(t, true)
	ctx := context.Background()
	alice, _ := st.EnsureUser(ctx, "alice")
	bob, _ := st.EnsureUser(ctx, "bob")
	ta, _, _ := st.CreateAgentToken(ctx, alice, "a")
	tb, _, _ := st.CreateAgentToken(ctx, bob, "b")
	if p, _ := st.AuthenticateAgent(ctx, ta); p.UserID != alice {
		t.Errorf("alice's token resolved to %s", p.UserID)
	}
	if p, _ := st.AuthenticateAgent(ctx, tb); p.UserID != bob {
		t.Errorf("bob's token resolved to %s", p.UserID)
	}
}

func TestListAgentTokens(t *testing.T) {
	st := newStore(t, true)
	ctx := context.Background()
	alice, _ := st.EnsureUser(ctx, "alice")
	bob, _ := st.EnsureUser(ctx, "bob")

	_, id1, _ := st.CreateAgentToken(ctx, alice, "first")
	time.Sleep(10 * time.Millisecond)
	plain2, id2, _ := st.CreateAgentToken(ctx, bob, "second")
	st.RevokeAgentToken(ctx, id1)
	st.AuthenticateAgent(ctx, plain2)

	list, err := st.ListAgentTokens(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("got %d tokens", len(list))
	}
	if list[0].ID != id2 || list[1].ID != id1 {
		t.Errorf("not newest first: %s, %s", list[0].ID, list[1].ID)
	}
	if list[0].Username != "bob" || list[0].Name != "second" || list[0].LastUsedAt == nil || list[0].RevokedAt != nil {
		t.Errorf("entry 0 = %+v", list[0])
	}
	if list[1].Username != "alice" || list[1].RevokedAt == nil || list[1].LastUsedAt != nil {
		t.Errorf("entry 1 = %+v", list[1])
	}
	if out := fmt.Sprintf("%+v", list); strings.Contains(out, plain2) {
		t.Error("ListAgentTokens exposes a secret")
	}
}

func TestListAgentTokens_EmptyIsNotAnError(t *testing.T) {
	st := newStore(t, true)
	list, err := st.ListAgentTokens(context.Background())
	if err != nil || len(list) != 0 {
		t.Errorf("got %v, %v", list, err)
	}
}

// ---- schema constraints -----------------------------------------------------

func TestSchemaConstraints(t *testing.T) {
	st := newStore(t, true)
	ctx := context.Background()
	uid, _ := st.EnsureUser(ctx, "alice")

	exec := func(q string, args ...any) error { _, err := st.DB.Exec(q, args...); return err }

	t.Run("usernames must be lower-case and non-empty", func(t *testing.T) {
		if exec(`INSERT INTO users (username) VALUES ('Bob')`) == nil {
			t.Error("upper-case username accepted")
		}
		if exec(`INSERT INTO users (username) VALUES ('')`) == nil {
			t.Error("empty username accepted")
		}
		if exec(`INSERT INTO users (username) VALUES ('alice')`) == nil {
			t.Error("duplicate username accepted")
		}
	})
	t.Run("hostnames must be unique, lower-case and have a valid kind", func(t *testing.T) {
		if err := exec(`INSERT INTO domains (hostname, user_id, kind) VALUES ('a.example.test', $1, 'custom')`, uid); err != nil {
			t.Fatal(err)
		}
		if exec(`INSERT INTO domains (hostname, user_id, kind) VALUES ('a.example.test', $1, 'custom')`, uid) == nil {
			t.Error("duplicate hostname accepted")
		}
		if exec(`INSERT INTO domains (hostname, user_id, kind) VALUES ('B.example.test', $1, 'custom')`, uid) == nil {
			t.Error("upper-case hostname accepted")
		}
		if exec(`INSERT INTO domains (hostname, user_id, kind) VALUES ('c.example.test', $1, 'weird')`, uid) == nil {
			t.Error("unknown kind accepted")
		}
	})
	t.Run("token hashes are unique", func(t *testing.T) {
		if err := exec(`INSERT INTO agent_tokens (user_id, name, token_hash) VALUES ($1, 'a', 'h')`, uid); err != nil {
			t.Fatal(err)
		}
		if exec(`INSERT INTO agent_tokens (user_id, name, token_hash) VALUES ($1, 'b', 'h')`, uid) == nil {
			t.Error("duplicate token hash accepted")
		}
	})
	t.Run("deleting a user removes their tokens and hostnames", func(t *testing.T) {
		if err := exec(`DELETE FROM users WHERE id = $1`, uid); err != nil {
			t.Fatal(err)
		}
		if n := count(t, st, `SELECT count(*) FROM agent_tokens`); n != 0 {
			t.Errorf("%d tokens survived user deletion", n)
		}
		if n := count(t, st, `SELECT count(*) FROM domains`); n != 0 {
			t.Errorf("%d domains survived user deletion", n)
		}
	})
	t.Run("a domain cannot belong to a missing user", func(t *testing.T) {
		if exec(`INSERT INTO domains (hostname, user_id, kind) VALUES ('d.example.test', gen_random_uuid(), 'custom')`) == nil {
			t.Error("orphan domain accepted")
		}
	})
}

func TestAdmins_SetLookupResetDelete(t *testing.T) {
	st := newStore(t, true)
	ctx := context.Background()
	created, err := st.SetAdmin(ctx, " Root ", "hash1")
	if err != nil || !created {
		t.Fatalf("SetAdmin create: created=%v err=%v", created, err)
	}
	a, err := st.AdminByUsername(ctx, "root")
	if err != nil || a.PasswordHash != "hash1" || a.LastLoginAt != nil {
		t.Fatalf("AdminByUsername: %+v %v", a, err)
	}
	if b, err := st.AdminByID(ctx, a.ID); err != nil || b.Username != "root" {
		t.Fatalf("AdminByID: %+v %v", b, err)
	}
	time.Sleep(10 * time.Millisecond)
	created, err = st.SetAdmin(ctx, "root", "hash2")
	if err != nil || created {
		t.Fatalf("SetAdmin reset: created=%v err=%v", created, err)
	}
	b, _ := st.AdminByID(ctx, a.ID)
	if b.PasswordHash != "hash2" || !b.PasswordChangedAt.After(a.PasswordChangedAt) {
		t.Errorf("reset did not update hash and password_changed_at: %+v", b)
	}
	if err := st.TouchAdminLogin(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if list, err := st.ListAdmins(ctx); err != nil || len(list) != 1 || list[0].LastLoginAt == nil {
		t.Errorf("ListAdmins: %+v %v", list, err)
	}
	if err := st.DeleteAdmin(ctx, "root"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AdminByID(ctx, a.ID); !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("deleted admin still found: %v", err)
	}
	if err := st.DeleteAdmin(ctx, "root"); !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
}

func TestUsersAndDomainsListing(t *testing.T) {
	st := newStore(t, true)
	ctx := context.Background()
	uid, _ := st.EnsureUser(ctx, "alice")
	if _, _, err := st.CreateAgentToken(ctx, uid, "laptop"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Claim(ctx, domain.Claim{Hostname: "api.example.com", OwnerID: uid, Kind: "custom", TunnelID: "t1"}); err != nil {
		t.Fatal(err)
	}
	users, err := st.ListUsers(ctx)
	if err != nil || len(users) != 1 || users[0].ActiveTokens != 1 || users[0].Domains != 1 {
		t.Fatalf("ListUsers: %+v %v", users, err)
	}
	doms, err := st.ListDomains(ctx)
	if err != nil || len(doms) != 1 || !doms[0].Online || doms[0].Username != "alice" {
		t.Fatalf("ListDomains: %+v %v", doms, err)
	}
	if err := st.ReleaseDomain(ctx, "api.example.com"); !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("released a hostname with a live tunnel: %v", err)
	}
	if err := st.Release(ctx, "api.example.com", "t1", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.ReleaseDomain(ctx, "api.example.com"); err != nil {
		t.Errorf("ReleaseDomain of a held name: %v", err)
	}
	if err := st.DeleteUser(ctx, uid); err != nil {
		t.Fatal(err)
	}
	if n := count(t, st, `SELECT count(*) FROM agent_tokens`); n != 0 {
		t.Errorf("tokens not cascaded on user delete: %d", n)
	}
}

func TestCaptures_InsertListPurgeDelete(t *testing.T) {
	st := newStore(t, true)
	ctx := context.Background()
	uid, _ := st.EnsureUser(ctx, "alice")
	now := time.Now()
	mk := func(host string, age time.Duration) inspect.Row {
		return inspect.Row{ID: inspect.NewID(), UserID: uid, Hostname: host, Status: 200, CreatedAt: now.Add(-age),
			Nonce: []byte("n"), Ciphertext: []byte("c")}
	}
	rows := []inspect.Row{mk("a.example.com", time.Minute), mk("b.example.com", 2*time.Minute), mk("a.example.com", 48*time.Hour)}
	if err := st.InsertCaptures(ctx, rows); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.ListCaptures(ctx, inspect.Filter{Hostname: "a.example.com"}); len(got) != 2 || got[0].ID != rows[0].ID {
		t.Errorf("list by host, newest first: %+v", got)
	}
	if got, err := st.GetCapture(ctx, rows[1].ID); err != nil || string(got.Ciphertext) != "c" || got.UserID != uid {
		t.Errorf("get: %+v %v", got, err)
	}
	if n, err := st.PurgeCaptures(ctx, now.Add(-24*time.Hour), 1); err != nil || n != 2 {
		t.Errorf("purge by age then count: n=%d err=%v", n, err)
	}
	if got, _ := st.ListCaptures(ctx, inspect.Filter{}); len(got) != 1 || got[0].ID != rows[0].ID {
		t.Errorf("after purge: %+v", got)
	}
	if err := st.DeleteUser(ctx, uid); err != nil {
		t.Fatal(err)
	}
	if n := count(t, st, `SELECT count(*) FROM captured_requests`); n != 0 {
		t.Errorf("captures survived deleting their user: %d", n)
	}
}

func TestUsage_UpsertWindowsAndPurge(t *testing.T) {
	st := newStore(t, true)
	ctx := context.Background()
	uid, _ := st.EnsureUser(ctx, "alice")
	hour := time.Now().UTC().Truncate(time.Hour)
	add := func(h time.Time, req, errs int64) {
		t.Helper()
		if err := st.AddUsage(ctx, []usage.Row{{UserID: uid, Hostname: "a.example.com", Hour: h, Requests: req, Errors: errs, BytesIn: 10, BytesOut: 20}}); err != nil {
			t.Fatal(err)
		}
	}
	add(hour, 3, 1)
	add(hour, 2, 0)                     // same hour: summed
	add(hour.Add(-72*time.Hour), 10, 0) // in the week, not the day
	add(hour.Add(-30*24*time.Hour), 99, 0)

	byHost, err := st.UsageByHost(ctx)
	if err != nil {
		t.Fatal(err)
	}
	w := byHost["a.example.com"]
	if w.Day.Requests != 5 || w.Day.Errors != 1 || w.Day.BytesIn != 20 || w.Week.Requests != 15 {
		t.Errorf("windows: %+v", w)
	}
	if w.Total.Requests != 114 {
		t.Errorf("lifetime total: %+v", w.Total)
	}
	if byUser, _ := st.UsageByUser(ctx); byUser[uid].Week.Requests != 15 || byUser[uid].Total.Requests != 114 {
		t.Errorf("by user: %+v", byUser)
	}
	if n, err := st.PurgeUsage(ctx, hour.Add(-7*24*time.Hour)); err != nil || n != 1 {
		t.Errorf("purge: n=%d err=%v", n, err)
	}
	// Purging hourly rows keeps the daily history and the lifetime total.
	if after, _ := st.UsageByHost(ctx); after["a.example.com"].Total.Requests != 114 {
		t.Errorf("lifetime total changed by the hourly purge: %+v", after["a.example.com"])
	}
	if n := count(t, st, `SELECT count(*) FROM usage_daily`); n != 3 {
		t.Errorf("daily rows: %d, want 3", n)
	}
	// Several hours of one day in one batch are combined, not rejected.
	if err := st.AddUsage(ctx, []usage.Row{
		{UserID: uid, Hostname: "c.example.com", Hour: hour, Requests: 1},
		{UserID: uid, Hostname: "c.example.com", Hour: hour.Add(-time.Hour), Requests: 2},
	}); err != nil {
		t.Fatalf("batch with two hours of one day: %v", err)
	}
	if err := st.DeleteUser(ctx, uid); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"usage_hourly", "usage_daily", "usage_total"} {
		if n := count(t, st, `SELECT count(*) FROM `+table); n != 0 {
			t.Errorf("%s survived deleting the user: %d", table, n)
		}
	}
}
