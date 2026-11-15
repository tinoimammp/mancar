package daemon_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/tinoimammp/mancar/internal/auth"
)

// firstTokenID returns the ID column of the first data row of `token list`.
func firstTokenID(t *testing.T, list string) string {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(list), "\n")
	if len(lines) < 2 {
		t.Fatalf("no token rows in:\n%s", list)
	}
	return strings.Fields(lines[1])[0]
}

func TestPostgres_MigrateTokenAdministrationAndServe(t *testing.T) {
	vars := prodVars(schemaURL(t))

	// migrate is idempotent
	for i := 0; i < 2; i++ {
		if r := run(t, vars, "migrate"); r.code != 0 || !strings.Contains(r.stdout, "up to date") {
			t.Fatalf("migrate #%d: %+v", i+1, r)
		}
	}

	// create: the secret alone on stdout, the explanation on stderr
	r := run(t, vars, "token", "create", "--user", "Alice", "--name", "laptop")
	tok := strings.TrimSpace(r.stdout)
	if r.code != 0 || !auth.WellFormed(tok) || strings.Count(r.stdout, "\n") != 1 {
		t.Fatalf("create: %+v", r)
	}
	if !strings.Contains(r.stderr, `"alice"`) || strings.Contains(r.stderr, tok) {
		t.Errorf("create stderr = %q (must name the user, never repeat the token)", r.stderr)
	}

	// list: no secrets, shows the owner and state
	list := run(t, vars, "token", "list")
	if list.code != 0 || !strings.Contains(list.stdout, "alice") || !strings.Contains(list.stdout, "laptop") ||
		!strings.Contains(list.stdout, "active") || strings.Contains(list.stdout, tok) {
		t.Fatalf("list: %+v", list)
	}
	id := firstTokenID(t, list.stdout)

	// the real server, started on the same database, honours the token
	srv := serve(t, vars)
	if got := upgradeStatus(t, srv.addr, "tunnel.test", tok); got != http.StatusSwitchingProtocols {
		t.Errorf("fresh token: %d, want 101", got)
	}

	// revoke takes effect immediately, without restarting the server
	if r := run(t, vars, "token", "revoke", id); r.code != 0 {
		t.Fatalf("revoke: %+v", r)
	}
	if got := upgradeStatus(t, srv.addr, "tunnel.test", tok); got != http.StatusUnauthorized {
		t.Errorf("revoked token: %d, want 401", got)
	}
	if l := run(t, vars, "token", "list"); !strings.Contains(l.stdout, "revoked") {
		t.Errorf("list after revoke: %s", l.stdout)
	}

	// revoking again, or an unknown ID, is a clear failure; missing arg is a usage error
	for _, id := range []string{id, "not-a-uuid", "00000000-0000-0000-0000-000000000000"} {
		if r := run(t, vars, "token", "revoke", id); r.code != 1 || !strings.Contains(r.stderr, "no active token") {
			t.Errorf("revoke %q: %+v", id, r)
		}
	}
	if r := run(t, vars, "token", "revoke"); r.code != 2 {
		t.Errorf("revoke without ID: %+v", r)
	}
}

func TestPostgres_ProductionLogsAreJSONAndContainNoSecrets(t *testing.T) {
	dsn := schemaURL(t)
	vars := prodVars(dsn)
	srv := serve(t, vars)
	srv.cancel()
	srv.wait(t)

	out := srv.stdout.String()
	if !strings.Contains(out, `"msg":"gateway listening"`) {
		t.Errorf("production logs must be JSON lines:\n%s", out)
	}
	for _, secret := range []string{vars["JWT_SECRET"], vars["ENCRYPTION_KEY"], dsn, "testpw"} {
		if strings.Contains(out, secret) || strings.Contains(srv.stderr.String(), secret) {
			t.Errorf("output leaks a secret: %q", secret)
		}
	}
}

func TestPostgres_ServeFailsClearlyWhenTheDatabaseIsUnreachable(t *testing.T) {
	vars := prodVars("postgres://u:topsecret@127.0.0.1:1/db?sslmode=disable&connect_timeout=1")
	// "serve" and "migrate" share this error path; run() bounds the wait.
	r := run(t, vars, "migrate")
	if r.code != 1 || !strings.Contains(r.stderr, "not reachable") {
		t.Fatalf("%+v", r)
	}
	if strings.Contains(r.stderr, "topsecret") {
		t.Errorf("the database password leaked: %s", r.stderr)
	}
}
