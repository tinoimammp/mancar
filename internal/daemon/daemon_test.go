package daemon_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/tinoimammp/mancar/internal/auth"
	"github.com/tinoimammp/mancar/internal/version"
)

func TestVersionAndHelp(t *testing.T) {
	if r := run(t, nil, "version"); r.code != 0 || strings.TrimSpace(r.stdout) != "mancard "+version.Version {
		t.Errorf("version: %+v", r)
	}
	for _, a := range []string{"help", "--help", "-h"} {
		if r := run(t, nil, a); r.code != 0 || !strings.Contains(r.stdout, "mancard serve") && !strings.Contains(r.stdout, "Usage:") {
			t.Errorf("%s: %+v", a, r)
		}
	}
}

func TestUnknownCommandIsAUsageError(t *testing.T) {
	r := run(t, nil, "frobnicate")
	if r.code != 2 || !strings.Contains(r.stderr, `unknown command "frobnicate"`) || !strings.Contains(r.stderr, "Usage:") {
		t.Errorf("%+v", r)
	}
}

func TestTokenUsageErrors(t *testing.T) {
	for _, args := range [][]string{{"token"}, {"token", "bogus"}} {
		if r := run(t, devVars(), args...); r.code != 2 {
			t.Errorf("%v: exit %d, want 2 (%s)", args, r.code, r.stderr)
		}
	}
}

func TestTokenGenerateNeedsNoConfiguration(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		r := run(t, map[string]string{}, "token", "generate")
		tok := strings.TrimSpace(r.stdout)
		if r.code != 0 || !auth.WellFormed(tok) || strings.Count(r.stdout, "\n") != 1 {
			t.Fatalf("%+v", r)
		}
		if seen[tok] {
			t.Fatal("duplicate token")
		}
		seen[tok] = true
	}
}

func TestInvalidConfigurationExitsWithTwoAndNamesEveryProblem(t *testing.T) {
	for _, cmd := range [][]string{{"serve"}, {"migrate"}, {"healthcheck"}, {"token", "list"}, {}} {
		r := run(t, map[string]string{}, cmd...)
		if r.code != 2 {
			t.Errorf("%v: exit %d, want 2", cmd, r.code)
		}
		for _, name := range []string{"BASE_DOMAIN", "POSTGRES_PASSWORD", "JWT_SECRET", "ENCRYPTION_KEY"} {
			if !strings.Contains(r.stderr, name) {
				t.Errorf("%v: stderr should mention %s: %s", cmd, name, r.stderr)
			}
		}
		if r.stdout != "" {
			t.Errorf("%v: nothing may be written to stdout on a config error: %q", cmd, r.stdout)
		}
	}
}

func TestConfigErrorsNeverEchoSecretValues(t *testing.T) {
	vars := with(devVars(), "JWT_SECRET", "my-very-secret-but-short", "ENCRYPTION_KEY", "my-secret-key-not-hex")
	r := run(t, vars, "serve")
	if r.code != 2 {
		t.Fatalf("exit %d", r.code)
	}
	for _, secret := range []string{"my-very-secret-but-short", "my-secret-key-not-hex"} {
		if strings.Contains(r.stderr, secret) {
			t.Errorf("stderr leaks %q: %s", secret, r.stderr)
		}
	}
}

func TestPostgresCommandsRefuseMemoryStorage(t *testing.T) {
	for _, cmd := range [][]string{{"migrate"}, {"token", "list"}, {"token", "create", "--user", "alice"}} {
		r := run(t, devVars(), cmd...)
		if r.code != 1 || !strings.Contains(r.stderr, "STORAGE=postgres") {
			t.Errorf("%v: %+v", cmd, r)
		}
	}
}

func TestTokenCreateValidatesUsername(t *testing.T) {
	for _, bad := range []string{"", "Bad User!", "-x", strings.Repeat("a", 65), "a/b", "名前"} {
		r := run(t, devVars(), "token", "create", "--user", bad)
		if r.code != 2 {
			t.Errorf("--user %q: exit %d, want 2 (%s)", bad, r.code, r.stderr)
		}
	}
}

func TestServe_MemoryModeServesAndStopsGracefully(t *testing.T) {
	r := serve(t, devVars())

	req, _ := http.NewRequest("GET", "http://"+r.addr+"/healthz", nil)
	req.Host = "tunnel.test"
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("healthz: %v %v", resp, err)
	}
	resp.Body.Close()

	if !strings.Contains(r.stdout.String(), "gateway listening") {
		t.Errorf("startup was not logged: %s", r.stdout)
	}
	if !strings.Contains(r.stdout.String(), "in-memory storage") {
		t.Errorf("memory mode must warn loudly: %s", r.stdout)
	}

	r.cancel()
	if code := r.wait(t); code != 0 {
		t.Errorf("exit code %d after graceful shutdown\n%s", code, r.stdout)
	}
	if !strings.Contains(r.stdout.String(), "shutting down") {
		t.Errorf("shutdown was not logged: %s", r.stdout)
	}
}

func TestServe_MemoryModePrintsATokenThatWorksAndKeepsItOutOfLogs(t *testing.T) {
	r := serve(t, devVars())

	var tok string
	for _, f := range strings.Fields(r.stderr.String()) {
		if auth.WellFormed(f) {
			tok = f
		}
	}
	if tok == "" {
		t.Fatalf("no development token announced on stderr: %q", r.stderr)
	}
	if strings.Contains(r.stdout.String(), tok) {
		t.Error("the token was written to the service log")
	}
	if got := upgradeStatus(t, r.addr, "tunnel.test", tok); got != http.StatusSwitchingProtocols {
		t.Errorf("announced token rejected: %d", got)
	}
	if got := upgradeStatus(t, r.addr, "tunnel.test", "mc_"+strings.Repeat("0", 64)); got != http.StatusUnauthorized {
		t.Errorf("unknown token: %d, want 401", got)
	}
}

func TestServe_UsesConfiguredDevAgentToken(t *testing.T) {
	tok := "mc_" + strings.Repeat("c", 64)
	r := serve(t, with(devVars(), "DEV_AGENT_TOKEN", tok))
	if strings.Contains(r.stderr.String(), "development agent token") || strings.Contains(r.stderr.String(), tok) {
		t.Errorf("a configured token must not be echoed: %q", r.stderr)
	}
	if got := upgradeStatus(t, r.addr, "tunnel.test", tok); got != http.StatusSwitchingProtocols {
		t.Errorf("configured token rejected: %d", got)
	}
}

func TestHealthcheck(t *testing.T) {
	r := serve(t, devVars())
	hc := run(t, with(devVars(), "LISTEN_ADDR", r.addr), "healthcheck")
	if hc.code != 0 || !strings.Contains(hc.stdout, "healthy") {
		t.Errorf("healthy server: %+v", hc)
	}

	// Wildcard listen addresses are probed on loopback.
	_, port, _ := strings.Cut(r.addr, ":")
	hc = run(t, with(devVars(), "LISTEN_ADDR", ":"+port), "healthcheck")
	if hc.code != 0 {
		t.Errorf("wildcard listen address: %+v", hc)
	}

	r.cancel()
	r.wait(t)
	hc = run(t, with(devVars(), "LISTEN_ADDR", r.addr), "healthcheck")
	if hc.code != 1 || !strings.Contains(hc.stderr, "unhealthy") {
		t.Errorf("stopped server must be unhealthy: %+v", hc)
	}
}

func TestHealthcheck_WrongServiceOnThePortIsUnhealthy(t *testing.T) {
	r := serve(t, devVars())
	// Same port, but a Host the router does not serve: /healthz must not be
	// reachable, so the check fails instead of reporting a false positive.
	hc := run(t, with(devVars(), "LISTEN_ADDR", r.addr, "BASE_DOMAIN", "other.test"), "healthcheck")
	if hc.code != 1 {
		t.Errorf("%+v", hc)
	}
}
