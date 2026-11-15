package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func (m *machine) configFile() string { return filepath.Join(m.cfgDir, "config.json") }

func TestConfigShowOnEmptyMachine(t *testing.T) {
	m := newMachine(t, nil)
	r := m.run("config")
	if r.code != 0 {
		t.Fatalf("%+v", r)
	}
	for _, want := range []string{"Server:      (not set)", "Token:       (not set)", "Tunnels:     (none)", m.configFile()} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output is missing %q:\n%s", want, r.stdout)
		}
	}
	if _, err := os.Stat(m.cfgDir); !os.IsNotExist(err) {
		t.Error("merely showing the config must not create files")
	}
	if p := m.run("config", "path"); strings.TrimSpace(p.stdout) != m.configFile() {
		t.Errorf("config path = %q", p.stdout)
	}
}

func TestConfigSetServer(t *testing.T) {
	m := newMachine(t, nil)
	if r := m.run("config", "set", "server", "https://Tunnel.Example.COM/"); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	if r := m.run("config"); !strings.Contains(r.stdout, "Server:      https://tunnel.example.com\n") {
		t.Errorf("show:\n%s", r.stdout)
	}

	for _, bad := range []string{"tunnel.example.com", "ftp://x.com", "https://", "https://x.com/path", "https://u:p@x.com", "https://x.com?a=b", "http://tunnel.example.com"} {
		r := m.run("config", "set", "server", bad)
		if r.code != 2 {
			t.Errorf("server %q accepted (exit %d)", bad, r.code)
		}
	}
	// the failed attempts did not clobber the saved value
	if r := m.run("config"); !strings.Contains(r.stdout, "https://tunnel.example.com") {
		t.Errorf("a rejected value overwrote the config:\n%s", r.stdout)
	}

	// plain http is allowed for loopback and when explicitly opted in
	if r := m.run("config", "set", "server", "http://localhost:8080"); r.code != 0 {
		t.Errorf("loopback http rejected: %+v", r)
	}
	opt := newMachine(t, map[string]string{"MANCAR_ALLOW_INSECURE": "1"})
	if r := opt.run("config", "set", "server", "http://tunnel.example.com"); r.code != 0 {
		t.Errorf("explicit insecure opt-in rejected: %+v", r)
	}
}

func TestConfigSetToken(t *testing.T) {
	m := newMachine(t, nil)

	r := m.run("config", "set", "token", devToken)
	if r.code != 0 || strings.Contains(r.stdout+r.stderr, devToken) {
		t.Fatalf("set token: %+v", r)
	}
	show := m.run("config")
	if strings.Contains(show.stdout, devToken) || strings.Contains(show.stdout, devToken[6:]) {
		t.Errorf("config show prints the token:\n%s", show.stdout)
	}
	if !strings.Contains(show.stdout, "Token:       mc_012…") {
		t.Errorf("token should be masked:\n%s", show.stdout)
	}

	// from stdin, so it never reaches shell history or the process list
	m2 := newMachine(t, nil)
	if r := m2.runIn(devToken+"\n", false, "config", "set", "token", "-"); r.code != 0 {
		t.Fatalf("stdin token: %+v", r)
	}
	if b, _ := os.ReadFile(m2.configFile()); !strings.Contains(string(b), devToken) {
		t.Error("the token read from stdin was not saved")
	}

	for _, bad := range []string{"", "short", "mc_" + strings.Repeat("a", 63), "xx_" + strings.Repeat("a", 64)} {
		r := m.runIn(bad, false, "config", "set", "token", "-")
		if r.code != 2 {
			t.Errorf("token %q accepted (exit %d)", bad, r.code)
		}
		if bad != "" && strings.Contains(r.stdout+r.stderr, bad) {
			t.Errorf("a rejected token was echoed: %q", bad)
		}
	}
}

func TestConfigFileIsPrivateAndAtomic(t *testing.T) {
	skipIfWindows(t)
	m := newMachine(t, nil)
	m.run("config", "set", "token", devToken)
	m.run("config", "set", "server", "https://tunnel.example.com")
	if mode := fileMode(t, m.configFile()); mode != 0o600 {
		t.Errorf("config.json mode = %v, want 0600 (it holds the token)", mode)
	}
	if mode := fileMode(t, m.cfgDir); mode != 0o700 {
		t.Errorf("config dir mode = %v, want 0700", mode)
	}
	entries, _ := os.ReadDir(m.cfgDir)
	for _, e := range entries {
		if e.Name() != "config.json" {
			t.Errorf("stray file after saving: %s", e.Name())
		}
	}
}

func TestConfigUsageErrors(t *testing.T) {
	m := newMachine(t, nil)
	for _, args := range [][]string{
		{"config", "set"}, {"config", "set", "server"}, {"config", "set", "colour", "red"},
		{"config", "set", "token", "a", "b"}, {"config", "unset"}, {"config", "unset", "tunnels"},
		{"config", "frobnicate"}, {"config", "add-tunnel"}, {"config", "rm-tunnel"},
	} {
		if r := m.run(args...); r.code != 2 {
			t.Errorf("%v: exit %d, want 2 (%s)", args, r.code, r.stderr)
		}
	}
}

func TestConfigUnset(t *testing.T) {
	m := newMachine(t, nil)
	m.run("config", "set", "server", "https://tunnel.example.com")
	m.run("config", "set", "token", devToken)
	if r := m.run("config", "unset", "token"); r.code != 0 {
		t.Fatal(r)
	}
	show := m.run("config").stdout
	if !strings.Contains(show, "Token:       (not set)") || !strings.Contains(show, "tunnel.example.com") {
		t.Errorf("after unset token:\n%s", show)
	}
	if b, _ := os.ReadFile(m.configFile()); strings.Contains(string(b), devToken) {
		t.Error("the token is still on disk after unset")
	}
	m.run("config", "unset", "server")
	if show := m.run("config").stdout; !strings.Contains(show, "Server:      (not set)") {
		t.Errorf("after unset server:\n%s", show)
	}
}

func TestConfigTunnels(t *testing.T) {
	m := newMachine(t, nil)

	if r := m.run("config", "add-tunnel", "Web", "http", "3000", "--subdomain", "My-App"); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	if r := m.run("config", "add-tunnel", "db", "tcp", "127.0.0.1:5432"); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	show := m.run("config").stdout
	for _, want := range []string{"web: http localhost:3000 subdomain=my-app", "db: tcp 127.0.0.1:5432"} {
		if !strings.Contains(show, want) {
			t.Errorf("show is missing %q:\n%s", want, show)
		}
	}

	bad := []struct {
		args []string
		want string
	}{
		{[]string{"Bad Name", "http", "3000"}, "must be 1-32 characters"},
		{[]string{"x", "udp", "3000"}, "http or tcp"},
		{[]string{"x", "http", "nope"}, "not a valid local address"},
		{[]string{"x", "tcp", "3000", "--subdomain", "abc-def"}, "only applies to http"},
		{[]string{"x", "http", "3000", "--subdomain", "ab"}, "3-63"},
		{[]string{"web", "http", "4000"}, "already exists"},
	}
	for _, tc := range bad {
		r := m.run(append([]string{"config", "add-tunnel"}, tc.args...)...)
		if r.code != 2 || !strings.Contains(r.stderr, tc.want) {
			t.Errorf("%v: exit %d stderr %q, want exit 2 containing %q", tc.args, r.code, r.stderr, tc.want)
		}
	}

	if r := m.run("config", "rm-tunnel", "WEB"); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	if show := m.run("config").stdout; strings.Contains(show, "web:") || !strings.Contains(show, "db:") {
		t.Errorf("after rm-tunnel:\n%s", show)
	}
	if r := m.run("config", "rm-tunnel", "ghost"); r.code != 1 || !strings.Contains(r.stderr, `no tunnel named "ghost"`) {
		t.Errorf("%+v", r)
	}
}

func TestCorruptConfigIsReportedAndNeverOverwritten(t *testing.T) {
	m := newMachine(t, nil)
	os.MkdirAll(m.cfgDir, 0o700)
	const garbage = "{ this is not json"
	os.WriteFile(m.configFile(), []byte(garbage), 0o600)

	for _, args := range [][]string{
		{"config"}, {"config", "set", "server", "https://tunnel.example.com"},
		{"config", "add-tunnel", "web", "http", "3000"}, {"start"}, {"http", "3000"},
	} {
		r := m.run(args...)
		if r.code != 1 || !strings.Contains(r.stderr, "not valid JSON") {
			t.Errorf("%v: exit %d stderr %q", args, r.code, r.stderr)
		}
	}
	if b, _ := os.ReadFile(m.configFile()); string(b) != garbage {
		t.Errorf("the damaged file was modified: %q", b)
	}
}

func TestEnvironmentOverridesTheConfigFile(t *testing.T) {
	m := newMachine(t, map[string]string{"MANCAR_SERVER": "https://from-env.example.com"})
	m.run("config", "set", "server", "https://from-file.example.com")
	if show := m.run("config").stdout; !strings.Contains(show, "from-env.example.com") || strings.Contains(show, "from-file") {
		t.Errorf("env must win:\n%s", show)
	}
}

func TestSavedConfigIsUsedWithoutEnvironment(t *testing.T) {
	gw := startGateway(t, "")
	// Only the test-only dial override is in the environment; server and
	// token come from the saved config file.
	m := newMachine(t, map[string]string{"MANCAR_DIAL_ADDR": gw.addr})
	if r := m.run("config", "set", "server", "http://"+baseDomain); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	if r := m.runIn(devToken+"\n", false, "config", "set", "token", "-"); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	p := m.start("http", httpBackend(t, "app"), "--subdomain", "from-config")
	p.waitOut(t, "http://from-config.tunnel.test")
	if resp, _ := gw.get(t, "from-config.tunnel.test", "/"); resp.Header.Get("X-Backend") != "app" {
		t.Errorf("not serving: %d", resp.StatusCode)
	}
}
