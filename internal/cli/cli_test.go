package cli_test

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tinoimammp/mancar/internal/version"
)

func TestVersionHelpAndUnknown(t *testing.T) {
	m := newMachine(t, nil)
	if r := m.run("version"); r.code != 0 || strings.TrimSpace(r.stdout) != "mancar "+version.Version {
		t.Errorf("version: %+v", r)
	}
	for _, args := range [][]string{{}, {"help"}, {"--help"}} {
		if r := m.run(args...); r.code != 0 || !strings.Contains(r.stdout, "mancar http") {
			t.Errorf("%v: %+v", args, r)
		}
	}
	if r := m.run("frobnicate"); r.code != 2 || !strings.Contains(r.stderr, `unknown command "frobnicate"`) {
		t.Errorf("%+v", r)
	}
}

func TestUsageErrors(t *testing.T) {
	gw := startGateway(t, "")
	m := newMachine(t, connected(gw))
	port := httpBackend(t, "b")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"http without address", []string{"http"}, "usage: mancar http"},
		{"two addresses", []string{"http", "3000", "4000"}, "usage: mancar http"},
		{"port zero", []string{"http", "0"}, "out of range"},
		{"port too large", []string{"http", "70000"}, "out of range"},
		{"not an address", []string{"http", "abc"}, "not a valid local address"},
		{"bad host:port", []string{"http", "host:99999"}, "invalid port"},
		{"subdomain and random", []string{"http", port, "--subdomain", "my-api", "--random"}, "cannot be combined"},
		{"too short subdomain", []string{"http", port, "--subdomain", "ab"}, "invalid subdomain"},
		{"reserved subdomain", []string{"http", port, "--subdomain", "admin"}, "reserved"},
		{"upper-case junk subdomain", []string{"http", port, "--subdomain", "my_api"}, "invalid subdomain"},
		{"tcp with subdomain", []string{"tcp", port, "--subdomain", "x-y-z"}, "only apply to http"},
		{"tcp with random", []string{"tcp", port, "--random"}, "only apply to http"},
		{"tcp private", []string{"tcp", port, "--private"}, "only apply to http"},
		{"tcp auth", []string{"tcp", port, "--auth", "klien:rahasia123"}, "only apply to http"},
		{"auth and private", []string{"http", port, "--auth", "klien:rahasia123", "--private"}, "cannot be combined"},
		{"short password", []string{"http", port, "--auth", "klien:short"}, "at least 8"},
		{"unknown flag", []string{"http", port, "--bogus"}, "flag provided but not defined"},
	}
	for _, tc := range cases {
		r := m.run(tc.args...)
		if r.code != 2 || !strings.Contains(r.stderr, tc.want) {
			t.Errorf("%s: exit %d, stderr %q; want exit 2 containing %q", tc.name, r.code, r.stderr, tc.want)
		}
		if strings.Contains(r.stdout, "Tunnel established") {
			t.Errorf("%s: a tunnel was started", tc.name)
		}
	}
}

func TestHTTPTunnelWithCustomSubdomain(t *testing.T) {
	gw := startGateway(t, "")
	m := newMachine(t, connected(gw))
	port := httpBackend(t, "app")

	p := m.start("http", port, "--subdomain", "My-API")
	p.waitOut(t, "Status: ONLINE")

	out := p.out.String()
	for _, want := range []string{
		"Checking availability...",
		"SUCCESS: my-api.tunnel.test is available.",
		"Tunnel established.",
		"Forwarding:",
		"http://my-api.tunnel.test\n    -> http://localhost:" + port + "\n",
		"Status: ONLINE\nProtocol: HTTP\nTLS: DISABLED",
		"Press Ctrl+C to stop.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, devToken) || strings.Contains(p.err.String(), devToken) {
		t.Error("the agent token was printed")
	}

	resp, body := gw.get(t, "my-api.tunnel.test", "/hello")
	if resp.StatusCode != 200 || resp.Header.Get("X-Backend") != "app" || !strings.Contains(body, "path=/hello") {
		t.Errorf("public request: %d %q", resp.StatusCode, body)
	}
	if !strings.Contains(body, "host=my-api.tunnel.test") {
		t.Errorf("the local service must see the public Host: %q", body)
	}

	// status reports it while it runs
	st := m.run("status")
	if st.code != 0 || !strings.Contains(st.stdout, fmt.Sprint(p.pid)) || !strings.Contains(st.stdout, "online") ||
		!strings.Contains(st.stdout, "http://my-api.tunnel.test") || !strings.Contains(st.stdout, "localhost:"+port) {
		t.Errorf("status: %+v", st)
	}

	// graceful stop cleans up
	p.cancel()
	if code := p.waitExit(t); code != 0 {
		t.Errorf("exit code %d\n%s", code, p.err)
	}
	if !strings.Contains(p.out.String(), "Shutting down.") {
		t.Errorf("no shutdown message: %s", p.out)
	}
	if files := m.stateFiles(); len(files) != 0 {
		t.Errorf("state files left behind: %v", files)
	}
	if st := m.run("status"); !strings.Contains(st.stdout, "No tunnels are running.") {
		t.Errorf("status after stop: %+v", st)
	}
	eventually(t, "the public URL to go offline", func() bool {
		resp, _ := gw.get(t, "my-api.tunnel.test", "/")
		return resp.StatusCode == http.StatusNotFound
	})
}

func TestHTTPTunnelRandomSubdomain(t *testing.T) {
	gw := startGateway(t, "")
	m := newMachine(t, connected(gw))
	port := httpBackend(t, "app")
	re := regexp.MustCompile(`http://([a-z]+-[a-z]+)\.tunnel\.test\n`)

	for _, args := range [][]string{{"http", port, "--random"}, {"http", port}} { // explicit and default
		p := m.start(args...)
		p.waitOut(t, "Status: ONLINE")
		mm := re.FindStringSubmatch(p.out.String())
		if mm == nil {
			t.Fatalf("%v: no random URL in:\n%s", args, p.out)
		}
		if strings.Contains(p.out.String(), "Checking availability") || strings.Contains(p.out.String(), "SUCCESS:") {
			t.Errorf("%v: random names are not 'checked':\n%s", args, p.out)
		}
		resp, _ := gw.get(t, mm[1]+".tunnel.test", "/")
		if resp.Header.Get("X-Backend") != "app" {
			t.Errorf("%v: random tunnel not serving: %d", args, resp.StatusCode)
		}
		p.cancel()
		p.waitExit(t)
	}
}

func TestAddressForms(t *testing.T) {
	gw := startGateway(t, "")
	m := newMachine(t, connected(gw))
	port := httpBackend(t, "app")
	for i, arg := range []string{"127.0.0.1:" + port, "http://127.0.0.1:" + port, "localhost:" + port} {
		name := fmt.Sprintf("addr-form-%d", i)
		p := m.start("http", arg, "--subdomain", name)
		p.waitOut(t, "Status: ONLINE")
		if resp, _ := gw.get(t, name+".tunnel.test", "/"); resp.Header.Get("X-Backend") != "app" {
			t.Errorf("%q: not serving (%d)", arg, resp.StatusCode)
		}
		p.cancel()
		p.waitExit(t)
	}
}

func TestTakenSubdomainIsRefusedNonInteractively(t *testing.T) {
	gw := startGateway(t, "")
	m := newMachine(t, connected(gw))
	port := httpBackend(t, "app")

	first := m.start("http", port, "--subdomain", "my-api")
	first.waitOut(t, "Status: ONLINE")

	second := m.start("http", port, "--subdomain", "my-api")
	if code := second.waitExit(t); code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, second.err)
	}
	if !strings.Contains(second.err.String(), `"my-api" is not available`) {
		t.Errorf("stderr: %s", second.err)
	}
	if strings.Contains(second.out.String(), "Tunnel established") {
		t.Error("a second tunnel claimed a taken name")
	}
	// the first keeps working
	if resp, _ := gw.get(t, "my-api.tunnel.test", "/"); resp.StatusCode != 200 {
		t.Errorf("first tunnel disturbed: %d", resp.StatusCode)
	}
}

func TestInteractiveMenuAndRetry(t *testing.T) {
	gw := startGateway(t, "")
	m := newMachine(t, connected(gw))
	port := httpBackend(t, "app")

	// Occupy a name, then walk the menu: custom -> taken -> another name.
	holder := m.start("http", port, "--subdomain", "my-api")
	holder.waitOut(t, "Status: ONLINE")

	p := m.startIn("2\nmy-api\nsecond-name\n", true, "http", port)
	p.waitOut(t, "Status: ONLINE")
	out, errOut := p.out.String(), p.err.String()
	for _, want := range []string{"Select your tunnel domain:", "1) Random subdomain", "2) Custom subdomain", "Enter subdomain:", "http://second-name.tunnel.test"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout is missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(errOut, `"my-api" is not available`) {
		t.Errorf("stderr: %s", errOut)
	}
	if resp, _ := gw.get(t, "second-name.tunnel.test", "/"); resp.Header.Get("X-Backend") != "app" {
		t.Errorf("retried tunnel not serving: %d", resp.StatusCode)
	}
}

func TestInteractiveMenuInputHandling(t *testing.T) {
	gw := startGateway(t, "")
	m := newMachine(t, connected(gw))
	port := httpBackend(t, "app")

	t.Run("enter selects random", func(t *testing.T) {
		p := m.startIn("\n", true, "http", port)
		p.waitOut(t, "Status: ONLINE")
		if !regexp.MustCompile(`http://[a-z]+-[a-z]+\.tunnel\.test`).MatchString(p.out.String()) {
			t.Errorf("no random URL:\n%s", p.out)
		}
		p.cancel()
		p.waitExit(t)
	})
	t.Run("bad choice then invalid names then valid", func(t *testing.T) {
		p := m.startIn("x\n2\n\nab\nadmin\nvalid-name\n", true, "http", port)
		p.waitOut(t, "Status: ONLINE")
		out := p.out.String()
		// The earlier subtest left a random name in the history, so the menu
		// now has a third option.
		for _, want := range []string{"Please enter a number from 1 to 3.", "A subdomain is required.", "Try again.", "http://valid-name.tunnel.test"} {
			if !strings.Contains(out, want) {
				t.Errorf("stdout is missing %q:\n%s", want, out)
			}
		}
		p.cancel()
		p.waitExit(t)
	})
	t.Run("end of input aborts cleanly", func(t *testing.T) {
		p := m.startIn("", true, "http", port)
		if code := p.waitExit(t); code != 1 || !strings.Contains(p.err.String(), "no input") {
			t.Errorf("exit %d stderr %q", code, p.err)
		}
	})
	t.Run("flags skip the menu", func(t *testing.T) {
		p := m.startIn("2\n", true, "http", port, "--random")
		p.waitOut(t, "Status: ONLINE")
		if strings.Contains(p.out.String(), "Select your tunnel domain") {
			t.Error("the menu was shown although --random was given")
		}
		p.cancel()
		p.waitExit(t)
	})
}

func TestRecentSubdomainsAreOffered(t *testing.T) {
	gw := startGateway(t, "")
	m := newMachine(t, connected(gw))
	port := httpBackend(t, "app")

	if p := m.startIn("", false, "http", port, "--last"); p.waitExit(t) != 2 || !strings.Contains(p.err.String(), "no subdomain has been used") {
		t.Errorf("--last without history: %q", p.err)
	}
	for _, name := range []string{"first-app", "second-app", "third-app", "fourth-app"} {
		p := m.start("http", port, "--subdomain", name)
		p.waitOut(t, "Status: ONLINE")
		p.cancel()
		p.waitExit(t)
	}

	// The menu offers the three most recent, newest first; choosing one
	// claims that name again.
	p := m.startIn("4\n", true, "http", port)
	p.waitOut(t, "Status: ONLINE")
	out := p.out.String()
	for _, want := range []string{"Recently used:", "3) fourth-app", "4) third-app", "5) second-app", "http://third-app.tunnel.test"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "first-app") {
		t.Errorf("more than three recent names offered:\n%s", out)
	}
	p.cancel()
	p.waitExit(t)

	// --last reuses the most recent one (now third-app) without a menu.
	p = m.startIn("", false, "http", port, "--last")
	p.waitOut(t, "Status: ONLINE")
	if !strings.Contains(p.out.String(), "http://third-app.tunnel.test") || strings.Contains(p.out.String(), "Select your tunnel domain") {
		t.Errorf("--last:\n%s", p.out)
	}
	p.cancel()
	p.waitExit(t)

	if p := m.startIn("", false, "http", port, "--last", "--random"); p.waitExit(t) != 2 {
		t.Error("--last combined with --random accepted")
	}
}

func TestTCPTunnel(t *testing.T) {
	gw := startGateway(t, "")
	m := newMachine(t, connected(gw))
	port := tcpEcho(t)

	p := m.start("tcp", port)
	p.waitOut(t, "Status: ONLINE")
	out := p.out.String()
	mm := regexp.MustCompile(`tcp://tunnel\.test:(\d+)\n    -> tcp://localhost:` + port + `\n`).FindStringSubmatch(out)
	if mm == nil {
		t.Fatalf("unexpected output:\n%s", out)
	}
	if !strings.Contains(out, "Protocol: TCP\nTLS: DISABLED") {
		t.Errorf("output:\n%s", out)
	}

	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+mm[1], 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(conn, "ping-through-the-tunnel\n")
	buf := make([]byte, len("ping-through-the-tunnel\n"))
	if _, err := conn.Read(buf); err != nil || string(buf) != "ping-through-the-tunnel\n" {
		t.Errorf("echo = %q, %v", buf, err)
	}
}

func TestWarnsWhenNothingListensLocally(t *testing.T) {
	gw := startGateway(t, "")
	m := newMachine(t, connected(gw))
	p := m.start("http", "1", "--subdomain", "no-backend")
	p.waitOut(t, "Status: ONLINE") // the tunnel still comes up: the service may start later
	if !strings.Contains(p.err.String(), "nothing is listening on localhost:1") {
		t.Errorf("stderr: %q", p.err)
	}
	resp, body := gw.get(t, "no-backend.tunnel.test", "/")
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "not reachable") {
		t.Errorf("public request with a dead local service: %d %q", resp.StatusCode, body)
	}
}

func TestConnectionProblems(t *testing.T) {
	gw := startGateway(t, "")
	port := httpBackend(t, "app")

	t.Run("no server configured", func(t *testing.T) {
		r := newMachine(t, map[string]string{}).run("http", port)
		if r.code != 2 || !strings.Contains(r.stderr, "no server configured") || !strings.Contains(r.stderr, "mancar config set server") {
			t.Errorf("%+v", r)
		}
	})
	t.Run("no token configured", func(t *testing.T) {
		r := newMachine(t, map[string]string{"MANCAR_SERVER": "https://tunnel.example.com"}).run("http", port)
		if r.code != 2 || !strings.Contains(r.stderr, "no agent token") {
			t.Errorf("%+v", r)
		}
	})
	t.Run("malformed token", func(t *testing.T) {
		v := connected(gw)
		v["MANCAR_TOKEN"] = "not-a-token"
		r := newMachine(t, v).run("http", port)
		if r.code != 2 || !strings.Contains(r.stderr, "malformed") || strings.Contains(r.stderr, "not-a-token") {
			t.Errorf("%+v", r)
		}
	})
	t.Run("token the gateway does not know", func(t *testing.T) {
		v := connected(gw)
		v["MANCAR_TOKEN"] = "mc_" + strings.Repeat("9", 64)
		r := newMachine(t, v).run("http", port)
		if r.code != 1 || !strings.Contains(r.stderr, "rejected the agent token") {
			t.Errorf("%+v", r)
		}
		if strings.Contains(r.stdout+r.stderr, strings.Repeat("9", 64)) {
			t.Error("the token was printed")
		}
	})
	t.Run("plain http to a remote host is refused", func(t *testing.T) {
		r := newMachine(t, map[string]string{"MANCAR_SERVER": "http://tunnel.example.com", "MANCAR_TOKEN": devToken}).run("http", port)
		if r.code != 2 || !strings.Contains(r.stderr, "refusing http://") {
			t.Errorf("%+v", r)
		}
	})
	t.Run("malformed server URLs", func(t *testing.T) {
		for _, s := range []string{"tunnel.example.com", "ftp://x.com", "https://", "https://x.com/path", "https://user:pw@x.com", "https://x.com?q=1"} {
			r := newMachine(t, map[string]string{"MANCAR_SERVER": s, "MANCAR_TOKEN": devToken}).run("http", port)
			if r.code != 2 {
				t.Errorf("server %q: exit %d, want 2 (%s)", s, r.code, r.stderr)
			}
		}
	})
}

func TestSurvivesGatewayRestart(t *testing.T) {
	gw := startGateway(t, "")
	m := newMachine(t, connected(gw))
	port := httpBackend(t, "app")

	p := m.start("http", port, "--subdomain", "my-api")
	p.waitOut(t, "Status: ONLINE")

	addr := gw.addr
	t0 := time.Now()
	gw.stop()
	t.Logf("gateway stopped after %v", time.Since(t0))
	p.waitOut(t, "Status: RECONNECTING")
	t.Logf("agent noticed after %v", time.Since(t0))
	if st := m.run("status"); !strings.Contains(st.stdout, "reconnecting") {
		t.Errorf("status while reconnecting: %s", st.stdout)
	}

	gw2 := startGateway(t, addr) // same address: the agent reconnects by itself
	p.waitOut(t, "Status: ONLINE (reconnected)")
	t.Logf("agent back online after %v", time.Since(t0))
	if resp, _ := gw2.get(t, "my-api.tunnel.test", "/"); resp.Header.Get("X-Backend") != "app" {
		t.Errorf("tunnel not restored: %d", resp.StatusCode)
	}
	p.cancel()
	if code := p.waitExit(t); code != 0 {
		t.Errorf("exit %d", code)
	}
}

func TestStartSavedTunnels(t *testing.T) {
	gw := startGateway(t, "")
	m := newMachine(t, connected(gw))
	web, db := httpBackend(t, "web"), tcpEcho(t)

	for _, args := range [][]string{
		{"config", "add-tunnel", "web", "http", web, "--subdomain", "web-app"},
		{"config", "add-tunnel", "db", "tcp", db},
	} {
		if r := m.run(args...); r.code != 0 {
			t.Fatalf("%v: %+v", args, r)
		}
	}

	t.Run("all", func(t *testing.T) {
		p := m.start("start")
		p.waitOut(t, "Status: ONLINE")
		out := p.out.String()
		for _, want := range []string{
			"Tunnels established.",
			"http://web-app.tunnel.test\n    -> http://localhost:" + web + "\n    Protocol: HTTP   TLS: DISABLED",
			"    -> tcp://localhost:" + db + "\n    Protocol: TCP   TLS: DISABLED",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("output is missing %q:\n%s", want, out)
			}
		}
		if resp, _ := gw.get(t, "web-app.tunnel.test", "/"); resp.Header.Get("X-Backend") != "web" {
			t.Errorf("web tunnel: %d", resp.StatusCode)
		}
		p.cancel()
		p.waitExit(t)
	})
	t.Run("subset by name", func(t *testing.T) {
		p := m.start("start", "db")
		p.waitOut(t, "Status: ONLINE")
		if strings.Contains(p.out.String(), "web-app") || !strings.Contains(p.out.String(), "tcp://") {
			t.Errorf("output:\n%s", p.out)
		}
		p.cancel()
		p.waitExit(t)
	})
	t.Run("unknown name", func(t *testing.T) {
		if r := m.run("start", "nope"); r.code != 2 || !strings.Contains(r.stderr, `no saved tunnel named "nope"`) {
			t.Errorf("%+v", r)
		}
	})
	t.Run("nothing saved", func(t *testing.T) {
		r := newMachine(t, connected(gw)).run("start")
		if r.code != 2 || !strings.Contains(r.stderr, "no tunnels saved") {
			t.Errorf("%+v", r)
		}
	})
}
