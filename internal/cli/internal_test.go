package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/tinoimammp/mancar/internal/agent"
	"github.com/tinoimammp/mancar/internal/protocol"
)

func TestParseLocalAddr(t *testing.T) {
	good := map[string]string{
		"3000":                    "localhost:3000",
		" 8080 ":                  "localhost:8080",
		"1":                       "localhost:1",
		"65535":                   "localhost:65535",
		"127.0.0.1:3000":          "127.0.0.1:3000",
		"myhost:80":               "myhost:80",
		"[::1]:3000":              "[::1]:3000",
		"http://localhost:3000":   "localhost:3000",
		"http://localhost:3000/x": "localhost:3000",
		"http://app.local":        "app.local:80",
		"https://app.local":       "app.local:443",
		"tcp://db.local:5432":     "db.local:5432",
	}
	for in, want := range good {
		got, err := parseLocalAddr(in)
		if err != nil || got != want {
			t.Errorf("parseLocalAddr(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{"", "  ", "0", "65536", "-1", "abc", "host", "host:", ":3000", "host:0", "host:99999", "host:abc",
		"a b:80", "tcp://db.local", "http://", "ftp//x:1", "host/path:80"}
	for _, in := range bad {
		if got, err := parseLocalAddr(in); err == nil {
			t.Errorf("parseLocalAddr(%q) = %q, want an error", in, got)
		}
	}
}

func TestCheckSubdomain(t *testing.T) {
	if got, err := checkSubdomain("  My-API "); err != nil || got != "my-api" {
		t.Errorf("got %q, %v", got, err)
	}
	for _, bad := range []string{"", "ab", "admin", "my_api", "a--b", strings.Repeat("a", 64)} {
		if _, err := checkSubdomain(bad); err == nil {
			t.Errorf("checkSubdomain(%q) accepted", bad)
		}
	}
	if _, err := checkSubdomain("ab"); err != nil && strings.HasPrefix(err.Error(), "domain:") {
		t.Errorf("internal package prefix leaked to users: %v", err)
	}
}

func TestMaskToken(t *testing.T) {
	tok := "mc_" + strings.Repeat("a", 64)
	got := maskToken(tok)
	if strings.Contains(got, strings.Repeat("a", 8)) || !strings.HasPrefix(got, "mc_aaa") {
		t.Errorf("maskToken = %q", got)
	}
	if maskToken("") != "(not set)" || maskToken("short") != "********" {
		t.Errorf("edge cases: %q %q", maskToken(""), maskToken("short"))
	}
}

func TestOneLine(t *testing.T) {
	if got := oneLine("a\n  b\t\tc\r\n"); got != "a b c" {
		t.Errorf("got %q", got)
	}
	if got := oneLine(strings.Repeat("x", 500)); len(got) != 160 || !strings.HasSuffix(got, "...") {
		t.Errorf("long input: len %d", len(got))
	}
}

func TestResolvePrecedenceAndValidation(t *testing.T) {
	tok := "mc_" + strings.Repeat("a", 64)
	other := "mc_" + strings.Repeat("b", 64)
	env := func(m map[string]string) Env {
		return Env{Getenv: func(k string) string { return m[k] }}
	}
	fc := fileConfig{Server: "https://file.example.com", Token: tok}

	s, err := env(nil).resolve("", fc)
	if err != nil || s.server != "https://file.example.com" || s.token != tok {
		t.Fatalf("file only: %+v %v", s, err)
	}
	s, _ = env(map[string]string{"MANCAR_SERVER": "https://env.example.com", "MANCAR_TOKEN": other}).resolve("", fc)
	if s.server != "https://env.example.com" || s.token != other {
		t.Errorf("env should beat the file: %+v", s)
	}
	s, _ = env(map[string]string{"MANCAR_SERVER": "https://env.example.com"}).resolve("https://flag.example.com", fc)
	if s.server != "https://flag.example.com" {
		t.Errorf("flag should beat env: %+v", s)
	}
	if _, err := env(nil).resolve("", fileConfig{Token: tok}); err == nil || !strings.Contains(err.Error(), "no server") {
		t.Errorf("missing server: %v", err)
	}
	if _, err := env(nil).resolve("", fileConfig{Server: "https://x.example.com"}); err == nil || !strings.Contains(err.Error(), "no agent token") {
		t.Errorf("missing token: %v", err)
	}
}

func TestCheckServerURLLoopbackAndDial(t *testing.T) {
	e := Env{Getenv: func(string) string { return "" }}
	for _, ok := range []string{"http://localhost:8080", "http://127.0.0.1", "http://[::1]:80", "https://x.example.com"} {
		if _, err := e.checkServerURL(ok, ""); err != nil {
			t.Errorf("%s rejected: %v", ok, err)
		}
	}
	if _, err := e.checkServerURL("http://tunnel.example.com", ""); err == nil {
		t.Error("plain http to a remote host accepted")
	}
	if _, err := e.checkServerURL("http://tunnel.example.com", "127.0.0.1:9000"); err != nil {
		t.Errorf("http with a loopback dial address rejected: %v", err)
	}
	if _, err := e.checkServerURL("http://tunnel.example.com", "10.0.0.5:9000"); err == nil {
		t.Error("http with a non-loopback dial address accepted")
	}
}

func status(proto, public, local, sub string) agent.TunnelStatus {
	return agent.TunnelStatus{
		Spec:       agent.TunnelSpec{Proto: proto, LocalAddr: local, Subdomain: sub},
		Registered: protocol.Registered{Proto: proto, PublicURL: public},
	}
}

// The expected text is the example from the project specification.
func TestPrintOnlineMatchesTheSpecification(t *testing.T) {
	var b bytes.Buffer
	printOnline(&b, []agent.TunnelStatus{status("http", "https://blue-falcon.mydomain.com", "localhost:3000", "")}, true)
	want := "Tunnel established.\n\n" +
		"Forwarding:\n" +
		"https://blue-falcon.mydomain.com\n" +
		"    -> http://localhost:3000\n\n" +
		"Status: ONLINE\n" +
		"Protocol: HTTP\n" +
		"TLS: ENABLED\n\n" +
		"Press Ctrl+C to stop.\n"
	if b.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}

func TestPrintOnlineVariants(t *testing.T) {
	var b bytes.Buffer
	ts := status("http", "https://my-api.mydomain.com", "localhost:3000", "my-api")
	ts.Registered.Hostname = "my-api.mydomain.com"
	printOnline(&b, []agent.TunnelStatus{ts}, true)
	if !strings.HasPrefix(b.String(), "SUCCESS: my-api.mydomain.com is available.\n\nTunnel established.") {
		t.Errorf("custom subdomain:\n%s", b.String())
	}

	b.Reset()
	printOnline(&b, []agent.TunnelStatus{ts}, false)
	if strings.Contains(b.String(), "SUCCESS:") {
		t.Errorf("a re-announcement must not repeat the availability line:\n%s", b.String())
	}

	b.Reset()
	printOnline(&b, []agent.TunnelStatus{status("tcp", "tcp://mydomain.com:20001", "localhost:5432", "")}, true)
	if !strings.Contains(b.String(), "    -> tcp://localhost:5432") || !strings.Contains(b.String(), "Protocol: TCP\nTLS: DISABLED") {
		t.Errorf("tcp:\n%s", b.String())
	}

	b.Reset()
	printOnline(&b, []agent.TunnelStatus{
		status("http", "https://a.mydomain.com", "localhost:3000", ""),
		status("tcp", "tcp://mydomain.com:20001", "localhost:5432", ""),
	}, true)
	for _, want := range []string{"Tunnels established.", "Protocol: HTTP   TLS: ENABLED", "Protocol: TCP   TLS: DISABLED", "Status: ONLINE\n"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("multi is missing %q:\n%s", want, b.String())
		}
	}
	if strings.Contains(b.String(), "Status: ONLINE\nProtocol:") {
		t.Errorf("multi-tunnel output must not use the single-tunnel footer:\n%s", b.String())
	}
}

func TestRendererStateMachine(t *testing.T) {
	var b bytes.Buffer
	r := &renderer{out: &b, server: "https://gw.example.com"}
	online := agent.Status{State: agent.StateOnline, Tunnels: []agent.TunnelStatus{status("http", "https://a.example.com", "localhost:1", "")}}

	r.onStatus(agent.Status{State: agent.StateConnecting})
	r.onStatus(agent.Status{State: agent.StateConnecting})
	if got := strings.Count(b.String(), "Connecting to https://gw.example.com"); got != 1 {
		t.Errorf("connecting printed %d times", got)
	}

	r.onStatus(online)
	if !strings.Contains(b.String(), "Tunnel established.") {
		t.Fatalf("no announcement:\n%s", b.String())
	}

	// repeated identical failures are printed once
	b.Reset()
	down := agent.Status{State: agent.StateReconnecting, Err: errors.New("dial tcp: connection\nrefused")}
	r.onStatus(down)
	r.onStatus(down)
	r.onStatus(down)
	if got := strings.Count(b.String(), "Status: RECONNECTING (dial tcp: connection refused)"); got != 1 || strings.Count(b.String(), "\n") != 1 {
		t.Errorf("reconnect lines:\n%s", b.String())
	}

	// same address after reconnect: one short line
	b.Reset()
	r.onStatus(online)
	if b.String() != "Status: ONLINE (reconnected)\n" {
		t.Errorf("same-URL reconnect printed:\n%s", b.String())
	}

	// a different address after reconnect is announced in full
	b.Reset()
	moved := agent.Status{State: agent.StateOnline, Tunnels: []agent.TunnelStatus{status("http", "https://b.example.com", "localhost:1", "")}}
	r.onStatus(moved)
	if !strings.Contains(b.String(), "https://b.example.com") || !strings.Contains(b.String(), "Tunnel established.") {
		t.Errorf("new address not announced:\n%s", b.String())
	}
}
