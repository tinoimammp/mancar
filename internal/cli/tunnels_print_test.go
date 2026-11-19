package cli

import "testing"

func TestPrintableStripsTerminalEscapes(t *testing.T) {
	for in, want := range map[string]string{
		"/api/items?x=1":        "/api/items?x=1",
		"/\x1b]0;pwned\x07":     "/?]0;pwned?",
		"/\x1b[2J\x1b[H":        "/?[2J?[H",
		"/a\r\n12:00 GET /fake": "/a??12:00 GET /fake",
		"/café":                 "/café",
		"/\u009b31m":            "/?31m",
	} {
		if got := printable(in); got != want {
			t.Errorf("printable(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseAuth(t *testing.T) {
	env := func(pw string) Env {
		return Env{Getenv: func(k string) string {
			if k == "MANCAR_AUTH_PASSWORD" {
				return pw
			}
			return ""
		}}
	}
	if got, err := parseAuth(env(""), "klien:rahasia123"); err != nil || got != "klien:rahasia123" {
		t.Errorf("user:password: %q %v", got, err)
	}
	if got, err := parseAuth(env("dari-env-123"), "klien"); err != nil || got != "klien:dari-env-123" {
		t.Errorf("password from MANCAR_AUTH_PASSWORD: %q %v", got, err)
	}
	for _, bad := range []string{"klien", ":rahasia123", "klien:short"} {
		if _, err := parseAuth(env(""), bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if got, _ := parseAuth(env(""), ""); got != "" {
		t.Error("no --auth should give nothing")
	}
}
