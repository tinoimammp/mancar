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
