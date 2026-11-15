package netutil

import (
	"net/http"
	"testing"
)

func TestClientFromRequest(t *testing.T) {
	trusted, err := ParsePrefixes("10.0.0.0/8, 127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, remote, xff, xfp string
		wantIP, wantProto      string
	}{
		{"direct client, spoofed headers ignored", "203.0.113.9:555", "1.2.3.4", "https", "203.0.113.9", "http"},
		{"trusted proxy", "10.0.0.2:555", "198.51.100.7", "https", "198.51.100.7", "https"},
		{"client-supplied prefix is not trusted", "10.0.0.2:555", "6.6.6.6, 198.51.100.7", "", "198.51.100.7", "http"},
		{"chain of trusted proxies", "10.0.0.2:555", "198.51.100.7, 10.0.0.9", "", "198.51.100.7", "http"},
		{"trusted proxy without header", "10.0.0.2:555", "", "", "10.0.0.2", "http"},
	}
	for _, c := range cases {
		r, _ := http.NewRequest("GET", "http://x/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if c.xfp != "" {
			r.Header.Set("X-Forwarded-Proto", c.xfp)
		}
		got := ClientFromRequest(r, trusted)
		if got.IP != c.wantIP || got.Proto != c.wantProto {
			t.Errorf("%s: got %+v, want %s/%s", c.name, got, c.wantIP, c.wantProto)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	for in, want := range map[string]string{
		"Foo.Example.com:443": "foo.example.com", "foo.example.com.": "foo.example.com", "[::1]:80": "::1", "x": "x",
	} {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}
