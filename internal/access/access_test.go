package access_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tinoimammp/mancar/internal/access"
)

func cookieFrom(t *testing.T, k *access.Keeper, host, user string) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	k.SetCookie(rec, host, user)
	cs := rec.Result().Cookies()
	if len(cs) != 1 {
		t.Fatalf("cookies: %v", cs)
	}
	return cs[0]
}

func is(id string) func(string) bool { return func(u string) bool { return u == id } }

func TestTicketIsSingleUseAndBound(t *testing.T) {
	k := access.New("secret", true)
	tk := k.Ticket("app.example.com", "u1")
	if _, ok := k.Redeem(tk, "other.example.com"); ok {
		t.Error("ticket worked on another host")
	}
	if u, ok := k.Redeem(tk, "app.example.com"); !ok || u != "u1" {
		t.Fatalf("Redeem = %q %v", u, ok)
	}
	if _, ok := k.Redeem(tk, "app.example.com"); ok {
		t.Error("ticket worked twice")
	}
	if _, ok := access.New("other secret", true).Redeem(k.Ticket("app.example.com", "u1"), "app.example.com"); ok {
		t.Error("ticket signed with another secret accepted")
	}
}

func TestTicketExpires(t *testing.T) {
	k := access.New("secret", true)
	now := time.Now()
	k.SetClock(func() time.Time { return now })
	tk := k.Ticket("app.example.com", "u1")
	k.SetClock(func() time.Time { return now.Add(access.TicketTTL + time.Second) })
	if _, ok := k.Redeem(tk, "app.example.com"); ok {
		t.Error("expired ticket accepted")
	}
}

func TestCookie(t *testing.T) {
	k := access.New("secret", true)
	c := cookieFrom(t, k, "app.example.com", "u1")
	if c.Name != "__Host-mancar_access" || !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" {
		t.Errorf("cookie attributes: %+v", c)
	}
	r := httptest.NewRequest("GET", "https://app.example.com/", nil)
	r.AddCookie(c)
	if !k.Allowed(r, "app.example.com", is("u1")) {
		t.Error("own cookie refused")
	}
	if k.Allowed(r, "app.example.com", is("u2")) {
		t.Error("cookie let another owner's tunnel in (hostname reused)")
	}
	if k.Allowed(r, "evil.example.com", is("u1")) {
		t.Error("cookie worked on another host")
	}
	// a ticket is not a cookie
	r2 := httptest.NewRequest("GET", "https://app.example.com/", nil)
	r2.AddCookie(&http.Cookie{Name: c.Name, Value: k.Ticket("app.example.com", "u1")})
	if k.Allowed(r2, "app.example.com", is("u1")) {
		t.Error("ticket accepted as a cookie")
	}
}

func TestStripCookie(t *testing.T) {
	k := access.New("secret", true)
	h := http.Header{}
	h.Add("Cookie", "a=1; __Host-mancar_access=xyz; b=2")
	k.StripCookie(h)
	if got := h.Get("Cookie"); got != "a=1; b=2" {
		t.Errorf("Cookie = %q", got)
	}
	h = http.Header{"Cookie": {"__Host-mancar_access=xyz"}}
	k.StripCookie(h)
	if _, ok := h["Cookie"]; ok {
		t.Errorf("Cookie header left: %v", h)
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"/a?b=1": "/a?b=1", "": "/", "//evil.com": "/", "https://evil.com": "/", "/\\evil.com": "/", "x": "/",
		"/\t/evil.com": "/", "/\n/evil.com": "/", "/\x00x": "/", "/caf\u00e9?q=1": "/caf\u00e9?q=1",
	} {
		if got := access.SafeNext(in); got != want {
			t.Errorf("SafeNext(%q) = %q, want %q", in, got, want)
		}
	}
	u := access.New("s", true).TicketURL("https://app.example.com", "app.example.com", "u1", "//evil.com")
	if !strings.HasPrefix(u, "https://app.example.com/_mancar/access?") || !strings.Contains(u, "next=%2F&") && !strings.HasSuffix(u, "next=%2F") {
		t.Errorf("TicketURL = %s", u)
	}
}

func TestRevokeEndsCookiesAndTickets(t *testing.T) {
	k := access.New("secret", true)
	now := time.Now()
	k.SetClock(func() time.Time { return now })
	c := cookieFrom(t, k, "app.example.com", "u1")
	ticket := k.Ticket("app.example.com", "u1")
	other := cookieFrom(t, k, "app.example.com", "u2")
	now = now.Add(2 * time.Second)
	k.Revoke("u1") // u1 disabled, deleted, or a new password
	req := func(c *http.Cookie) *http.Request {
		r := httptest.NewRequest("GET", "https://app.example.com/", nil)
		r.AddCookie(c)
		return r
	}
	all := func(string) bool { return true }
	if k.Allowed(req(c), "app.example.com", all) {
		t.Error("a cookie issued before Revoke still works")
	}
	if _, ok := k.Redeem(ticket, "app.example.com"); ok {
		t.Error("a ticket issued before Revoke still works")
	}
	if !k.Allowed(req(other), "app.example.com", all) {
		t.Error("another account's cookie stopped working")
	}
	now = now.Add(2 * time.Second) // signed in again afterwards
	if !k.Allowed(req(cookieFrom(t, k, "app.example.com", "u1")), "app.example.com", all) {
		t.Error("a cookie issued after Revoke is refused")
	}
}
