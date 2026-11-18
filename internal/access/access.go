// Package access guards private tunnels: only the account that owns a
// tunnel may open it in a browser.
//
// The visitor's dashboard session lives on the base domain and is never
// sent to tunnel hosts (any tunnel's app would see it). Instead:
//
//  1. The router sends a visitor without access to the dashboard
//     sign in page (/dashboard/#ref=HOST/PATH).
//  2. Once signed in, the dashboard checks that the account owns the live
//     tunnel on HOST and issues a ticket: signed, for that host and
//     account, valid for a minute, usable once.
//  3. The browser goes to https://HOST/_mancar/access?ticket=...; the
//     router redeems the ticket for a cookie scoped to that host only
//     (__Host- prefix: no Domain attribute, Secure, Path=/) and removes
//     the cookie from every request it forwards to the app.
//
// Tickets and cookies are bound to the owner's account ID, so a hostname
// that later belongs to someone else does not let the old cookie in.
package access

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// Path is where the router redeems tickets on a private tunnel host.
	Path = "/_mancar/access"
	// TicketTTL bounds the trip dashboard -> tunnel host.
	TicketTTL = time.Minute
	// CookieTTL is how long a browser keeps access to one tunnel host.
	CookieTTL = 12 * time.Hour

	kindTicket = "t"
	kindCookie = "c"
)

// Keeper issues and checks tickets and cookies. The router and the
// dashboard share one (same process), which keeps single use simple.
type Keeper struct {
	key    []byte
	secure bool
	now    func() time.Time

	mu   sync.Mutex
	used map[string]time.Time // ticket nonce -> expiry
}

// New derives the signing key from the gateway secret. secure is true when
// tunnels are served over HTTPS (the cookie then carries the __Host- prefix).
func New(secret string, secure bool) *Keeper {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("mancar private tunnel access v1"))
	return &Keeper{key: m.Sum(nil), secure: secure, now: time.Now, used: map[string]time.Time{}}
}

// SetClock replaces the clock (tests).
func (k *Keeper) SetClock(now func() time.Time) { k.now = now }

type claims struct {
	Kind  string `json:"k"`
	Host  string `json:"h"`
	User  string `json:"u"`
	Exp   int64  `json:"e"`
	Nonce string `json:"n,omitempty"`
}

func (k *Keeper) sign(c claims) string {
	b, _ := json.Marshal(c)
	p := base64.RawURLEncoding.EncodeToString(b)
	m := hmac.New(sha256.New, k.key)
	m.Write([]byte(p))
	return p + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (k *Keeper) parse(s, kind, host string) (claims, bool) {
	p, sig, ok := strings.Cut(s, ".")
	if !ok {
		return claims{}, false
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	m := hmac.New(sha256.New, k.key)
	m.Write([]byte(p))
	if err != nil || !hmac.Equal(got, m.Sum(nil)) {
		return claims{}, false
	}
	b, err := base64.RawURLEncoding.DecodeString(p)
	var c claims
	if err != nil || json.Unmarshal(b, &c) != nil {
		return claims{}, false
	}
	if c.Kind != kind || c.Host != host || c.User == "" || k.now().Unix() >= c.Exp {
		return claims{}, false
	}
	return c, true
}

// Ticket issues a one-time ticket letting userID into host.
func (k *Keeper) Ticket(host, userID string) string {
	n := make([]byte, 16)
	rand.Read(n)
	return k.sign(claims{Kind: kindTicket, Host: host, User: userID,
		Exp: k.now().Add(TicketTTL).Unix(), Nonce: base64.RawURLEncoding.EncodeToString(n)})
}

// TicketURL is where the dashboard sends the browser: the redemption path
// on the tunnel (publicURL, e.g. https://app.example.com), then next (a
// path on it).
func (k *Keeper) TicketURL(publicURL, host, userID, next string) string {
	q := url.Values{"ticket": {k.Ticket(host, userID)}, "next": {SafeNext(next)}}
	return strings.TrimSuffix(publicURL, "/") + Path + "?" + q.Encode()
}

// Redeem checks a ticket for host and burns it. It returns the account ID.
func (k *Keeper) Redeem(ticket, host string) (string, bool) {
	c, ok := k.parse(ticket, kindTicket, host)
	if !ok || c.Nonce == "" {
		return "", false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	for n, exp := range k.used {
		if now.After(exp) {
			delete(k.used, n)
		}
	}
	if _, seen := k.used[c.Nonce]; seen {
		return "", false
	}
	k.used[c.Nonce] = time.Unix(c.Exp, 0).Add(time.Second)
	return c.User, true
}

// CookieName is __Host-mancar_access over HTTPS (host-only enforced by the
// browser), mancar_access otherwise (local development).
func (k *Keeper) CookieName() string {
	if k.secure {
		return "__Host-mancar_access"
	}
	return "mancar_access"
}

// SetCookie gives the browser access to host for CookieTTL.
func (k *Keeper) SetCookie(w http.ResponseWriter, host, userID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     k.CookieName(),
		Value:    k.sign(claims{Kind: kindCookie, Host: host, User: userID, Exp: k.now().Add(CookieTTL).Unix()}),
		Path:     "/",
		MaxAge:   int(CookieTTL / time.Second),
		Secure:   k.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// Allowed reports whether r carries a valid access cookie for host and
// the account ownerID.
func (k *Keeper) Allowed(r *http.Request, host, ownerID string) bool {
	for _, c := range r.Cookies() {
		if c.Name == k.CookieName() {
			if got, ok := k.parse(c.Value, kindCookie, host); ok && got.User == ownerID {
				return true
			}
		}
	}
	return false
}

// StripCookie removes the access cookie from a request before it is
// forwarded, so the tunnel's app never sees it.
func (k *Keeper) StripCookie(h http.Header) {
	lines := h.Values("Cookie")
	if len(lines) == 0 {
		return
	}
	var keep []string
	for _, line := range lines {
		for _, part := range strings.Split(line, ";") {
			name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
			if name != "" && name != k.CookieName() {
				keep = append(keep, strings.TrimSpace(part))
			}
		}
	}
	h.Del("Cookie")
	if len(keep) > 0 {
		h.Set("Cookie", strings.Join(keep, "; "))
	}
}

// SafeNext keeps only a local path ("/x?y"), never another site. Control
// characters are refused too: browsers drop tabs and newlines from URLs,
// which would turn "/\t/evil.com" into "//evil.com".
func SafeNext(next string) string {
	if next == "" || next[0] != '/' || strings.HasPrefix(next, "//") || strings.Contains(next, "\\") {
		return "/"
	}
	for _, c := range next {
		if c < 0x20 || c == 0x7f {
			return "/"
		}
	}
	return next
}
