package dashboard

import (
	"cmp"
	_ "embed"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/tinoimammp/mancar/internal/access"
)

//go:embed pages/restricted.html
var restrictedHTML string

var restrictedPage = template.Must(template.New("restricted").Parse(restrictedHTML))

// RestrictedPage answers a browser that opened a private tunnel without
// access: a page on the tunnel's own host with a "Log in to continue"
// button to signIn (the dashboard sign in page with the tunnel as ref).
// It is self-contained, so nothing is loaded from the app behind the tunnel.
func RestrictedPage(w http.ResponseWriter, host, signIn string) {
	// the logo comes from the dashboard (the sign in page's origin)
	dash := ""
	if u, err := url.Parse(signIn); err == nil && u.Host != "" {
		dash = u.Scheme + "://" + u.Host
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src "+cmp.Or(dash, "'none'")+
		"; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.WriteHeader(http.StatusUnauthorized)
	restrictedPage.Execute(w, struct{ Host, SignIn, Logo string }{host, signIn, dash + "/dashboard/logo.webp"})
}

// myAccess sends the signed-in person on from the sign in page (#ref=
// HOST/PATH) to a tunnel. The owner of a live private tunnel, and the
// accounts it was shared with (--allow), get its URL with a one-time ticket; anyone else (and any host that is offline) gets
// the plain URL, where the gateway shows the Restricted page again;
// "allowed" tells the dashboard which of the two it is. Someone else's
// tunnel and an offline one answer alike, so this does not reveal who owns
// what. Hosts outside
// BASE_DOMAIN are refused: this is never an open redirect.
func (d *Dashboard) myAccess(w http.ResponseWriter, r *http.Request) {
	a := accountFrom(r)
	var in struct {
		Target string `json:"target"` // "host/path?query"
	}
	if err := readJSON(r, &in); err != nil || in.Target == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "expected JSON with target")
		return
	}
	host, path := in.Target, "/"
	if i := strings.IndexAny(in.Target, "/?"); i >= 0 {
		host, path = in.Target[:i], in.Target[i:]
		if path[0] == '?' {
			path = "/" + path
		}
	}
	host, path = strings.ToLower(host), access.SafeNext(path)
	label, ok := strings.CutSuffix(host, "."+d.opts.BaseDomain)
	if !ok || label == "" || strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-.") != "" {
		writeErr(w, http.StatusNotFound, "not_found", "not a tunnel of this server")
		return
	}
	plain := d.opts.PublicScheme + "://" + host
	if d.opts.PublicPort != "" {
		plain += ":" + d.opts.PublicPort
	}
	out := map[string]any{"url": plain + path, "allowed": false}
	for _, s := range d.opts.Hub.Sessions() {
		for _, t := range s.Tunnels {
			mayOpen := s.UserID == a.ID || slices.Contains(t.AllowIDs, a.ID)
			switch {
			case t.Hostname != host || !mayOpen:
			case t.Private && d.opts.Access != nil:
				out["url"], out["allowed"] = d.opts.Access.TicketURL(t.PublicURL, host, a.ID, path), true
			case !t.Private:
				out["url"], out["allowed"] = strings.TrimSuffix(t.PublicURL, "/")+path, true
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}
