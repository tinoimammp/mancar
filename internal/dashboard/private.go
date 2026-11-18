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
// HOST/PATH) to a tunnel. The owner of a live tunnel, and the accounts a
// private one was shared with (--allow), get its URL (with a one-time
// ticket when private). Anyone else gets the plain URL of a live private
// tunnel, where the gateway shows the Restricted page again, or no URL at
// all. Hosts outside BASE_DOMAIN are refused.
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
	// The answer only ever points at a tunnel this account may open, or at
	// a live private tunnel (where the gateway shows its own Restricted
	// page). Never at someone else's public tunnel: the dashboard is not a
	// redirector to arbitrary apps under BASE_DOMAIN (phishing).
	out := map[string]any{"url": "", "allowed": false, "owner": false}
	for _, s := range d.opts.Hub.Sessions() {
		for _, t := range s.Tunnels {
			if t.Hostname != host {
				continue
			}
			owner := s.UserID == a.ID
			// shared accounts must have confirmed their email (the owner
			// may have shared by email address)
			mayOpen := owner || (a.Verified() && slices.Contains(t.AllowIDs, a.ID))
			switch {
			case mayOpen && t.Private && d.opts.Access != nil:
				out["url"], out["allowed"], out["owner"] = d.opts.Access.TicketURL(t.PublicURL, host, a.ID, path), true, owner
			case mayOpen && !t.Private:
				out["url"], out["allowed"], out["owner"] = strings.TrimSuffix(t.PublicURL, "/")+path, true, owner
			case t.Private:
				out["url"] = plain + path // the Restricted page again
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}
