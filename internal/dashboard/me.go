package dashboard

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/tinoimammp/mancar/internal/gateway"
	"github.com/tinoimammp/mancar/internal/store/postgres"
)

// The signed-in account's own things (/api/v1/me). Every handler works on
// accountFrom(r) only; IDs in the path are checked against it, and anything
// that belongs to someone else answers 404, the same as a missing one.

type limitsOut struct {
	Tunnels       int  `json:"tunnels"`
	Tokens        *int `json:"tokens"`         // null: no limit
	CustomDomains *int `json:"custom_domains"` // null: no limit
}

func (d *Dashboard) limits(a postgres.Account) limitsOut {
	l := limitsOut{Tunnels: d.opts.MaxTunnels}
	if !a.IsAdmin() { // admins have no limits
		l.Tokens, l.CustomDomains = a.MaxTokens, a.MaxCustomDomains
	}
	return l
}

type myDomain struct {
	Hostname  string                `json:"hostname"`
	Kind      string                `json:"kind"`
	Online    bool                  `json:"online"`
	HoldUntil *time.Time            `json:"hold_until,omitempty"`
	Usage     postgres.UsageWindows `json:"usage"`
}

func (d *Dashboard) myDomains(r *http.Request, id string) ([]myDomain, error) {
	list, err := d.opts.Store.ListDomains(r.Context())
	if err != nil {
		return nil, err
	}
	traffic, err := d.opts.Store.UsageByHost(r.Context())
	if err != nil {
		d.log.Warn("dashboard: reading traffic statistics failed", "err", err)
	}
	out := []myDomain{}
	for _, x := range list {
		if x.UserID != id {
			continue
		}
		v := myDomain{Hostname: x.Hostname, Kind: x.Kind, Online: x.Online, Usage: traffic[x.Hostname]}
		if !x.Online {
			h := x.HoldUntil
			v.HoldUntil = &h
		}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Online && !out[j].Online })
	return out, nil
}

func (d *Dashboard) myOverview(w http.ResponseWriter, r *http.Request) {
	a := accountFrom(r)
	tunnels := []gateway.TunnelInfo{}
	for _, s := range d.opts.Hub.Sessions() {
		if s.UserID == a.ID {
			tunnels = append(tunnels, s.Tunnels...)
		}
	}
	domains, err := d.myDomains(r, a.ID)
	if err != nil {
		d.internal(w, "list domains", err)
		return
	}
	byUser, err := d.opts.Store.UsageByUser(r.Context())
	if err != nil {
		d.log.Warn("dashboard: reading traffic statistics failed", "err", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"base_domain": d.opts.BaseDomain, "email": a.Email, "email_verified": a.Verified(),
		"limits": d.limits(a), "tunnels": tunnels, "domains": domains, "usage": byUser[a.ID],
	})
}

type myToken struct {
	ID         string     `json:"id"`
	Username   string     `json:"username"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	Agents     int        `json:"connected_agents"`
}

func (d *Dashboard) ownTokens(r *http.Request, id string) ([]myToken, error) {
	list, err := d.opts.Store.ListAgentTokens(r.Context())
	if err != nil {
		return nil, err
	}
	online := map[string]int{}
	for _, s := range d.opts.Hub.Sessions() {
		online[s.TokenID]++
	}
	out := []myToken{}
	for _, t := range list {
		if t.UserID == id {
			out = append(out, myToken{t.ID, t.Username, t.Name, t.CreatedAt, t.LastUsedAt, t.RevokedAt, online[t.ID]})
		}
	}
	return out, nil
}

func (d *Dashboard) myTokens(w http.ResponseWriter, r *http.Request) {
	a := accountFrom(r)
	toks, err := d.ownTokens(r, a.ID)
	if err != nil {
		d.internal(w, "list tokens", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"email_verified": a.Verified(), "limit": d.limits(a).Tokens, "tokens": toks})
}

func (d *Dashboard) myCreateToken(w http.ResponseWriter, r *http.Request) {
	a := accountFrom(r)
	var in struct {
		Name string `json:"name"`
		User string `json:"user"` // ignored: a token is always for the signed-in account
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "expected JSON with name")
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "dashboard"
	}
	if len(name) > 64 {
		writeErr(w, http.StatusBadRequest, "invalid_name", "name: at most 64 characters")
		return
	}
	tok, id, status, code, msg := d.createOwnToken(r, a, name)
	if status != 0 {
		writeErr(w, status, code, msg)
		return
	}
	d.audit(r, "token.create", a.Username, name)
	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "user": a.Username, "name": name, "token": tok})
}

func (d *Dashboard) myRevokeToken(w http.ResponseWriter, r *http.Request) {
	a := accountFrom(r)
	id := r.PathValue("id")
	toks, err := d.ownTokens(r, a.ID)
	if err != nil {
		d.internal(w, "list tokens", err)
		return
	}
	owned := false
	for _, t := range toks {
		owned = owned || (t.ID == id && t.RevokedAt == nil)
	}
	if !owned {
		writeErr(w, http.StatusNotFound, "not_found", "no active token with that ID")
		return
	}
	d.revokeToken(w, r)
}

func (d *Dashboard) myReleaseDomain(w http.ResponseWriter, r *http.Request) {
	a := accountFrom(r)
	host := strings.ToLower(r.PathValue("hostname"))
	domains, err := d.myDomains(r, a.ID)
	if err != nil {
		d.internal(w, "list domains", err)
		return
	}
	for _, x := range domains {
		if x.Hostname == host {
			d.releaseDomain(w, r)
			return
		}
	}
	writeErr(w, http.StatusConflict, "not_releasable", "no such reservation, or a tunnel is still connected to it")
}

// ownsHost reports whether hostname is one of the account's reservations.
func (d *Dashboard) ownsHost(r *http.Request, id, host string) (bool, error) {
	domains, err := d.myDomains(r, id)
	if err != nil {
		return false, err
	}
	for _, x := range domains {
		if x.Hostname == host {
			return true, nil
		}
	}
	return false, nil
}

func (d *Dashboard) myAccount(w http.ResponseWriter, r *http.Request) {
	a := accountFrom(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"username": a.Username, "email": a.Email, "email_verified": a.Verified(), "role": a.Role,
		"created_at": a.CreatedAt, "limits": d.limits(a),
	})
}

func (d *Dashboard) myChangePassword(w http.ResponseWriter, r *http.Request) {
	a := accountFrom(r)
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "expected JSON with current and new")
		return
	}
	if retry, blocked := d.byUser.Blocked(a.Username); blocked {
		d.tooMany(w, retry)
		return
	}
	if ok, _ := CheckPassword(a.PasswordHash, in.Current); !ok {
		d.byUser.Fail(a.Username)
		writeErr(w, http.StatusBadRequest, "bad_password", "the current password is wrong")
		return
	}
	hash, err := HashPassword(in.New)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "weak_password", err.Error())
		return
	}
	if err := d.opts.Store.SetPassword(r.Context(), a.ID, hash); err != nil {
		d.internal(w, "set password", err)
		return
	}
	// other sessions end; this one continues with a fresh cookie
	if b, err := d.opts.Store.AccountByID(r.Context(), a.ID); err == nil {
		d.startSession(w, b)
	}
	d.audit(r, "account.password", a.Username, "")
	w.WriteHeader(http.StatusNoContent)
}

func (d *Dashboard) myResendVerification(w http.ResponseWriter, r *http.Request) {
	a := accountFrom(r)
	if a.Verified() {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if d.opts.Mailer == nil {
		writeErr(w, http.StatusConflict, "email_disabled", "this server cannot send email; ask the admin to confirm your address")
		return
	}
	if d.mailLimited(w, r) {
		return
	}
	if d.addrAllowed(a.Email) {
		if err := d.sendVerify(r.Context(), a); err != nil {
			d.internal(w, "create link", err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (d *Dashboard) myDeleteAccount(w http.ResponseWriter, r *http.Request) {
	a := accountFrom(r)
	switch err := d.opts.Store.DeleteAccount(r.Context(), a.ID); {
	case errors.Is(err, postgres.ErrLastAdmin):
		writeErr(w, http.StatusConflict, "last_admin", "you are the last admin; make someone else admin first")
		return
	case err != nil:
		d.internal(w, "delete account", err)
		return
	}
	d.disconnectUser(a.ID)
	d.audit(r, "account.delete", a.Username, "")
	d.clearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// disconnectUser ends every agent session of an account.
func (d *Dashboard) disconnectUser(id string) int {
	n := 0
	for _, s := range d.opts.Hub.Sessions() {
		if s.UserID == id && d.opts.Hub.Disconnect(s.ID) {
			n++
		}
	}
	return n
}
