// Package dashboard serves the web dashboard and its JSON API on the base
// domain: /dashboard/ (static single-page app, embedded in the binary) and
// /api/v1/admin/* (session-authenticated operator API).
//
// Security model:
//   - Admins log in with a username and password (PBKDF2-SHA256). Admin
//     accounts are created on the server with "mancard admin set".
//   - The session is an HMAC-signed cookie (HttpOnly, SameSite=Strict, Secure
//     over HTTPS) re-validated against the database on every request.
//   - State-changing requests must carry the X-Mancar-CSRF header and, when the
//     browser sends one, an Origin of the dashboard itself. Together with
//     SameSite=Strict this blocks cross-site request forgery.
//   - Failed logins are limited per client address and per username.
//   - Agent token secrets are shown exactly once, in the create response.
package dashboard

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tinoimammp/mancar/internal/gateway"
	"github.com/tinoimammp/mancar/internal/inspect"
	"github.com/tinoimammp/mancar/internal/netutil"
	"github.com/tinoimammp/mancar/internal/ratelimit"
	"github.com/tinoimammp/mancar/internal/store/postgres"
	"github.com/tinoimammp/mancar/internal/usage"
	"github.com/tinoimammp/mancar/internal/version"
)

//go:embed static
var staticFS embed.FS

// Store is the persistence the dashboard needs (implemented by
// *postgres.Store).
type Store interface {
	AdminByUsername(ctx context.Context, username string) (postgres.Admin, error)
	AdminByID(ctx context.Context, id string) (postgres.Admin, error)
	TouchAdminLogin(ctx context.Context, id string) error

	ListUsers(ctx context.Context) ([]postgres.UserInfo, error)
	EnsureUser(ctx context.Context, username string) (string, error)
	DeleteUser(ctx context.Context, id string) error

	ListAgentTokens(ctx context.Context) ([]postgres.TokenInfo, error)
	CreateAgentToken(ctx context.Context, userID, name string) (plaintext, id string, err error)
	RevokeAgentToken(ctx context.Context, id string) error

	ListDomains(ctx context.Context) ([]postgres.DomainInfo, error)
	ReleaseDomain(ctx context.Context, hostname string) error

	UsageByHost(ctx context.Context) (map[string]postgres.UsageWindows, error)
	UsageByUser(ctx context.Context) (map[string]postgres.UsageWindows, error)
}

// Hub is the part of the gateway the dashboard reads and controls.
type Hub interface {
	Stats() gateway.Stats
	Sessions() []gateway.SessionInfo
	Disconnect(sessionID string) bool
	DisconnectToken(tokenID string) int
}

// Options configures the dashboard.
type Options struct {
	Store Store // nil disables the dashboard (in-memory development mode)
	Hub   Hub
	// SessionSecret signs session cookies (JWT_SECRET).
	SessionSecret string
	// Secure marks cookies Secure (public scheme is https).
	Secure         bool
	BaseDomain     string
	PublicScheme   string
	PublicPort     string
	TCPPortMin     int
	TCPPortMax     int
	TrustedProxies []netip.Prefix
	SessionTTL     time.Duration
	// HealthCheck verifies the database for the overview page; may be nil.
	HealthCheck func(ctx context.Context) error
	Logger      *slog.Logger
	// Now replaces the clock (tests).
	Now func() time.Time
	// Inspector is the request inspector; nil when it is off.
	Inspector *inspect.Recorder
	// Replay serves replayed requests (the public router).
	Replay http.Handler
}

// Dashboard is an http.Handler for /dashboard/ and /api/v1/admin/.
type Dashboard struct {
	opts      Options
	log       *slog.Logger
	signer    signer
	cookie    string
	byIP      *ratelimit.FailureLimiter
	byUser    *ratelimit.FailureLimiter
	mux       *http.ServeMux
	startedAt time.Time
}

// HeaderCSRF must be present on every state-changing API request.
const HeaderCSRF = "X-Mancar-CSRF"

var usernameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// New builds the dashboard handler.
func New(opts Options) *Dashboard {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.SessionTTL <= 0 {
		opts.SessionTTL = 12 * time.Hour
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	d := &Dashboard{
		opts: opts, log: opts.Logger, signer: newSigner(opts.SessionSecret),
		byIP:      ratelimit.NewFailureLimiter(10, 15*time.Minute),
		byUser:    ratelimit.NewFailureLimiter(10, 15*time.Minute),
		mux:       http.NewServeMux(),
		startedAt: opts.Now(),
	}
	// The __Host- prefix makes browsers refuse the cookie unless it is Secure,
	// host-only and Path=/, so a sibling tunnel subdomain can never set or
	// overwrite it.
	d.cookie = "mancar_session"
	if opts.Secure {
		d.cookie = "__Host-mancar_session"
	}

	static, _ := fs.Sub(staticFS, "static")
	files := http.FileServerFS(static)
	d.mux.Handle("GET /dashboard/", http.StripPrefix("/dashboard/", files))
	d.mux.HandleFunc("GET /dashboard", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard/", http.StatusMovedPermanently)
	})

	d.mux.HandleFunc("POST /api/v1/admin/login", d.login)
	d.mux.HandleFunc("POST /api/v1/admin/logout", d.logout)
	d.mux.HandleFunc("GET /api/v1/admin/session", d.authed(d.session))
	d.mux.HandleFunc("GET /api/v1/admin/overview", d.authed(d.overview))
	d.mux.HandleFunc("GET /api/v1/admin/agents", d.authed(d.agents))
	d.mux.HandleFunc("POST /api/v1/admin/agents/{id}/disconnect", d.authed(d.disconnectAgent))
	d.mux.HandleFunc("GET /api/v1/admin/users", d.authed(d.users))
	d.mux.HandleFunc("DELETE /api/v1/admin/users/{id}", d.authed(d.deleteUser))
	d.mux.HandleFunc("GET /api/v1/admin/tokens", d.authed(d.tokens))
	d.mux.HandleFunc("POST /api/v1/admin/tokens", d.authed(d.createToken))
	d.mux.HandleFunc("POST /api/v1/admin/tokens/{id}/revoke", d.authed(d.revokeToken))
	d.mux.HandleFunc("GET /api/v1/admin/domains", d.authed(d.domains))
	d.mux.HandleFunc("DELETE /api/v1/admin/domains/{hostname}", d.authed(d.releaseDomain))
	d.mux.HandleFunc("GET /api/v1/admin/requests", d.authed(d.listRequests))
	d.mux.HandleFunc("DELETE /api/v1/admin/requests", d.authed(d.clearRequests))
	d.mux.HandleFunc("GET /api/v1/admin/requests/{id}", d.authed(d.getRequest))
	d.mux.HandleFunc("POST /api/v1/admin/requests/{id}/replay", d.authed(d.replayRequest))
	d.mux.HandleFunc("/api/v1/admin/", func(w http.ResponseWriter, _ *http.Request) {
		writeErr(w, http.StatusNotFound, "not_found", "no such endpoint")
	})
	return d
}

func (d *Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
		"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	h.Set("Cache-Control", "no-store")
	if d.opts.Store == nil {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeErr(w, http.StatusServiceUnavailable, "dashboard_disabled", "the dashboard needs STORAGE=postgres")
			return
		}
		h.Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "The dashboard is disabled: it needs STORAGE=postgres.\n")
		return
	}
	d.mux.ServeHTTP(w, r)
}

// ---- helpers ---------------------------------------------------------------

type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	var e apiError
	e.Error.Code, e.Error.Message = code, msg
	writeJSON(w, status, e)
}

func (d *Dashboard) internal(w http.ResponseWriter, what string, err error) {
	d.log.Error("dashboard: "+what, "err", err)
	writeErr(w, http.StatusInternalServerError, "internal", "internal error")
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// sameOrigin rejects cross-site state changes: the CSRF header cannot be set
// by a plain cross-site form, and a cross-origin fetch that sets it needs a
// CORS preflight this server never approves. Origin is checked as well when
// the browser sends one.
func (d *Dashboard) sameOrigin(r *http.Request) bool {
	if r.Header.Get(HeaderCSRF) == "" {
		return false
	}
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	want := d.opts.PublicScheme + "://" + d.opts.BaseDomain
	if d.opts.PublicPort != "" {
		want += ":" + d.opts.PublicPort
	}
	return strings.EqualFold(o, want)
}

func (d *Dashboard) client(r *http.Request) string {
	return netutil.ClientFromRequest(r, d.opts.TrustedProxies).IP
}

type ctxAdmin struct{}

// authed wraps a handler with session validation (and the CSRF check for
// anything that is not a GET).
func (d *Dashboard) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && !d.sameOrigin(r) {
			writeErr(w, http.StatusForbidden, "csrf", "cross-site request refused")
			return
		}
		ck, err := r.Cookie(d.cookie)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthenticated", "please log in")
			return
		}
		c, err := d.signer.verify(ck.Value, d.opts.Now())
		if err != nil {
			d.clearCookie(w)
			writeErr(w, http.StatusUnauthorized, "unauthenticated", "session expired, please log in again")
			return
		}
		a, err := d.opts.Store.AdminByID(r.Context(), c.AdminID)
		if errors.Is(err, postgres.ErrNotFound) || (err == nil && c.IssuedMs < a.PasswordChangedAt.UnixMilli()) {
			d.clearCookie(w)
			writeErr(w, http.StatusUnauthorized, "unauthenticated", "session is no longer valid, please log in again")
			return
		}
		if err != nil {
			d.internal(w, "session lookup", err)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxAdmin{}, a)))
	}
}

func adminFrom(r *http.Request) postgres.Admin {
	a, _ := r.Context().Value(ctxAdmin{}).(postgres.Admin)
	return a
}

func (d *Dashboard) setCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: d.cookie, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: d.opts.Secure, SameSite: http.SameSiteStrictMode,
	})
}

func (d *Dashboard) clearCookie(w http.ResponseWriter) { d.setCookie(w, "", -1) }

// ---- authentication --------------------------------------------------------

func (d *Dashboard) login(w http.ResponseWriter, r *http.Request) {
	if !d.sameOrigin(r) {
		writeErr(w, http.StatusForbidden, "csrf", "cross-site request refused")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "expected JSON with username and password")
		return
	}
	user := strings.ToLower(strings.TrimSpace(in.Username))
	ip := d.client(r)
	if retry, blocked := d.byIP.Blocked(ip); blocked {
		d.tooMany(w, retry)
		return
	}
	if retry, blocked := d.byUser.Blocked(user); blocked {
		d.tooMany(w, retry)
		return
	}

	a, err := d.opts.Store.AdminByUsername(r.Context(), user)
	if err != nil && !errors.Is(err, postgres.ErrNotFound) {
		d.internal(w, "admin lookup", err)
		return
	}
	hash := a.PasswordHash
	if err != nil {
		hash = dummyHash // equal work for unknown users
	}
	ok, cerr := CheckPassword(hash, in.Password)
	if err != nil || cerr != nil || !ok {
		d.byIP.Fail(ip)
		d.byUser.Fail(user)
		d.log.Warn("dashboard login failed", "client", ip, "username", user)
		writeErr(w, http.StatusUnauthorized, "invalid_credentials", "wrong username or password")
		return
	}

	now := d.opts.Now()
	value := d.signer.sign(claims{AdminID: a.ID, Username: a.Username, IssuedMs: now.UnixMilli(),
		Expires: now.Add(d.opts.SessionTTL).Unix()})
	d.setCookie(w, value, int(d.opts.SessionTTL/time.Second))
	if err := d.opts.Store.TouchAdminLogin(r.Context(), a.ID); err != nil {
		d.log.Warn("dashboard: recording login time failed", "err", err)
	}
	d.log.Info("dashboard login", "client", ip, "username", a.Username)
	writeJSON(w, http.StatusOK, map[string]string{"username": a.Username})
}

func (d *Dashboard) tooMany(w http.ResponseWriter, retry time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(retry/time.Second)+1))
	writeErr(w, http.StatusTooManyRequests, "too_many_attempts", "too many failed logins; try again later")
}

func (d *Dashboard) logout(w http.ResponseWriter, r *http.Request) {
	if !d.sameOrigin(r) {
		writeErr(w, http.StatusForbidden, "csrf", "cross-site request refused")
		return
	}
	d.clearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (d *Dashboard) session(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"username": adminFrom(r).Username})
}

// ---- read endpoints --------------------------------------------------------

func (d *Dashboard) overview(w http.ResponseWriter, r *http.Request) {
	type out struct {
		Version    string        `json:"version"`
		BaseDomain string        `json:"base_domain"`
		TCPPorts   string        `json:"tcp_ports"`
		Database   string        `json:"database"`
		Uptime     int64         `json:"uptime_seconds"`
		Gateway    gateway.Stats `json:"gateway"`
		Users      int           `json:"users"`
		Tokens     int           `json:"active_tokens"`
		Domains    int           `json:"reserved_domains"`
		Inspector  string        `json:"inspector"`
		Traffic    usage.Totals  `json:"traffic_24h"`
		AllTime    usage.Totals  `json:"traffic_total"`
		TopHosts   []hostUsage   `json:"top_hosts"`
	}
	o := out{Version: version.Version, BaseDomain: d.opts.BaseDomain, Database: "ok",
		Uptime: int64(d.opts.Now().Sub(d.startedAt) / time.Second), Gateway: d.opts.Hub.Stats(), TCPPorts: "off",
		Inspector: "off"}
	if d.opts.Inspector != nil {
		o.Inspector = "on, kept " + d.opts.Inspector.Retention().String()
	}
	if d.opts.TCPPortMin > 0 {
		o.TCPPorts = strconv.Itoa(d.opts.TCPPortMin) + "-" + strconv.Itoa(d.opts.TCPPortMax)
	}
	if d.opts.HealthCheck != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := d.opts.HealthCheck(ctx); err != nil {
			o.Database = "unreachable"
			writeJSON(w, http.StatusOK, o)
			return
		}
	}
	users, err := d.opts.Store.ListUsers(r.Context())
	if err != nil {
		d.internal(w, "list users", err)
		return
	}
	o.Users = len(users)
	for _, u := range users {
		o.Tokens += u.ActiveTokens
		o.Domains += u.Domains
	}
	o.TopHosts = []hostUsage{}
	if byHost, err := d.opts.Store.UsageByHost(r.Context()); err != nil {
		d.log.Warn("dashboard: reading traffic statistics failed", "err", err)
	} else {
		for host, u := range byHost {
			o.Traffic.Requests += u.Day.Requests
			o.Traffic.Errors += u.Day.Errors
			o.Traffic.BytesIn += u.Day.BytesIn
			o.Traffic.BytesOut += u.Day.BytesOut
			o.AllTime.Requests += u.Total.Requests
			o.AllTime.Errors += u.Total.Errors
			o.AllTime.BytesIn += u.Total.BytesIn
			o.AllTime.BytesOut += u.Total.BytesOut
			if u.Day.Requests > 0 {
				o.TopHosts = append(o.TopHosts, hostUsage{Hostname: host, Usage: u})
			}
		}
		sort.Slice(o.TopHosts, func(i, j int) bool { return o.TopHosts[i].Usage.Day.Requests > o.TopHosts[j].Usage.Day.Requests })
		if len(o.TopHosts) > 10 {
			o.TopHosts = o.TopHosts[:10]
		}
	}
	writeJSON(w, http.StatusOK, o)
}

type hostUsage struct {
	Hostname string                `json:"hostname"`
	Usage    postgres.UsageWindows `json:"usage"`
}

// usernames maps user IDs to names for annotating live sessions.
func (d *Dashboard) usernames(ctx context.Context) (map[string]string, error) {
	users, err := d.opts.Store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, len(users))
	for _, u := range users {
		m[u.ID] = u.Username
	}
	return m, nil
}

func (d *Dashboard) agents(w http.ResponseWriter, r *http.Request) {
	names, err := d.usernames(r.Context())
	if err != nil {
		d.internal(w, "list users", err)
		return
	}
	tokenNames := map[string]string{}
	if toks, err := d.opts.Store.ListAgentTokens(r.Context()); err == nil {
		for _, t := range toks {
			tokenNames[t.ID] = t.Name
		}
	}
	type agent struct {
		gateway.SessionInfo
		Username  string `json:"username"`
		TokenName string `json:"token_name"`
	}
	out := []agent{}
	for _, s := range d.opts.Hub.Sessions() {
		out = append(out, agent{SessionInfo: s, Username: names[s.UserID], TokenName: tokenNames[s.TokenID]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"agents": out})
}

func (d *Dashboard) users(w http.ResponseWriter, r *http.Request) {
	users, err := d.opts.Store.ListUsers(r.Context())
	if err != nil {
		d.internal(w, "list users", err)
		return
	}
	online := map[string]int{}
	for _, s := range d.opts.Hub.Sessions() {
		online[s.UserID]++
	}
	traffic, err := d.opts.Store.UsageByUser(r.Context())
	if err != nil {
		d.log.Warn("dashboard: reading traffic statistics failed", "err", err)
	}
	type user struct {
		ID           string                `json:"id"`
		Username     string                `json:"username"`
		CreatedAt    time.Time             `json:"created_at"`
		ActiveTokens int                   `json:"active_tokens"`
		Domains      int                   `json:"domains"`
		Agents       int                   `json:"connected_agents"`
		Usage        postgres.UsageWindows `json:"usage"`
	}
	out := []user{}
	for _, u := range users {
		out = append(out, user{u.ID, u.Username, u.CreatedAt, u.ActiveTokens, u.Domains, online[u.ID], traffic[u.ID]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (d *Dashboard) tokens(w http.ResponseWriter, r *http.Request) {
	list, err := d.opts.Store.ListAgentTokens(r.Context())
	if err != nil {
		d.internal(w, "list tokens", err)
		return
	}
	online := map[string]int{}
	for _, s := range d.opts.Hub.Sessions() {
		online[s.TokenID]++
	}
	type token struct {
		ID         string     `json:"id"`
		Username   string     `json:"username"`
		Name       string     `json:"name"`
		CreatedAt  time.Time  `json:"created_at"`
		LastUsedAt *time.Time `json:"last_used_at"`
		RevokedAt  *time.Time `json:"revoked_at"`
		Agents     int        `json:"connected_agents"`
	}
	out := []token{}
	for _, t := range list {
		out = append(out, token{t.ID, t.Username, t.Name, t.CreatedAt, t.LastUsedAt, t.RevokedAt, online[t.ID]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

func (d *Dashboard) domains(w http.ResponseWriter, r *http.Request) {
	list, err := d.opts.Store.ListDomains(r.Context())
	if err != nil {
		d.internal(w, "list domains", err)
		return
	}
	traffic, err := d.opts.Store.UsageByHost(r.Context())
	if err != nil {
		d.log.Warn("dashboard: reading traffic statistics failed", "err", err)
	}
	type dom struct {
		Hostname  string                `json:"hostname"`
		Username  string                `json:"username"`
		Kind      string                `json:"kind"`
		Online    bool                  `json:"online"`
		HoldUntil *time.Time            `json:"hold_until,omitempty"`
		Usage     postgres.UsageWindows `json:"usage"`
	}
	out := []dom{}
	for _, x := range list {
		v := dom{Hostname: x.Hostname, Username: x.Username, Kind: x.Kind, Online: x.Online, Usage: traffic[x.Hostname]}
		if !x.Online {
			h := x.HoldUntil
			v.HoldUntil = &h
		}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Online && !out[j].Online })
	writeJSON(w, http.StatusOK, map[string]any{"domains": out})
}

// ---- write endpoints -------------------------------------------------------

func (d *Dashboard) audit(r *http.Request, action string, args ...any) {
	d.log.Info("dashboard action", append([]any{"action", action, "admin", adminFrom(r).Username, "client", d.client(r)}, args...)...)
}

func (d *Dashboard) disconnectAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !d.opts.Hub.Disconnect(id) {
		writeErr(w, http.StatusNotFound, "not_found", "no connected agent with that ID")
		return
	}
	d.audit(r, "agent.disconnect", "session", id)
	w.WriteHeader(http.StatusNoContent)
}

func (d *Dashboard) createToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		User string `json:"user"`
		Name string `json:"name"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "expected JSON with user and name")
		return
	}
	user := strings.ToLower(strings.TrimSpace(in.User))
	if !usernameRE.MatchString(user) {
		writeErr(w, http.StatusBadRequest, "invalid_user", "user: 1-64 characters from a-z, 0-9, '.', '_' and '-'")
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
	uid, err := d.opts.Store.EnsureUser(r.Context(), user)
	if err != nil {
		d.internal(w, "ensure user", err)
		return
	}
	tok, id, err := d.opts.Store.CreateAgentToken(r.Context(), uid, name)
	if err != nil {
		d.internal(w, "create token", err)
		return
	}
	d.audit(r, "token.create", "token", id, "user", user)
	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "user": user, "name": name, "token": tok})
}

func (d *Dashboard) revokeToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	switch err := d.opts.Store.RevokeAgentToken(r.Context(), id); {
	case errors.Is(err, postgres.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "no active token with that ID")
		return
	case err != nil:
		d.internal(w, "revoke token", err)
		return
	}
	n := d.opts.Hub.DisconnectToken(id)
	d.audit(r, "token.revoke", "token", id, "disconnected", n)
	writeJSON(w, http.StatusOK, map[string]int{"disconnected_agents": n})
}

func (d *Dashboard) deleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	switch err := d.opts.Store.DeleteUser(r.Context(), id); {
	case errors.Is(err, postgres.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "no user with that ID")
		return
	case err != nil:
		d.internal(w, "delete user", err)
		return
	}
	n := 0
	for _, s := range d.opts.Hub.Sessions() {
		if s.UserID == id && d.opts.Hub.Disconnect(s.ID) {
			n++
		}
	}
	d.audit(r, "user.delete", "user", id, "disconnected", n)
	writeJSON(w, http.StatusOK, map[string]int{"disconnected_agents": n})
}

func (d *Dashboard) releaseDomain(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.PathValue("hostname"))
	switch err := d.opts.Store.ReleaseDomain(r.Context(), host); {
	case errors.Is(err, postgres.ErrNotFound):
		writeErr(w, http.StatusConflict, "not_releasable", "no such reservation, or a tunnel is still connected to it")
		return
	case err != nil:
		d.internal(w, "release domain", err)
		return
	}
	d.audit(r, "domain.release", "hostname", host)
	w.WriteHeader(http.StatusNoContent)
}
