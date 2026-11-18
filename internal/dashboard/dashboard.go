// Package dashboard serves the web dashboard and its JSON API on the base
// domain: /dashboard/ (static single-page app, embedded in the binary),
// /api/v1/auth/* (sign in, sign up, email links), /api/v1/admin/* (the
// whole gateway, admins only) and /api/v1/me/* (a signed-in account's own
// tunnels, tokens and requests).
//
// Security model:
//   - Accounts sign in with a username or email and a password
//     (PBKDF2-SHA256). Admins are made with "mancard user create NAME --admin" or promoted
//     in the dashboard; users are made by an admin or by web sign up
//     (REGISTER_ENABLED), which confirms the email address first.
//   - The session is an HMAC-signed cookie (HttpOnly, SameSite=Strict, Secure
//     over HTTPS) re-validated against the database on every request: the
//     role, a disabled flag and a password change take effect at once.
//   - Every /me endpoint works on the signed-in account only; the account is
//     never taken from the request. /admin endpoints refuse non-admins.
//   - State-changing requests must carry the X-Mancar-CSRF header and, when the
//     browser sends one, an Origin of the dashboard itself. Together with
//     SameSite=Strict this blocks cross-site request forgery.
//   - Sign up, "forgot password" and "send again" answer the same whether an
//     address is registered or not; the difference only shows in the email
//     its owner receives. Failed logins and email sending are rate limited.
//   - Agent token secrets are shown exactly once, in the create response.
package dashboard

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
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

	"github.com/tinoimammp/mancar/internal/access"
	"github.com/tinoimammp/mancar/internal/gateway"
	"github.com/tinoimammp/mancar/internal/inspect"
	"github.com/tinoimammp/mancar/internal/mail"
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
	AccountByID(ctx context.Context, id string) (postgres.Account, error)
	AccountByLogin(ctx context.Context, login string) (postgres.Account, error)
	AccountByEmail(ctx context.Context, email string) (postgres.Account, error)
	TouchLogin(ctx context.Context, id string) error
	CreateAccount(ctx context.Context, n postgres.NewAccount) (string, error)
	SetupDone(ctx context.Context) (bool, error)
	CreateFirstAdmin(ctx context.Context, n postgres.NewAccount) (string, error)
	SetPassword(ctx context.Context, id, hash string) error
	EndSessions(ctx context.Context, id string) error
	SetEmailVerified(ctx context.Context, id string, verified bool) error
	SetEmail(ctx context.Context, id, email string) error
	SetLimits(ctx context.Context, id string, maxTokens, maxCustomDomains *int) error
	SetRole(ctx context.Context, id, role string) error
	SetDisabled(ctx context.Context, id string, disabled bool) error
	DeleteAccount(ctx context.Context, id string) error
	CreateEmailLink(ctx context.Context, userID, purpose string, ttl time.Duration) (string, error)
	UseEmailLink(ctx context.Context, purpose, secret string) (string, error)
	PurgeUnconfirmed(ctx context.Context, olderThan time.Time) (int64, error)
	AddAudit(ctx context.Context, e postgres.AuditEntry) error
	ListAudit(ctx context.Context, limit int) ([]postgres.AuditEntry, error)
	PurgeAudit(ctx context.Context, before time.Time) error

	ListUsers(ctx context.Context) ([]postgres.UserInfo, error)
	EnsureUser(ctx context.Context, username string) (string, error)

	ListAgentTokens(ctx context.Context) ([]postgres.TokenInfo, error)
	CreateAgentToken(ctx context.Context, userID, name string) (plaintext, id string, err error)
	RevokeAgentToken(ctx context.Context, id string) error
	RevokeUserTokens(ctx context.Context, userID string) ([]string, error)

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
	// Mailer sends email links; nil turns sign up and "forgot password" off.
	Mailer mail.Sender
	// RegisterEnabled opens web sign up (REGISTER_ENABLED; needs Mailer).
	RegisterEnabled bool
	// MaxTunnels is how many tunnels one account can have open at once
	// (MAX_AGENTS_PER_USER x MAX_TUNNELS_PER_AGENT), shown to users.
	MaxTunnels int
	// Access issues tickets into private tunnels; nil when they are off.
	Access *access.Keeper
}

// Dashboard is an http.Handler for /dashboard/ and /api/v1/admin/.
type Dashboard struct {
	opts   Options
	log    *slog.Logger
	signer signer
	cookie string
	byIP   *ratelimit.FailureLimiter
	byUser *ratelimit.FailureLimiter
	// mailByIP and mailByAddr bound the emails one client can make the
	// gateway send (sign up, send again, forgot password), so it can be used
	// neither to spam an address nor to probe many.
	mailByIP   *ratelimit.FailureLimiter
	mailByAddr *ratelimit.FailureLimiter
	// device login ("mancar login"): pending requests, and a bound on how
	// many one client may start
	devices    *deviceFlows
	deviceByIP *ratelimit.FailureLimiter
	mux        *http.ServeMux
	startedAt  time.Time
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
		byIP:       ratelimit.NewFailureLimiter(10, 15*time.Minute),
		byUser:     ratelimit.NewFailureLimiter(10, 15*time.Minute),
		mailByIP:   ratelimit.NewFailureLimiter(5, time.Hour),
		mailByAddr: ratelimit.NewFailureLimiter(3, time.Hour),
		devices:    newDeviceFlows(),
		deviceByIP: ratelimit.NewFailureLimiter(20, time.Hour),
		mux:        http.NewServeMux(),
		startedAt:  opts.Now(),
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

	// sign in, sign up, email links (the old /api/v1/admin paths still work)
	for _, base := range []string{"/api/v1/auth", "/api/v1/admin"} {
		d.mux.HandleFunc("POST "+base+"/login", d.login)
		d.mux.HandleFunc("POST "+base+"/logout", d.logout)
		d.mux.HandleFunc("GET "+base+"/session", d.authed(false, d.session))
	}
	d.mux.HandleFunc("GET /api/v1/auth/options", d.authOptions)
	d.mux.HandleFunc("POST /api/v1/auth/setup", d.setup)
	d.mux.HandleFunc("POST /api/v1/auth/device", d.deviceStart)
	d.mux.HandleFunc("POST /api/v1/auth/device/token", d.deviceToken)
	d.mux.HandleFunc("POST /api/v1/auth/signup", d.signup)
	d.mux.HandleFunc("POST /api/v1/auth/signup/verify", d.verifyEmail)
	d.mux.HandleFunc("POST /api/v1/auth/signup/resend", d.resendPublic)
	d.mux.HandleFunc("POST /api/v1/auth/password/forgot", d.forgotPassword)
	d.mux.HandleFunc("POST /api/v1/auth/password/reset", d.resetPassword)

	// the whole gateway: admins only
	admin := func(pattern string, h http.HandlerFunc) { d.mux.HandleFunc(pattern, d.authed(true, h)) }
	admin("GET /api/v1/admin/overview", d.overview)
	admin("GET /api/v1/admin/agents", d.agents)
	admin("POST /api/v1/admin/agents/{id}/disconnect", d.disconnectAgent)
	admin("GET /api/v1/admin/users", d.users)
	admin("POST /api/v1/admin/users", d.createUser)
	admin("PATCH /api/v1/admin/users/{id}", d.updateUser)
	admin("DELETE /api/v1/admin/users/{id}", d.deleteUser)
	admin("POST /api/v1/admin/users/{id}/revoke-tokens", d.revokeUserTokens)
	admin("POST /api/v1/admin/users/{id}/reset-password", d.adminResetPassword)
	admin("POST /api/v1/admin/users/{id}/resend-verification", d.adminResendVerification)
	admin("GET /api/v1/admin/audit", d.auditLog)
	admin("GET /api/v1/admin/tokens", d.tokens)
	admin("POST /api/v1/admin/tokens", d.createToken)
	admin("POST /api/v1/admin/tokens/{id}/revoke", d.revokeToken)
	admin("GET /api/v1/admin/domains", d.domains)
	admin("DELETE /api/v1/admin/domains/{hostname}", d.releaseDomain)
	admin("GET /api/v1/admin/requests", d.listRequests)
	admin("DELETE /api/v1/admin/requests", d.clearRequests)
	admin("GET /api/v1/admin/requests/{id}", d.getRequest)
	admin("POST /api/v1/admin/requests/{id}/replay", d.replayRequest)

	// the signed-in account's own things (any role)
	me := func(pattern string, h http.HandlerFunc) { d.mux.HandleFunc(pattern, d.authed(false, mine(h))) }
	me("GET /api/v1/me/overview", d.myOverview)
	me("GET /api/v1/me/tokens", d.myTokens)
	me("POST /api/v1/me/tokens", d.myCreateToken)
	me("POST /api/v1/me/tokens/{id}/revoke", d.myRevokeToken)
	me("DELETE /api/v1/me/domains/{hostname}", d.myReleaseDomain)
	me("GET /api/v1/me/requests", d.listRequests)
	me("DELETE /api/v1/me/requests", d.clearRequests)
	me("GET /api/v1/me/requests/{id}", d.getRequest)
	me("POST /api/v1/me/requests/{id}/replay", d.replayRequest)
	me("GET /api/v1/me/account", d.myAccount)
	me("POST /api/v1/me/account/password", d.myChangePassword)
	me("POST /api/v1/me/account/verify/resend", d.myResendVerification)
	me("DELETE /api/v1/me/account", d.myDeleteAccount)
	me("GET /api/v1/me/device/{code}", d.myDevice)
	me("POST /api/v1/me/device/{code}/approve", d.myDeviceApprove)
	me("POST /api/v1/me/device/{code}/deny", d.myDeviceDeny)
	me("POST /api/v1/me/access", d.myAccess)

	for _, p := range []string{"/api/v1/admin/", "/api/v1/auth/", "/api/v1/me/"} {
		d.mux.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) {
			writeErr(w, http.StatusNotFound, "not_found", "no such endpoint")
		})
	}
	return d
}

func (d *Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Dashboard requests are small JSON: a client that sends its body slowly
	// is cut off instead of holding a connection forever. (Tunnel traffic
	// has no such limit: uploads through a tunnel may take long.)
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(30 * time.Second))
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

// origin is the dashboard's own origin, e.g. https://tunnel.example.com.
func (d *Dashboard) origin() string {
	o := d.opts.PublicScheme + "://" + d.opts.BaseDomain
	if d.opts.PublicPort != "" {
		o += ":" + d.opts.PublicPort
	}
	return o
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
	return o == "" || strings.EqualFold(o, d.origin())
}

func (d *Dashboard) client(r *http.Request) string {
	return netutil.ClientFromRequest(r, d.opts.TrustedProxies).IP
}

// rateKey is the client address for rate limits: an IPv6 address counts
// as its /64, which one customer usually holds whole (otherwise a single
// connection could rotate through 2^64 addresses and never be limited).
func (d *Dashboard) rateKey(r *http.Request) string {
	ip := d.client(r)
	if a, err := netip.ParseAddr(ip); err == nil && a.Is6() && !a.Is4In6() {
		if p, err := a.Prefix(64); err == nil {
			return p.String()
		}
	}
	return ip
}

type ctxAccount struct{}

// authed wraps a handler with session validation (and the CSRF check for
// anything that is not a GET). The account is read from the database on
// every request, so a new role, a disabled flag or a password change apply
// at once. adminOnly refuses users.
func (d *Dashboard) authed(adminOnly bool, next http.HandlerFunc) http.HandlerFunc {
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
		a, err := d.opts.Store.AccountByID(r.Context(), c.ID)
		if errors.Is(err, postgres.ErrNotFound) || (err == nil && (c.IssuedMs < a.PasswordChangedAt.UnixMilli() || a.DisabledAt != nil)) {
			d.clearCookie(w)
			writeErr(w, http.StatusUnauthorized, "unauthenticated", "session is no longer valid, please log in again")
			return
		}
		if err != nil {
			d.internal(w, "session lookup", err)
			return
		}
		if adminOnly && !a.IsAdmin() {
			writeErr(w, http.StatusForbidden, "forbidden", "this needs an admin account")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxAccount{}, a)))
	}
}

// accountFrom returns the signed-in account (set by authed).
func accountFrom(r *http.Request) postgres.Account {
	a, _ := r.Context().Value(ctxAccount{}).(postgres.Account)
	return a
}

type ctxMine struct{}

// mine marks a request as scoped to the signed-in account: shared handlers
// (the request inspector) then only see that account's data.
func mine(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		next(w, r.WithContext(context.WithValue(r.Context(), ctxMine{}, true)))
	}
}

// scopeUser is the account a request is limited to, or "" for the whole
// gateway (an admin endpoint).
func scopeUser(r *http.Request) string {
	if v, _ := r.Context().Value(ctxMine{}).(bool); v {
		return accountFrom(r).ID
	}
	return ""
}

func (d *Dashboard) setCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: d.cookie, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: d.opts.Secure, SameSite: http.SameSiteStrictMode,
	})
}

func (d *Dashboard) clearCookie(w http.ResponseWriter) { d.setCookie(w, "", -1) }

// startSession sets a session cookie for a. It is issued no earlier than
// the account's last password change, so a session made right after a
// change is valid even when the database clock runs a little ahead.
func (d *Dashboard) startSession(w http.ResponseWriter, a postgres.Account) {
	now := d.opts.Now()
	issued := now.UnixMilli()
	if pc := a.PasswordChangedAt.UnixMilli(); pc >= issued {
		issued = pc + 1
	}
	value := d.signer.sign(claims{ID: a.ID, Username: a.Username, IssuedMs: issued, Expires: now.Add(d.opts.SessionTTL).Unix()})
	d.setCookie(w, value, int(d.opts.SessionTTL/time.Second))
}

func (d *Dashboard) tooMany(w http.ResponseWriter, retry time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(retry/time.Second)+1))
	writeErr(w, http.StatusTooManyRequests, "too_many_attempts", "too many attempts; try again later")
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

// audit records an action in the log and the audit log (shown to admins).
func (d *Dashboard) audit(r *http.Request, action, target, detail string) {
	actor := accountFrom(r).Username
	d.log.Info("dashboard action", "action", action, "actor", actor, "target", target, "detail", detail, "client", d.client(r))
	if err := d.opts.Store.AddAudit(r.Context(), postgres.AuditEntry{Actor: actor, Action: action, Target: target, Detail: detail}); err != nil {
		d.log.Warn("dashboard: writing the audit log failed", "err", err)
	}
}

func (d *Dashboard) disconnectAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !d.opts.Hub.Disconnect(id) {
		writeErr(w, http.StatusNotFound, "not_found", "no connected agent with that ID")
		return
	}
	d.audit(r, "agent.disconnect", id, "")
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
	d.audit(r, "token.create", user, name)
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
	d.audit(r, "token.revoke", id, fmt.Sprintf("%d agent(s) disconnected", n))
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
	d.audit(r, "domain.release", host, "")
	w.WriteHeader(http.StatusNoContent)
}
