package dashboard

import (
	"context"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"

	mailer "github.com/tinoimammp/mancar/internal/mail"
	"github.com/tinoimammp/mancar/internal/store/postgres"
	"github.com/tinoimammp/mancar/internal/version"
)

// Sign in, sign up and email links (/api/v1/auth).
//
// Privacy: sign up, "send again" and "forgot password" answer exactly the
// same whether an address is registered or not. Only the owner of the
// address learns which, from the email they receive.

const (
	verifyLinkTTL = 24 * time.Hour
	resetLinkTTL  = time.Hour
	// UnconfirmedTTL is how long a web sign up may stay unconfirmed before
	// it is deleted.
	UnconfirmedTTL = 7 * 24 * time.Hour
	auditRetention = 365 * 24 * time.Hour
)

func (d *Dashboard) login(w http.ResponseWriter, r *http.Request) {
	if !d.sameOrigin(r) {
		writeErr(w, http.StatusForbidden, "csrf", "cross-site request refused")
		return
	}
	var in struct {
		Username string `json:"username"` // a username or an email address
		Password string `json:"password"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "expected JSON with username and password")
		return
	}
	login := strings.ToLower(strings.TrimSpace(in.Username))
	ip := d.client(r)
	if retry, blocked := d.byIP.Blocked(ip); blocked {
		d.tooMany(w, retry)
		return
	}
	if retry, blocked := d.byUser.Blocked(login); blocked {
		d.tooMany(w, retry)
		return
	}

	a, err := d.opts.Store.AccountByLogin(r.Context(), login)
	if err != nil && !errors.Is(err, postgres.ErrNotFound) {
		d.internal(w, "account lookup", err)
		return
	}
	hash := a.PasswordHash
	if err != nil || hash == "" {
		hash = dummyHash // equal work for unknown accounts and accounts without a password
	}
	ok, cerr := CheckPassword(hash, in.Password)
	if err != nil || a.PasswordHash == "" || cerr != nil || !ok {
		d.byIP.Fail(ip)
		d.byUser.Fail(login)
		d.log.Warn("dashboard login failed", "client", ip)
		writeErr(w, http.StatusUnauthorized, "invalid_credentials", "wrong username, email or password")
		return
	}
	// Only someone who knows the password learns the account is disabled.
	if a.DisabledAt != nil {
		writeErr(w, http.StatusForbidden, "account_disabled", "this account is disabled; contact the server admin")
		return
	}
	d.startSession(w, a)
	if err := d.opts.Store.TouchLogin(r.Context(), a.ID); err != nil {
		d.log.Warn("dashboard: recording login time failed", "err", err)
	}
	d.log.Info("dashboard login", "client", ip, "username", a.Username, "role", a.Role)
	writeJSON(w, http.StatusOK, sessionOut(a))
}

func sessionOut(a postgres.Account) map[string]any {
	return map[string]any{"username": a.Username, "role": a.Role, "email": a.Email, "email_verified": a.Verified()}
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
	writeJSON(w, http.StatusOK, sessionOut(accountFrom(r)))
}

// authOptions tells the sign in page what this gateway offers. setup is
// true while no admin exists: the page then asks for the first admin.
func (d *Dashboard) authOptions(w http.ResponseWriter, r *http.Request) {
	hasAdmin, err := d.opts.Store.AdminExists(r.Context())
	if err != nil {
		d.internal(w, "admin lookup", err)
		return
	}
	out := map[string]any{
		"setup":          !hasAdmin,
		"signup":         d.signupOpen(),
		"password_reset": d.opts.Mailer != nil,
	}
	// The version helps attackers, so it is only shown to whoever sets up a
	// fresh server, never once an admin exists.
	if !hasAdmin {
		out["version"] = version.Version
	}
	writeJSON(w, http.StatusOK, out)
}

// setup creates the first admin from the dashboard, then signs them in. It
// works only while no admin exists; afterwards it answers 404. Whoever opens
// a fresh gateway first becomes its admin, so do it right after deploying
// ("mancard user ..." on the server can always take it back).
func (d *Dashboard) setup(w http.ResponseWriter, r *http.Request) {
	if !d.sameOrigin(r) {
		writeErr(w, http.StatusForbidden, "csrf", "cross-site request refused")
		return
	}
	ip := d.client(r)
	if retry, blocked := d.byIP.Blocked(ip); blocked {
		d.tooMany(w, retry)
		return
	}
	var in struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "expected JSON with username, email and password")
		return
	}
	user := strings.ToLower(strings.TrimSpace(in.Username))
	email := postgres.NormalizeEmail(in.Email)
	switch {
	case !usernameRE.MatchString(user):
		writeErr(w, http.StatusBadRequest, "invalid_user", "username: 1-64 characters from a-z, 0-9, '.', '_' and '-'")
		return
	case email != "" && !validEmail(email):
		writeErr(w, http.StatusBadRequest, "invalid_email", "enter a valid email address, or leave it empty")
		return
	}
	hash, err := HashPassword(in.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "weak_password", err.Error())
		return
	}
	id, err := d.opts.Store.CreateFirstAdmin(r.Context(), postgres.NewAccount{Username: user, Email: email, PasswordHash: hash})
	switch {
	case errors.Is(err, postgres.ErrSetupDone):
		d.byIP.Fail(ip)
		writeErr(w, http.StatusNotFound, "setup_done", "this server already has an admin; sign in instead")
		return
	case errors.Is(err, postgres.ErrUsernameTaken):
		writeErr(w, http.StatusConflict, "username_taken", "that username is taken; choose another")
		return
	case err != nil:
		d.internal(w, "create first admin", err)
		return
	}
	a, err := d.opts.Store.AccountByID(r.Context(), id)
	if err != nil {
		d.internal(w, "account lookup", err)
		return
	}
	d.startSession(w, a)
	d.log.Warn("dashboard: first admin created from the web", "username", user, "client", ip)
	r = r.WithContext(context.WithValue(r.Context(), ctxAccount{}, a))
	d.audit(r, "setup.admin", user, "first admin, created from the dashboard")
	writeJSON(w, http.StatusCreated, sessionOut(a))
}

func (d *Dashboard) signupOpen() bool { return d.opts.RegisterEnabled && d.opts.Mailer != nil }

// validEmail accepts a plain address (no display name) of sane length.
func validEmail(e string) bool {
	if len(e) > 254 || strings.ContainsAny(e, " \t\r\n<>") {
		return false
	}
	a, err := mail.ParseAddress(e)
	return err == nil && a.Address == e && strings.Contains(e[strings.LastIndex(e, "@"):], ".")
}

// mailLimited counts one email-sending attempt from this client and for
// this address, and reports whether either is over its allowance.
func (d *Dashboard) mailLimited(w http.ResponseWriter, r *http.Request) bool {
	ip := d.client(r)
	if retry, blocked := d.mailByIP.Blocked(ip); blocked {
		d.tooMany(w, retry)
		return true
	}
	d.mailByIP.Fail(ip)
	return false
}

// addrAllowed reports whether another email may go to addr this hour; it
// does not answer differently, it just stops sending.
func (d *Dashboard) addrAllowed(addr string) bool {
	if _, blocked := d.mailByAddr.Blocked(addr); blocked {
		return false
	}
	d.mailByAddr.Fail(addr)
	return true
}

// link renders a dashboard link carrying a secret in the fragment, which
// browsers never send to a server or put in a Referer.
func (d *Dashboard) link(kind, secret string) string {
	return d.origin() + "/dashboard/#" + kind + "=" + secret
}

// send delivers an email in the background, so the answer to the request
// does not depend on whether (or how slowly) an email was sent.
func (d *Dashboard) send(to, subject, body string) {
	if d.opts.Mailer == nil {
		d.log.Warn("dashboard: an email was not sent: SMTP_URL is not set")
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := d.opts.Mailer.Send(ctx, mailer.Message{To: to, Subject: subject, Body: body}); err != nil {
			d.log.Error("dashboard: sending an email failed", "subject", subject, "err", err)
		}
	}()
}

func (d *Dashboard) sendVerify(ctx context.Context, a postgres.Account) error {
	secret, err := d.opts.Store.CreateEmailLink(ctx, a.ID, postgres.LinkVerify, verifyLinkTTL)
	if err != nil {
		return err
	}
	d.send(a.Email, "Confirm your email for mancar", "Hi "+a.Username+",\n\n"+
		"Confirm your email address to finish setting up your mancar account on "+d.opts.BaseDomain+":\n\n"+
		d.link("verify", secret)+"\n\n"+
		"The link works once, for 24 hours. If you did not sign up, ignore this email: "+
		"the account is deleted after 7 days.\n")
	return nil
}

func (d *Dashboard) sendReset(ctx context.Context, a postgres.Account) error {
	secret, err := d.opts.Store.CreateEmailLink(ctx, a.ID, postgres.LinkReset, resetLinkTTL)
	if err != nil {
		return err
	}
	d.send(a.Email, "Reset your mancar password", "Hi "+a.Username+",\n\n"+
		"Someone asked to reset the password of your mancar account on "+d.opts.BaseDomain+". "+
		"To choose a new password, open:\n\n"+d.link("reset", secret)+"\n\n"+
		"The link works once, for 1 hour. If it was not you, ignore this email: your password stays the same.\n")
	return nil
}

// signup creates an unconfirmed account and emails a confirmation link. An
// address that already has an account gets a notice instead, and the
// answer is the same either way.
func (d *Dashboard) signup(w http.ResponseWriter, r *http.Request) {
	if !d.signupOpen() {
		writeErr(w, http.StatusNotFound, "signup_disabled", "sign up is not open on this server")
		return
	}
	if !d.sameOrigin(r) {
		writeErr(w, http.StatusForbidden, "csrf", "cross-site request refused")
		return
	}
	var in struct {
		Email    string `json:"email"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "expected JSON with email, username and password")
		return
	}
	email := postgres.NormalizeEmail(in.Email)
	user := strings.ToLower(strings.TrimSpace(in.Username))
	switch {
	case !validEmail(email):
		writeErr(w, http.StatusBadRequest, "invalid_email", "enter a valid email address")
		return
	case !usernameRE.MatchString(user):
		writeErr(w, http.StatusBadRequest, "invalid_user", "username: 1-64 characters from a-z, 0-9, '.', '_' and '-'")
		return
	}
	if d.mailLimited(w, r) {
		return
	}
	hash, err := HashPassword(in.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "weak_password", err.Error())
		return
	}
	id, err := d.opts.Store.CreateAccount(r.Context(), postgres.NewAccount{
		Username: user, Email: email, PasswordHash: hash, Role: postgres.RoleUser, SignedUp: true,
	})
	switch {
	case errors.Is(err, postgres.ErrUsernameTaken):
		// usernames are public (they name tokens), so this is said plainly
		writeErr(w, http.StatusConflict, "username_taken", "that username is taken; choose another")
		return
	case errors.Is(err, postgres.ErrEmailTaken):
		if d.addrAllowed(email) {
			d.send(email, "Someone tried to sign up with your email", "Hi,\n\n"+
				"Someone tried to create a mancar account on "+d.opts.BaseDomain+" with this email address, "+
				"which already has an account.\n\nIf it was you, sign in instead, or reset your password at:\n\n"+
				d.origin()+"/dashboard/\n\nIf it was not you, you can ignore this email.\n")
		}
	case err != nil:
		d.internal(w, "create account", err)
		return
	default:
		a := postgres.Account{ID: id, Username: user, Email: email}
		if d.addrAllowed(email) {
			if err := d.sendVerify(r.Context(), a); err != nil {
				d.internal(w, "create link", err)
				return
			}
		}
		d.log.Info("dashboard sign up", "username", user, "client", d.client(r))
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"verify_email": true})
}

// verifyEmail consumes a confirmation link.
func (d *Dashboard) verifyEmail(w http.ResponseWriter, r *http.Request) {
	if !d.sameOrigin(r) {
		writeErr(w, http.StatusForbidden, "csrf", "cross-site request refused")
		return
	}
	var in struct {
		Token string `json:"token"`
	}
	if readJSON(r, &in) != nil || in.Token == "" || len(in.Token) > 128 {
		writeErr(w, http.StatusBadRequest, "bad_request", "expected JSON with token")
		return
	}
	ip := d.client(r)
	if retry, blocked := d.byIP.Blocked(ip); blocked {
		d.tooMany(w, retry)
		return
	}
	id, err := d.opts.Store.UseEmailLink(r.Context(), postgres.LinkVerify, in.Token)
	if errors.Is(err, postgres.ErrLinkInvalid) {
		d.byIP.Fail(ip)
		writeErr(w, http.StatusBadRequest, "link_invalid", "this link is invalid, already used or expired; sign in and ask for a new one")
		return
	}
	if err != nil {
		d.internal(w, "use link", err)
		return
	}
	if err := d.opts.Store.SetEmailVerified(r.Context(), id, true); err != nil {
		d.internal(w, "verify email", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"verified": true})
}

// resendPublic sends a new confirmation link to an unconfirmed address,
// answering the same for any address.
func (d *Dashboard) resendPublic(w http.ResponseWriter, r *http.Request) {
	d.byEmail(w, r, func(ctx context.Context, a postgres.Account) error {
		if a.Verified() {
			return nil
		}
		return d.sendVerify(ctx, a)
	})
}

// forgotPassword emails a reset link, answering the same for any address.
func (d *Dashboard) forgotPassword(w http.ResponseWriter, r *http.Request) {
	d.byEmail(w, r, func(ctx context.Context, a postgres.Account) error { return d.sendReset(ctx, a) })
}

// byEmail runs act for the active account with the posted email, if there
// is one, and answers 204 in every case.
func (d *Dashboard) byEmail(w http.ResponseWriter, r *http.Request, act func(context.Context, postgres.Account) error) {
	if d.opts.Mailer == nil {
		writeErr(w, http.StatusNotFound, "email_disabled", "this server cannot send email (SMTP_URL is not set)")
		return
	}
	if !d.sameOrigin(r) {
		writeErr(w, http.StatusForbidden, "csrf", "cross-site request refused")
		return
	}
	var in struct {
		Email string `json:"email"`
	}
	if readJSON(r, &in) != nil || !validEmail(postgres.NormalizeEmail(in.Email)) {
		writeErr(w, http.StatusBadRequest, "invalid_email", "enter a valid email address")
		return
	}
	if d.mailLimited(w, r) {
		return
	}
	email := postgres.NormalizeEmail(in.Email)
	a, err := d.opts.Store.AccountByEmail(r.Context(), email)
	switch {
	case errors.Is(err, postgres.ErrNotFound):
	case err != nil:
		d.internal(w, "account lookup", err)
		return
	case a.DisabledAt == nil && d.addrAllowed(email):
		if err := act(r.Context(), a); err != nil {
			d.internal(w, "create link", err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// resetPassword consumes a reset link and sets the new password. Opening
// the link proves the address, so it is confirmed as well.
func (d *Dashboard) resetPassword(w http.ResponseWriter, r *http.Request) {
	if !d.sameOrigin(r) {
		writeErr(w, http.StatusForbidden, "csrf", "cross-site request refused")
		return
	}
	var in struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if readJSON(r, &in) != nil || in.Token == "" || len(in.Token) > 128 {
		writeErr(w, http.StatusBadRequest, "bad_request", "expected JSON with token and password")
		return
	}
	hash, err := HashPassword(in.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "weak_password", err.Error())
		return
	}
	ip := d.client(r)
	if retry, blocked := d.byIP.Blocked(ip); blocked {
		d.tooMany(w, retry)
		return
	}
	id, err := d.opts.Store.UseEmailLink(r.Context(), postgres.LinkReset, in.Token)
	if errors.Is(err, postgres.ErrLinkInvalid) {
		d.byIP.Fail(ip)
		writeErr(w, http.StatusBadRequest, "link_invalid", "this link is invalid, already used or expired; ask for a new one")
		return
	}
	if err != nil {
		d.internal(w, "use link", err)
		return
	}
	if err := d.opts.Store.SetPassword(r.Context(), id, hash); err != nil {
		d.internal(w, "set password", err)
		return
	}
	if err := d.opts.Store.SetEmailVerified(r.Context(), id, true); err != nil {
		d.log.Warn("dashboard: confirming email after a reset failed", "err", err)
	}
	d.log.Info("dashboard password reset by email", "client", ip)
	w.WriteHeader(http.StatusNoContent)
}

// DropRevoked disconnects agents whose token no longer works: revoked,
// or the account disabled or deleted. The dashboard drops them at once
// itself; this catches changes made elsewhere (mancard CLI, another
// process). The server calls it every RevokeCheck.
func (d *Dashboard) DropRevoked(ctx context.Context) int {
	st, ok := d.opts.Store.(interface {
		UsableTokens(ctx context.Context, ids []string) (map[string]bool, error)
	})
	if !ok || d.opts.Hub == nil {
		return 0
	}
	var ids []string
	for _, s := range d.opts.Hub.Sessions() {
		if s.TokenID != "" {
			ids = append(ids, s.TokenID)
		}
	}
	if len(ids) == 0 {
		return 0
	}
	usable, err := st.UsableTokens(ctx, ids)
	if err != nil { // keep everyone connected when the check itself fails
		d.log.Warn("dashboard: checking connected tokens failed", "err", err)
		return 0
	}
	n := 0
	for _, s := range d.opts.Hub.Sessions() {
		if s.TokenID != "" && !usable[s.TokenID] && d.opts.Hub.Disconnect(s.ID) {
			d.log.Info("dashboard: disconnected an agent whose access was removed", "session", s.ID, "user", s.UserID)
			n++
		}
	}
	return n
}

// RevokeCheck is how often the server calls DropRevoked.
const RevokeCheck = 30 * time.Second

// Housekeeping deletes stale sign ups and old audit entries. The server
// calls it every hour.
func (d *Dashboard) Housekeeping(ctx context.Context) {
	if d.opts.Store == nil {
		return
	}
	now := d.opts.Now()
	if n, err := d.opts.Store.PurgeUnconfirmed(ctx, now.Add(-UnconfirmedTTL)); err != nil {
		d.log.Warn("dashboard: deleting unconfirmed sign ups failed", "err", err)
	} else if n > 0 {
		d.log.Info("dashboard: deleted unconfirmed sign ups", "count", n)
	}
	if err := d.opts.Store.PurgeAudit(ctx, now.Add(-auditRetention)); err != nil {
		d.log.Warn("dashboard: trimming the audit log failed", "err", err)
	}
}
