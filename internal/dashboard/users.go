package dashboard

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tinoimammp/mancar/internal/store/postgres"
)

// Account management for admins (/api/v1/admin/users, /api/v1/admin/audit).
//
// Guards: an admin cannot demote, disable or delete themselves, the last
// active admin is always kept (enforced in the database), and promoting
// someone to admin needs the acting admin's password.

type userOut struct {
	ID               string                `json:"id"`
	Username         string                `json:"username"`
	Email            string                `json:"email"`
	Role             string                `json:"role"`
	Status           string                `json:"status"` // active, unverified, disabled
	EmailVerified    bool                  `json:"email_verified"`
	HasPassword      bool                  `json:"has_password"`
	SignedUp         bool                  `json:"signed_up"`
	CreatedAt        time.Time             `json:"created_at"`
	LastLoginAt      *time.Time            `json:"last_login_at"`
	ActiveTokens     int                   `json:"active_tokens"`
	Domains          int                   `json:"domains"`
	CustomDomains    int                   `json:"custom_domains"`
	Agents           int                   `json:"connected_agents"`
	MaxTokens        *int                  `json:"max_tokens"`
	MaxCustomDomains *int                  `json:"max_custom_domains"`
	Usage            postgres.UsageWindows `json:"usage"`
}

func status(a postgres.Account) string {
	switch {
	case a.DisabledAt != nil:
		return "disabled"
	case !a.Verified():
		return "unverified"
	}
	return "active"
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
	out := []userOut{}
	for _, u := range users {
		out = append(out, userOut{
			ID: u.ID, Username: u.Username, Email: u.Email, Role: u.Role, Status: status(u.Account),
			EmailVerified: u.Verified(), HasPassword: u.PasswordHash != "", SignedUp: u.SignedUp,
			CreatedAt: u.CreatedAt, LastLoginAt: u.LastLoginAt, ActiveTokens: u.ActiveTokens,
			Domains: u.Domains, CustomDomains: u.CustomDomains, Agents: online[u.ID],
			MaxTokens: u.MaxTokens, MaxCustomDomains: u.MaxCustomDomains, Usage: traffic[u.ID],
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out, "email_enabled": d.opts.Mailer != nil})
}

// target loads the account named in the path, answering 404 if missing.
func (d *Dashboard) target(w http.ResponseWriter, r *http.Request) (postgres.Account, bool) {
	a, err := d.opts.Store.AccountByID(r.Context(), r.PathValue("id"))
	if errors.Is(err, postgres.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "no user with that ID")
		return a, false
	}
	if err != nil {
		d.internal(w, "account lookup", err)
		return a, false
	}
	return a, true
}

func (d *Dashboard) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "expected JSON with username, email, password and role")
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
	case in.Role != postgres.RoleAdmin && in.Role != postgres.RoleUser:
		writeErr(w, http.StatusBadRequest, "invalid_role", "role must be admin or user")
		return
	}
	hash, err := HashPassword(in.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "weak_password", err.Error())
		return
	}
	id, err := d.opts.Store.CreateAccount(r.Context(), postgres.NewAccount{
		Username: user, Email: email, PasswordHash: hash, Role: in.Role, Verified: true,
	})
	switch {
	case errors.Is(err, postgres.ErrUsernameTaken):
		writeErr(w, http.StatusConflict, "username_taken", "an account with that username already exists")
		return
	case errors.Is(err, postgres.ErrEmailTaken):
		writeErr(w, http.StatusConflict, "email_taken", "an account with that email already exists")
		return
	case err != nil:
		d.internal(w, "create account", err)
		return
	}
	d.audit(r, "user.create", user, "role "+in.Role)
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

// optInt distinguishes "not sent" from "null" (no limit) in a PATCH body.
type optInt struct {
	set bool
	v   *int
}

func (o *optInt) UnmarshalJSON(b []byte) error {
	o.set = true
	if string(b) == "null" {
		return nil
	}
	var n int
	if err := json.Unmarshal(b, &n); err != nil || n < 0 || n > 10_000 {
		return errors.New("a limit is a whole number from 0 to 10000, or null for no limit")
	}
	o.v = &n
	return nil
}

func (d *Dashboard) updateUser(w http.ResponseWriter, r *http.Request) {
	me := accountFrom(r)
	t, ok := d.target(w, r)
	if !ok {
		return
	}
	var in struct {
		Role             *string `json:"role"`
		Disabled         *bool   `json:"disabled"`
		EmailVerified    *bool   `json:"email_verified"`
		Email            *string `json:"email"`
		MaxTokens        optInt  `json:"max_tokens"`
		MaxCustomDomains optInt  `json:"max_custom_domains"`
		// ConfirmPassword is the acting admin's own password, needed to
		// make someone an admin.
		ConfirmPassword string `json:"confirm_password"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	self := t.ID == me.ID
	if self && (in.Role != nil || (in.Disabled != nil && *in.Disabled)) {
		writeErr(w, http.StatusConflict, "self", "you cannot change your own role or disable yourself")
		return
	}
	ctx := r.Context()
	fail := func(what string, err error) bool {
		switch {
		case err == nil:
			return false
		case errors.Is(err, postgres.ErrLastAdmin):
			writeErr(w, http.StatusConflict, "last_admin", "the server needs at least one active admin")
		case errors.Is(err, postgres.ErrEmailTaken):
			writeErr(w, http.StatusConflict, "email_taken", "an account with that email already exists")
		case errors.Is(err, postgres.ErrNotFound):
			writeErr(w, http.StatusNotFound, "not_found", "no user with that ID")
		default:
			d.internal(w, what, err)
		}
		return true
	}

	if in.Role != nil && *in.Role != t.Role {
		role := *in.Role
		if role != postgres.RoleAdmin && role != postgres.RoleUser {
			writeErr(w, http.StatusBadRequest, "invalid_role", "role must be admin or user")
			return
		}
		if role == postgres.RoleAdmin {
			if retry, blocked := d.byUser.Blocked(me.Username); blocked {
				d.tooMany(w, retry)
				return
			}
			if ok, _ := CheckPassword(me.PasswordHash, in.ConfirmPassword); !ok {
				d.byUser.Fail(me.Username)
				writeErr(w, http.StatusForbidden, "confirm_password", "enter your own password to make someone an admin")
				return
			}
		}
		if fail("set role", d.opts.Store.SetRole(ctx, t.ID, role)) {
			return
		}
		d.audit(r, "user.role", t.Username, t.Role+" → "+role)
	}
	if in.Disabled != nil && *in.Disabled != (t.DisabledAt != nil) {
		if fail("set disabled", d.opts.Store.SetDisabled(ctx, t.ID, *in.Disabled)) {
			return
		}
		if *in.Disabled {
			n := d.disconnectUser(t.ID)
			d.audit(r, "user.disable", t.Username, fmt.Sprintf("%d agent(s) disconnected", n))
		} else {
			d.audit(r, "user.enable", t.Username, "")
		}
	}
	if in.Email != nil && postgres.NormalizeEmail(*in.Email) != t.Email {
		email := postgres.NormalizeEmail(*in.Email)
		if email != "" && !validEmail(email) {
			writeErr(w, http.StatusBadRequest, "invalid_email", "enter a valid email address, or leave it empty")
			return
		}
		if fail("set email", d.opts.Store.SetEmail(ctx, t.ID, email)) {
			return
		}
		t.Email, t.EmailVerifiedAt = email, nil
		d.audit(r, "user.email", t.Username, "")
	}
	if in.EmailVerified != nil && *in.EmailVerified != (t.EmailVerifiedAt != nil) && t.Email != "" {
		if fail("set verified", d.opts.Store.SetEmailVerified(ctx, t.ID, *in.EmailVerified)) {
			return
		}
		d.audit(r, "user.verify", t.Username, fmt.Sprintf("email confirmed: %v", *in.EmailVerified))
	}
	if in.MaxTokens.set || in.MaxCustomDomains.set {
		maxTok, maxDom := t.MaxTokens, t.MaxCustomDomains
		if in.MaxTokens.set {
			maxTok = in.MaxTokens.v
		}
		if in.MaxCustomDomains.set {
			maxDom = in.MaxCustomDomains.v
		}
		if fail("set limits", d.opts.Store.SetLimits(ctx, t.ID, maxTok, maxDom)) {
			return
		}
		d.audit(r, "user.limits", t.Username, "tokens "+limitText(maxTok)+", custom subdomains "+limitText(maxDom))
	}
	w.WriteHeader(http.StatusNoContent)
}

func limitText(p *int) string {
	if p == nil {
		return "no limit"
	}
	return fmt.Sprint(*p)
}

func (d *Dashboard) deleteUser(w http.ResponseWriter, r *http.Request) {
	t, ok := d.target(w, r)
	if !ok {
		return
	}
	if t.ID == accountFrom(r).ID {
		writeErr(w, http.StatusConflict, "self", "you cannot delete your own account here; use Account")
		return
	}
	switch err := d.opts.Store.DeleteAccount(r.Context(), t.ID); {
	case errors.Is(err, postgres.ErrLastAdmin):
		writeErr(w, http.StatusConflict, "last_admin", "the server needs at least one active admin")
		return
	case errors.Is(err, postgres.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "no user with that ID")
		return
	case err != nil:
		d.internal(w, "delete user", err)
		return
	}
	n := d.disconnectUser(t.ID)
	d.audit(r, "user.delete", t.Username, fmt.Sprintf("%d agent(s) disconnected", n))
	writeJSON(w, http.StatusOK, map[string]int{"disconnected_agents": n})
}

func (d *Dashboard) revokeUserTokens(w http.ResponseWriter, r *http.Request) {
	t, ok := d.target(w, r)
	if !ok {
		return
	}
	ids, err := d.opts.Store.RevokeUserTokens(r.Context(), t.ID)
	if err != nil {
		d.internal(w, "revoke tokens", err)
		return
	}
	n := 0
	for _, id := range ids {
		n += d.opts.Hub.DisconnectToken(id)
	}
	d.audit(r, "user.revoke_tokens", t.Username, fmt.Sprintf("%d token(s), %d agent(s) disconnected", len(ids), n))
	writeJSON(w, http.StatusOK, map[string]int{"revoked": len(ids), "disconnected_agents": n})
}

// adminResetPassword emails a reset link (mode "email") or sets a random
// temporary password shown once to the admin (mode "temporary"). Either way
// the account's sessions end.
func (d *Dashboard) adminResetPassword(w http.ResponseWriter, r *http.Request) {
	t, ok := d.target(w, r)
	if !ok {
		return
	}
	var in struct {
		Mode string `json:"mode"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "expected JSON with mode")
		return
	}
	switch in.Mode {
	case "email":
		if d.opts.Mailer == nil || t.Email == "" {
			writeErr(w, http.StatusConflict, "email_unavailable", "this account has no email, or the server cannot send email; use a temporary password")
			return
		}
		if err := d.sendReset(r.Context(), t); err != nil {
			d.internal(w, "create link", err)
			return
		}
		d.audit(r, "user.reset_password", t.Username, "link emailed")
		w.WriteHeader(http.StatusNoContent)
	case "temporary":
		b := make([]byte, 15)
		if _, err := rand.Read(b); err != nil {
			d.internal(w, "random", err)
			return
		}
		pw := base64.RawURLEncoding.EncodeToString(b) // 20 characters
		hash, err := HashPassword(pw)
		if err != nil {
			d.internal(w, "hash", err)
			return
		}
		if err := d.opts.Store.SetPassword(r.Context(), t.ID, hash); err != nil {
			d.internal(w, "set password", err)
			return
		}
		d.audit(r, "user.reset_password", t.Username, "temporary password")
		writeJSON(w, http.StatusOK, map[string]string{"password": pw})
	default:
		writeErr(w, http.StatusBadRequest, "bad_request", "mode must be email or temporary")
	}
}

func (d *Dashboard) adminResendVerification(w http.ResponseWriter, r *http.Request) {
	t, ok := d.target(w, r)
	if !ok {
		return
	}
	switch {
	case t.Email == "" || t.Verified():
		writeErr(w, http.StatusConflict, "nothing_to_confirm", "this account has no unconfirmed email")
		return
	case d.opts.Mailer == nil:
		writeErr(w, http.StatusConflict, "email_disabled", "the server cannot send email (SMTP_URL is not set)")
		return
	}
	if err := d.sendVerify(r.Context(), t); err != nil {
		d.internal(w, "create link", err)
		return
	}
	d.audit(r, "user.resend_verification", t.Username, "")
	w.WriteHeader(http.StatusNoContent)
}

func (d *Dashboard) auditLog(w http.ResponseWriter, r *http.Request) {
	list, err := d.opts.Store.ListAudit(r.Context(), 300)
	if err != nil {
		d.internal(w, "list audit", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": list})
}
