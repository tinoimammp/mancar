package dashboard_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tinoimammp/mancar/internal/access"
	"github.com/tinoimammp/mancar/internal/dashboard"
	"github.com/tinoimammp/mancar/internal/gateway"
	"github.com/tinoimammp/mancar/internal/store/postgres"
)

// setupAccounts is a gateway with sign up open, an admin "root" and a
// confirmed user "tino".
func setupAccounts(t *testing.T) (*dashboard.Dashboard, *fakeStore, *fakeMailer) {
	t.Helper()
	hash, err := dashboard.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	st := newFakeStore()
	past := time.Now().Add(-time.Hour)
	st.add(postgres.Account{ID: "a1", Username: "root", Role: postgres.RoleAdmin, PasswordHash: hash, PasswordChangedAt: past})
	three := 3
	st.add(postgres.Account{ID: "u-tino", Username: "tino", Email: "tino@example.com", EmailVerifiedAt: &past,
		PasswordHash: hash, PasswordChangedAt: past, MaxTokens: &three, MaxCustomDomains: &three})
	m := &fakeMailer{}
	d := dashboard.New(dashboard.Options{
		Store: st, Hub: &fakeHub{}, SessionSecret: strings.Repeat("s", 32), Secure: true,
		BaseDomain: "tunnel.example.com", PublicScheme: "https", Mailer: m, RegisterEnabled: true, MaxTunnels: 10,
	})
	return d, st, m
}

func loginAs(t *testing.T, d http.Handler, login, pw string) *http.Cookie {
	t.Helper()
	rec := do(d, req{method: "POST", path: "/api/v1/auth/login", body: `{"username":"` + login + `","password":"` + pw + `"}`, csrf: true})
	if rec.Code != http.StatusOK {
		t.Fatalf("login %s: %d %s", login, rec.Code, rec.Body)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-mancar_session" {
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

// linkSecret pulls the secret out of a "#verify=" or "#reset=" link.
func linkSecret(t *testing.T, body, kind string) string {
	t.Helper()
	i := strings.Index(body, "#"+kind+"=")
	if i < 0 {
		t.Fatalf("no %s link in:\n%s", kind, body)
	}
	rest := body[i+len(kind)+2:]
	if j := strings.IndexAny(rest, "\n "); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

func TestSignupClosedByDefault(t *testing.T) {
	d, _, _ := setup(t)
	rec := do(d, req{method: "POST", path: "/api/v1/auth/signup", body: `{"email":"a@example.com","username":"a","password":"` + password + `"}`, csrf: true})
	if rec.Code != http.StatusNotFound {
		t.Errorf("sign up on a closed gateway: %d", rec.Code)
	}
	opts := do(d, req{method: "GET", path: "/api/v1/auth/options"})
	if !strings.Contains(opts.Body.String(), `"signup":false`) {
		t.Errorf("options: %s", opts.Body)
	}
}

func TestSignupConfirmAndPrivacy(t *testing.T) {
	d, st, m := setupAccounts(t)
	signup := func(email, user string) *httpResult {
		rec := do(d, req{method: "POST", path: "/api/v1/auth/signup", csrf: true,
			body: `{"email":"` + email + `","username":"` + user + `","password":"` + password + `"}`})
		return &httpResult{rec.Code, rec.Body.String()}
	}

	fresh := signup("New@Example.com", "newbie")
	if fresh.code != http.StatusAccepted {
		t.Fatalf("sign up: %d %s", fresh.code, fresh.body)
	}
	// an address that already has an account gets exactly the same answer
	taken := signup("tino@example.com", "someone")
	if taken.code != fresh.code || taken.body != fresh.body {
		t.Errorf("registered email answers differently: %d %q vs %d %q", taken.code, taken.body, fresh.code, fresh.body)
	}
	sent := m.wait(2)
	if len(sent) != 2 {
		t.Fatalf("sent %d emails, want 2", len(sent))
	}
	var verify, notice string
	for _, msg := range sent {
		switch msg.To {
		case "new@example.com":
			verify = msg.Body
		case "tino@example.com":
			notice = msg.Body
		}
	}
	if !strings.Contains(notice, "already has an account") || strings.Contains(notice, "#verify=") {
		t.Errorf("notice to the existing owner: %q", notice)
	}
	if !strings.HasPrefix(verify[strings.Index(verify, "https://"):], "https://tunnel.example.com/dashboard/#verify=") {
		t.Errorf("verify link: %q", verify)
	}

	// usernames are public: a taken one is said plainly
	if r := signup("x@example.com", "tino"); r.code != http.StatusConflict || !strings.Contains(r.body, "username_taken") {
		t.Errorf("taken username: %d %s", r.code, r.body)
	}
	if r := signup("not-an-email", "x1"); r.code != http.StatusBadRequest {
		t.Errorf("bad email: %d", r.code)
	}

	// unconfirmed: can sign in, cannot make tokens
	c := loginAs(t, d, "new@example.com", password)
	if rec := do(d, req{method: "POST", path: "/api/v1/me/tokens", body: `{"name":"x"}`, cookie: c, csrf: true}); rec.Code != http.StatusForbidden {
		t.Errorf("token before confirming: %d %s", rec.Code, rec.Body)
	}
	secret := linkSecret(t, verify, "verify")
	if rec := do(d, req{method: "POST", path: "/api/v1/auth/signup/verify", body: `{"token":"` + secret + `"}`, csrf: true}); rec.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body)
	}
	if rec := do(d, req{method: "POST", path: "/api/v1/auth/signup/verify", body: `{"token":"` + secret + `"}`, csrf: true}); rec.Code != http.StatusBadRequest {
		t.Errorf("link used twice: %d", rec.Code)
	}
	for i := 0; i < postgres.SignupMaxTokens; i++ {
		if rec := do(d, req{method: "POST", path: "/api/v1/me/tokens", body: `{"name":"t"}`, cookie: c, csrf: true}); rec.Code != http.StatusCreated {
			t.Fatalf("token %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	if rec := do(d, req{method: "POST", path: "/api/v1/me/tokens", body: `{"name":"t"}`, cookie: c, csrf: true}); rec.Code != http.StatusConflict {
		t.Errorf("token over the limit: %d", rec.Code)
	}
	a, _ := st.AccountByLogin(t.Context(), "newbie")
	for _, tok := range st.tokens {
		if tok.UserID != a.ID {
			t.Errorf("token made for someone else: %+v", tok)
		}
	}
}

type httpResult struct {
	code int
	body string
}

func TestForgotPasswordAnswersTheSame(t *testing.T) {
	d, _, m := setupAccounts(t)
	forgot := func(email string) (int, string) {
		rec := do(d, req{method: "POST", path: "/api/v1/auth/password/forgot", body: `{"email":"` + email + `"}`, csrf: true})
		return rec.Code, rec.Body.String()
	}
	c1, b1 := forgot("nobody@example.com")
	c2, b2 := forgot("tino@example.com")
	if c1 != http.StatusNoContent || c1 != c2 || b1 != b2 {
		t.Errorf("unknown vs known address: %d %q / %d %q", c1, b1, c2, b2)
	}
	sent := m.wait(1)
	if len(sent) != 1 || sent[0].To != "tino@example.com" {
		t.Fatalf("emails: %+v", sent)
	}
	old := loginAs(t, d, "tino", password)
	secret := linkSecret(t, sent[0].Body, "reset")
	newPW := "a brand new passphrase"
	if rec := do(d, req{method: "POST", path: "/api/v1/auth/password/reset", body: `{"token":"` + secret + `","password":"` + newPW + `"}`, csrf: true}); rec.Code != http.StatusNoContent {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body)
	}
	if rec := do(d, req{method: "GET", path: "/api/v1/auth/session", cookie: old}); rec.Code != http.StatusUnauthorized {
		t.Errorf("old session survived a reset: %d", rec.Code)
	}
	loginAs(t, d, "tino@example.com", newPW)
}

func TestUsersCannotUseAdminEndpoints(t *testing.T) {
	d, _, _ := setupAccounts(t)
	c := loginAs(t, d, "tino", password)
	for _, p := range []string{"/api/v1/admin/users", "/api/v1/admin/tokens", "/api/v1/admin/requests", "/api/v1/admin/audit"} {
		if rec := do(d, req{method: "GET", path: p, cookie: c}); rec.Code != http.StatusForbidden {
			t.Errorf("user on %s: %d", p, rec.Code)
		}
	}
	rec := do(d, req{method: "GET", path: "/api/v1/auth/session", cookie: c})
	if !strings.Contains(rec.Body.String(), `"role":"user"`) {
		t.Errorf("session: %s", rec.Body)
	}
}

func TestUsersSeeOnlyTheirOwnTokens(t *testing.T) {
	d, st, _ := setupAccounts(t)
	st.CreateAgentToken(t.Context(), "a1", "root-laptop")
	c := loginAs(t, d, "tino", password)
	list := do(d, req{method: "GET", path: "/api/v1/me/tokens", cookie: c})
	if strings.Contains(list.Body.String(), "root-laptop") {
		t.Error("a user sees another account's token")
	}
	if rec := do(d, req{method: "POST", path: "/api/v1/me/tokens/t1/revoke", cookie: c, csrf: true}); rec.Code != http.StatusNotFound {
		t.Errorf("revoking someone else's token: %d", rec.Code)
	}
	// the user field is ignored: a token is always the signed-in account's
	rec := do(d, req{method: "POST", path: "/api/v1/me/tokens", body: `{"user":"root","name":"sneaky"}`, cookie: c, csrf: true})
	var out map[string]string
	json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusCreated || out["user"] != "tino" {
		t.Errorf("create with a foreign user: %d %s", rec.Code, rec.Body)
	}
}

func TestDisabledAccount(t *testing.T) {
	d, st, _ := setupAccounts(t)
	c := loginAs(t, d, "tino", password)
	st.SetDisabled(t.Context(), "u-tino", true)
	if rec := do(d, req{method: "GET", path: "/api/v1/me/account", cookie: c}); rec.Code != http.StatusUnauthorized {
		t.Errorf("session of a disabled account: %d", rec.Code)
	}
	if rec := do(d, req{method: "POST", path: "/api/v1/auth/login", body: `{"username":"tino","password":"wrong wrong wrong"}`, csrf: true}); rec.Code != http.StatusUnauthorized {
		t.Errorf("disabled + wrong password must look like any wrong password: %d", rec.Code)
	}
	if rec := do(d, req{method: "POST", path: "/api/v1/auth/login", body: `{"username":"tino","password":"` + password + `"}`, csrf: true}); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "account_disabled") {
		t.Errorf("disabled + right password: %d %s", rec.Code, rec.Body)
	}
}

func TestAdminRoleGuards(t *testing.T) {
	d, st, _ := setupAccounts(t)
	c := loginAs(t, d, "root", password)
	patch := func(id, body string) (int, string) {
		rec := do(d, req{method: "PATCH", path: "/api/v1/admin/users/" + id, body: body, cookie: c, csrf: true})
		return rec.Code, rec.Body.String()
	}
	if code, _ := patch("a1", `{"role":"user"}`); code != http.StatusConflict {
		t.Errorf("demoting yourself: %d", code)
	}
	if code, _ := patch("a1", `{"disabled":true}`); code != http.StatusConflict {
		t.Errorf("disabling yourself: %d", code)
	}
	if code, body := patch("u-tino", `{"role":"admin"}`); code != http.StatusForbidden || !strings.Contains(body, "confirm_password") {
		t.Errorf("promotion without the admin's password: %d %s", code, body)
	}
	if code, body := patch("u-tino", `{"role":"admin","confirm_password":"`+password+`"}`); code != http.StatusNoContent {
		t.Fatalf("promotion: %d %s", code, body)
	}
	if a, _ := st.AccountByID(t.Context(), "u-tino"); !a.IsAdmin() {
		t.Error("tino not promoted")
	}
	// the change applies to tino's existing session at once
	tc := loginAs(t, d, "tino", password)
	if rec := do(d, req{method: "GET", path: "/api/v1/admin/users", cookie: tc}); rec.Code != http.StatusOK {
		t.Errorf("new admin: %d", rec.Code)
	}
	if code, _ := patch("u-tino", `{"role":"user"}`); code != http.StatusNoContent {
		t.Errorf("demotion: %d", code)
	}
	if rec := do(d, req{method: "GET", path: "/api/v1/admin/users", cookie: tc}); rec.Code != http.StatusForbidden {
		t.Errorf("demoted admin still has access: %d", rec.Code)
	}
	if code, body := patch("u-tino", `{"max_tokens":null,"max_custom_domains":5}`); code != http.StatusNoContent {
		t.Errorf("limits: %d %s", code, body)
	}
	if a, _ := st.AccountByID(t.Context(), "u-tino"); a.MaxTokens != nil || a.MaxCustomDomains == nil || *a.MaxCustomDomains != 5 {
		t.Errorf("limits not saved: %+v", a)
	}
	if code, _ := patch("u-tino", `{"max_tokens":-1}`); code != http.StatusBadRequest {
		t.Errorf("negative limit: %d", code)
	}
	if rec := do(d, req{method: "DELETE", path: "/api/v1/admin/users/a1", cookie: c, csrf: true}); rec.Code != http.StatusConflict {
		t.Errorf("deleting yourself: %d", rec.Code)
	}
	audit := do(d, req{method: "GET", path: "/api/v1/admin/audit", cookie: c}).Body.String()
	for _, want := range []string{"user.role", "user → admin", "user.limits"} {
		if !strings.Contains(audit, want) {
			t.Errorf("audit log lacks %q: %s", want, audit)
		}
	}
}

func TestAdminTemporaryPassword(t *testing.T) {
	d, _, _ := setupAccounts(t)
	c := loginAs(t, d, "root", password)
	old := loginAs(t, d, "tino", password)
	rec := do(d, req{method: "POST", path: "/api/v1/admin/users/u-tino/reset-password", body: `{"mode":"temporary"}`, cookie: c, csrf: true})
	var out map[string]string
	json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK || len(out["password"]) < dashboard.MinPasswordLength {
		t.Fatalf("temporary password: %d %s", rec.Code, rec.Body)
	}
	if rec := do(d, req{method: "GET", path: "/api/v1/me/account", cookie: old}); rec.Code != http.StatusUnauthorized {
		t.Errorf("old session survived: %d", rec.Code)
	}
	loginAs(t, d, "tino", out["password"])
}

func TestAdminCreatesUser(t *testing.T) {
	d, st, _ := setupAccounts(t)
	c := loginAs(t, d, "root", password)
	body := `{"username":"rina","email":"rina@example.com","password":"` + password + `","role":"user"}`
	if rec := do(d, req{method: "POST", path: "/api/v1/admin/users", body: body, cookie: c, csrf: true}); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if a, _ := st.AccountByLogin(t.Context(), "rina"); !a.Verified() || a.MaxTokens != nil {
		t.Errorf("admin-made account must be confirmed and unlimited: %+v", a)
	}
	if rec := do(d, req{method: "POST", path: "/api/v1/admin/users", body: body, cookie: c, csrf: true}); rec.Code != http.StatusConflict {
		t.Errorf("duplicate: %d", rec.Code)
	}
	loginAs(t, d, "rina@example.com", password)
}

func TestChangeOwnPasswordKeepsThisSession(t *testing.T) {
	d, _, _ := setupAccounts(t)
	c := loginAs(t, d, "tino", password)
	other := loginAs(t, d, "tino", password)
	time.Sleep(2 * time.Millisecond)
	rec := do(d, req{method: "POST", path: "/api/v1/me/account/password", cookie: c, csrf: true,
		body: `{"current":"` + password + `","new":"another long passphrase"}`})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("change: %d %s", rec.Code, rec.Body)
	}
	var fresh *http.Cookie
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == "__Host-mancar_session" {
			fresh = ck
		}
	}
	if fresh == nil {
		t.Fatal("no fresh cookie")
	}
	if rec := do(d, req{method: "GET", path: "/api/v1/me/account", cookie: fresh}); rec.Code != http.StatusOK {
		t.Errorf("this session after the change: %d", rec.Code)
	}
	if rec := do(d, req{method: "GET", path: "/api/v1/me/account", cookie: other}); rec.Code != http.StatusUnauthorized {
		t.Errorf("other session survived: %d", rec.Code)
	}
	bad := do(d, req{method: "POST", path: "/api/v1/me/account/password", cookie: fresh, csrf: true,
		body: `{"current":"wrong","new":"another long passphrase"}`})
	if bad.Code != http.StatusBadRequest {
		t.Errorf("wrong current password: %d", bad.Code)
	}
}

func TestFirstAdminSetup(t *testing.T) {
	st := newFakeStore()
	d := dashboard.New(dashboard.Options{Store: st, Hub: &fakeHub{}, SessionSecret: strings.Repeat("s", 32), Secure: true,
		BaseDomain: "tunnel.example.com", PublicScheme: "https"})
	if body := do(d, req{method: "GET", path: "/api/v1/auth/options"}).Body.String(); !strings.Contains(body, `"setup":true`) || !strings.Contains(body, `"version"`) {
		t.Fatalf("options on a fresh gateway: %s", body)
	}
	body := `{"username":"Boss","email":"","password":"` + password + `"}`
	if rec := do(d, req{method: "POST", path: "/api/v1/auth/setup", body: body}); rec.Code != http.StatusForbidden {
		t.Errorf("setup without the CSRF header: %d", rec.Code)
	}
	if rec := do(d, req{method: "POST", path: "/api/v1/auth/setup", body: `{"username":"boss","password":"short"}`, csrf: true}); rec.Code != http.StatusBadRequest {
		t.Errorf("weak password: %d", rec.Code)
	}
	rec := do(d, req{method: "POST", path: "/api/v1/auth/setup", body: body, csrf: true})
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"role":"admin"`) {
		t.Fatalf("setup: %d %s", rec.Code, rec.Body)
	}
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-mancar_session" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("setup did not sign the admin in")
	}
	if rec := do(d, req{method: "GET", path: "/api/v1/admin/users", cookie: cookie}); rec.Code != http.StatusOK {
		t.Errorf("new admin: %d", rec.Code)
	}
	// closed for good once an admin exists
	again := do(d, req{method: "POST", path: "/api/v1/auth/setup", body: `{"username":"intruder","password":"` + password + `"}`, csrf: true})
	if again.Code != http.StatusNotFound {
		t.Errorf("second setup: %d %s", again.Code, again.Body)
	}
	if body := do(d, req{method: "GET", path: "/api/v1/auth/options"}).Body.String(); !strings.Contains(body, `"setup":false`) || strings.Contains(body, "version") {
		t.Errorf("options after setup (must not reveal the version): %s", body)
	}
}

func TestDeviceLogin(t *testing.T) {
	d, st, _ := setupAccounts(t)
	start := func(name string) (deviceCode, userCode string) {
		rec := do(d, req{method: "POST", path: "/api/v1/auth/device", body: `{"name":"` + name + `"}`})
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != http.StatusOK || !strings.HasPrefix(out["verification_url"].(string), "https://tunnel.example.com/dashboard/#device=") {
			t.Fatalf("start: %d %s", rec.Code, rec.Body)
		}
		return out["device_code"].(string), out["user_code"].(string)
	}
	poll := func(dc string) (int, string) {
		rec := do(d, req{method: "POST", path: "/api/v1/auth/device/token", body: `{"device_code":"` + dc + `"}`})
		return rec.Code, rec.Body.String()
	}

	dc, uc := start("MacBook Tino")
	if code, body := poll(dc); code != http.StatusPreconditionRequired || !strings.Contains(body, "authorization_pending") {
		t.Errorf("before approval: %d %s", code, body)
	}
	c := loginAs(t, d, "tino", password)
	// the code is case and dash insensitive, and the page shows the device name
	if rec := do(d, req{method: "GET", path: "/api/v1/me/device/" + strings.ToLower(strings.ReplaceAll(uc, "-", "")), cookie: c}); !strings.Contains(rec.Body.String(), "MacBook Tino") {
		t.Errorf("device info: %d %s", rec.Code, rec.Body)
	}
	if rec := do(d, req{method: "POST", path: "/api/v1/me/device/" + uc + "/approve", cookie: c}); rec.Code != http.StatusForbidden {
		t.Errorf("approve without CSRF: %d", rec.Code)
	}
	if rec := do(d, req{method: "POST", path: "/api/v1/me/device/" + uc + "/approve", cookie: c, csrf: true}); rec.Code != http.StatusNoContent {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	code, body := poll(dc)
	if code != http.StatusOK || !strings.Contains(body, `"token":"mc_secret"`) || !strings.Contains(body, `"username":"tino"`) {
		t.Fatalf("token: %d %s", code, body)
	}
	if code, _ := poll(dc); code != http.StatusGone {
		t.Errorf("token handed out twice: %d", code)
	}
	if len(st.tokens) != 1 || st.tokens[0].UserID != "u-tino" || st.tokens[0].Name != "MacBook Tino" {
		t.Errorf("token: %+v", st.tokens)
	}
	if rec := do(d, req{method: "POST", path: "/api/v1/me/device/" + uc + "/approve", cookie: c, csrf: true}); rec.Code != http.StatusNotFound {
		t.Errorf("approving a used code: %d", rec.Code)
	}

	// denied
	dc2, uc2 := start("other")
	do(d, req{method: "POST", path: "/api/v1/me/device/" + uc2 + "/deny", cookie: c, csrf: true})
	if code, _ := poll(dc2); code != http.StatusForbidden {
		t.Errorf("denied: %d", code)
	}
	// a wrong device code learns nothing
	if code, _ := poll("guess"); code != http.StatusGone {
		t.Errorf("unknown device code: %d", code)
	}
	// an unconfirmed account cannot approve
	st.SetEmailVerified(t.Context(), "u-tino", false)
	_, uc3 := start("third")
	if rec := do(d, req{method: "POST", path: "/api/v1/me/device/" + uc3 + "/approve", cookie: c, csrf: true}); rec.Code != http.StatusForbidden {
		t.Errorf("unconfirmed approve: %d", rec.Code)
	}
}

// sessionHub has live agent sessions and records which were dropped.
type sessionHub struct {
	fakeHub
	live []gateway.SessionInfo
}

func (h *sessionHub) Sessions() []gateway.SessionInfo { return slices.Clone(h.live) }
func (h *sessionHub) Disconnect(id string) bool {
	for i, s := range h.live {
		if s.ID == id {
			h.live = append(h.live[:i], h.live[i+1:]...)
			return true
		}
	}
	return false
}

func TestDropRevokedAgents(t *testing.T) {
	st := newFakeStore()
	st.add(postgres.Account{ID: "a1", Username: "root", Role: postgres.RoleAdmin})
	st.add(postgres.Account{ID: "u1", Username: "ana"})
	st.add(postgres.Account{ID: "u2", Username: "budi"})
	_, keep, _ := st.CreateAgentToken(t.Context(), "u1", "laptop")
	_, revoked, _ := st.CreateAgentToken(t.Context(), "u1", "old")
	_, disabled, _ := st.CreateAgentToken(t.Context(), "u2", "server")
	hub := &sessionHub{live: []gateway.SessionInfo{
		{ID: "s1", UserID: "u1", TokenID: keep},
		{ID: "s2", UserID: "u1", TokenID: revoked},
		{ID: "s3", UserID: "u2", TokenID: disabled},
	}}
	d := dashboard.New(dashboard.Options{Store: st, Hub: hub, SessionSecret: strings.Repeat("s", 32)})

	if n := d.DropRevoked(t.Context()); n != 0 {
		t.Fatalf("nothing changed yet, but %d agents were dropped", n)
	}
	// as "mancard token revoke" and "mancard user disable" would, from another process
	if err := st.RevokeAgentToken(t.Context(), revoked); err != nil {
		t.Fatal(err)
	}
	if err := st.SetDisabled(t.Context(), "u2", true); err != nil {
		t.Fatal(err)
	}
	if n := d.DropRevoked(t.Context()); n != 2 {
		t.Fatalf("dropped %d agents, want 2", n)
	}
	if len(hub.live) != 1 || hub.live[0].ID != "s1" {
		t.Errorf("still connected: %+v", hub.live)
	}
}

func TestPrivateTunnelAccess(t *testing.T) {
	_, st, _ := setupAccounts(t)
	k := access.New("secret", true)
	hub := &sessionHub{live: []gateway.SessionInfo{
		{ID: "s1", UserID: "u-tino", Tunnels: []gateway.TunnelInfo{
			{Proto: "http", Hostname: "app.tunnel.example.com", PublicURL: "https://app.tunnel.example.com", Private: true},
			{Proto: "http", Hostname: "open.tunnel.example.com", PublicURL: "https://open.tunnel.example.com"},
		}},
		{ID: "s2", UserID: "a1", Tunnels: []gateway.TunnelInfo{
			{Proto: "http", Hostname: "root.tunnel.example.com", PublicURL: "https://root.tunnel.example.com", Private: true},
			{Proto: "http", Hostname: "team.tunnel.example.com", PublicURL: "https://team.tunnel.example.com", Private: true,
				SharedWith: []string{"tino"}, AllowIDs: []string{"u-tino"}},
			{Proto: "http", Hostname: "phish.tunnel.example.com", PublicURL: "https://phish.tunnel.example.com"},
		}},
	}}
	d := dashboard.New(dashboard.Options{Store: st, Hub: hub, SessionSecret: strings.Repeat("s", 32), Secure: true,
		BaseDomain: "tunnel.example.com", PublicScheme: "https", Access: k})
	c := loginAs(t, d, "tino", password)
	ask := func(target string, csrf bool) (int, map[string]any) {
		rec := do(d, req{method: "POST", path: "/api/v1/me/access", body: `{"target":"` + target + `"}`, cookie: c, csrf: csrf})
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	code, out := ask("app.tunnel.example.com/x?y=1", true)
	if code != http.StatusOK {
		t.Fatalf("own private tunnel: %d %v", code, out)
	}
	u, err := url.Parse(out["url"].(string))
	if err != nil || u.Host != "app.tunnel.example.com" || u.Path != access.Path || u.Query().Get("next") != "/x?y=1" {
		t.Fatalf("url = %v", out["url"])
	}
	if out["allowed"] != true || out["owner"] != true {
		t.Errorf("allowed = %v, owner = %v", out["allowed"], out["owner"])
	}
	if user, ok := k.Redeem(u.Query().Get("ticket"), "app.tunnel.example.com"); !ok || user != "u-tino" {
		t.Errorf("ticket: %q %v", user, ok)
	}
	if code, out := ask("open.tunnel.example.com//evil.com", true); code != http.StatusOK || out["url"] != "https://open.tunnel.example.com/" {
		t.Errorf("own public tunnel: %d %v", code, out)
	}
	// someone else's private tunnel: back to its Restricted page, no ticket
	if code, out := ask("root.tunnel.example.com/a", true); code != http.StatusOK || out["url"] != "https://root.tunnel.example.com/a" || out["allowed"] != false {
		t.Errorf("another account's private tunnel: %d %v", code, out)
	}
	// someone else's public tunnel, or nothing there: no URL at all, so the
	// dashboard never forwards a signed-in person to an arbitrary app
	codePub, pub := ask("phish.tunnel.example.com/login", true)
	codeOff, off := ask("gone.tunnel.example.com/a", true)
	if codePub != http.StatusOK || pub["url"] != "" || pub["allowed"] != false || codeOff != http.StatusOK || fmt.Sprint(pub) != fmt.Sprint(off) {
		t.Errorf("another account's public tunnel: %d %v / offline: %d %v", codePub, pub, codeOff, off)
	}
	// root shared team.* with tino (--allow tino): allowed, but not the owner
	if code, out := ask("team.tunnel.example.com/", true); code != http.StatusOK || out["allowed"] != true || out["owner"] != false ||
		!strings.HasPrefix(fmt.Sprint(out["url"]), "https://team.tunnel.example.com"+access.Path+"?") {
		t.Errorf("tunnel shared with this account: %d %v", code, out)
	}
	// ... but not while tino's email is unconfirmed (shared by address)
	st.SetEmail(t.Context(), "u-tino", "tino2@example.com")
	if code, out := ask("team.tunnel.example.com/", true); code != http.StatusOK || out["allowed"] != false {
		t.Errorf("shared tunnel with an unconfirmed email: %d %v", code, out)
	}
	// never a redirect off this server
	for _, target := range []string{"evil.com/", "tunnel.example.com/", "x.tunnel.example.com.evil.com/", "a_b.tunnel.example.com/"} {
		if code, out := ask(target, true); code != http.StatusNotFound {
			t.Errorf("target %q: %d %v", target, code, out)
		}
	}
	if code, _ := ask("app.tunnel.example.com/", false); code != http.StatusForbidden {
		t.Errorf("without CSRF header: %d", code)
	}
}

func TestRestrictedPage(t *testing.T) {
	rec := httptest.NewRecorder()
	dashboard.RestrictedPage(rec, `app.tunnel.example.com"><script>`, `https://tunnel.example.com/dashboard/#ref=app.tunnel.example.com%2F`)
	body := rec.Body.String()
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Errorf("status %d, CSP %q", rec.Code, rec.Header().Get("Content-Security-Policy"))
	}
	if strings.Contains(body, "<script>") || !strings.Contains(body, "Log in to continue") ||
		!strings.Contains(body, `href="https://tunnel.example.com/dashboard/#ref=app.tunnel.example.com%2F"`) ||
		!strings.Contains(body, `url("https://tunnel.example.com/dashboard/logo.webp")`) ||
		!strings.Contains(rec.Header().Get("Content-Security-Policy"), "img-src https://tunnel.example.com;") {
		t.Errorf("body:\n%s", body)
	}
}

// The public first-run page is only for a fresh server: once any account
// has a password, losing the last admin does not reopen it.
func TestSetupStaysClosedWithoutAdmins(t *testing.T) {
	st := newFakeStore()
	st.add(postgres.Account{ID: "t1", Username: "token-only"}) // from "mancard token create": no password
	d := dashboard.New(dashboard.Options{Store: st, Hub: &fakeHub{}, SessionSecret: strings.Repeat("s", 32), Secure: true})
	setup := func() any {
		var out map[string]any
		json.Unmarshal(do(d, req{method: "GET", path: "/api/v1/auth/options"}).Body.Bytes(), &out)
		return out["setup"]
	}
	if setup() != true {
		t.Fatal("a server with only token users should offer setup")
	}
	st.add(postgres.Account{ID: "u1", Username: "former-admin", PasswordHash: "h"}) // demoted last admin
	if setup() != false {
		t.Error("setup reopened although an account with a password exists")
	}
	if rec := do(d, req{method: "POST", path: "/api/v1/auth/setup", csrf: true,
		body: `{"username":"intruder","email":"i@example.com","password":"` + password + `"}`}); rec.Code == http.StatusOK || rec.Code == http.StatusCreated {
		t.Errorf("setup accepted: %d %s", rec.Code, rec.Body)
	}
}

// A stolen admin session must not be enough to make or take over admins:
// each of these needs the acting admin's own password.
func TestAdminTakeoverNeedsOwnPassword(t *testing.T) {
	d, st, _ := setupAccounts(t)
	hash, _ := dashboard.HashPassword(password)
	st.add(postgres.Account{ID: "a2", Username: "ops", Role: postgres.RoleAdmin, Email: "ops@example.com", PasswordHash: hash, PasswordChangedAt: time.Now().Add(-time.Hour)})
	c := loginAs(t, d, "root", password)
	send := func(method, path, body string) int {
		return do(d, req{method: method, path: path, body: body, cookie: c, csrf: true}).Code
	}
	newAdmin := `{"username":"mallory","email":"","password":"` + password + `","role":"admin"`
	cases := []struct{ name, method, path, without, with string }{
		{"create an admin", "POST", "/api/v1/admin/users", newAdmin + `}`, newAdmin + `,"confirm_password":"` + password + `"}`},
		{"temporary password for another admin", "POST", "/api/v1/admin/users/a2/reset-password", `{"mode":"temporary"}`, `{"mode":"temporary","confirm_password":"` + password + `"}`},
		{"another admin's email", "PATCH", "/api/v1/admin/users/a2", `{"email":"mallory@example.com"}`, `{"email":"mallory@example.com","confirm_password":"` + password + `"}`},
	}
	for _, tc := range cases {
		if code := send(tc.method, tc.path, tc.without); code != http.StatusForbidden {
			t.Errorf("%s without the password: %d", tc.name, code)
		}
		if code := send(tc.method, tc.path, tc.with); code/100 != 2 {
			t.Errorf("%s with the password: %d", tc.name, code)
		}
	}
	// a plain user's temporary password needs no extra step
	if code := send("POST", "/api/v1/admin/users/u-tino/reset-password", `{"mode":"temporary"}`); code != http.StatusOK {
		t.Errorf("temporary password for a user: %d", code)
	}
}

func loginFrom(d http.Handler, addr, user, pw string) int {
	q := httptest.NewRequest("POST", "https://tunnel.example.com/api/v1/auth/login",
		strings.NewReader(`{"username":"`+user+`","password":"`+pw+`"}`))
	q.RemoteAddr = addr
	q.Header.Set(dashboard.HeaderCSRF, "1")
	rec := httptest.NewRecorder()
	d.ServeHTTP(rec, q)
	return rec.Code
}

// Someone guessing tino's password from elsewhere must not lock tino out,
// and an IPv6 client cannot dodge the limit by changing its address.
func TestLoginLimits(t *testing.T) {
	d, _, _ := setupAccounts(t)
	for i := 0; i < 10; i++ {
		loginFrom(d, "203.0.113.1:1000", "tino", "wrong wrong wrong")
	}
	if code := loginFrom(d, "203.0.113.1:1000", "tino", password); code != http.StatusTooManyRequests {
		t.Errorf("the guessing address should be blocked: %d", code)
	}
	if code := loginFrom(d, "198.51.100.9:1000", "tino", password); code != http.StatusOK {
		t.Errorf("tino from another address was locked out: %d", code)
	}
	for i := 0; i < 10; i++ {
		loginFrom(d, fmt.Sprintf("[2001:db8:1:2::%x]:1000", i+1), "root", "wrong wrong wrong")
	}
	if code := loginFrom(d, "[2001:db8:1:2::ffff]:1000", "root", password); code != http.StatusTooManyRequests {
		t.Errorf("a new address in the same IPv6 /64 should still be blocked: %d", code)
	}
	if code := loginFrom(d, "[2001:db8:1:3::1]:1000", "root", password); code != http.StatusOK {
		t.Errorf("another /64: %d", code)
	}
}
