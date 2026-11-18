package dashboard

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tinoimammp/mancar/internal/store/postgres"
)

// Device login ("mancar login"), the OAuth device flow without OAuth:
//
//  1. The client asks for a code: POST /api/v1/auth/device {"name"}. It
//     gets a secret device_code (kept by the client) and a short user_code
//     shown in the terminal and in a dashboard link.
//  2. The person opens the link while signed in, checks that the code and
//     device name match their terminal, and clicks Allow
//     (POST /api/v1/me/device/{code}/approve). Only then is an agent token
//     created, for the signed-in account.
//  3. The client polls POST /api/v1/auth/device/token {"device_code"} and
//     receives the token once.
//
// Requests live in memory for 10 minutes (the gateway is a single process).
// The token secret is held only until the client fetches it.

const (
	deviceTTL      = 10 * time.Minute
	devicePoll     = 2 * time.Second
	maxDevicePends = 1000
	// no 0/O, 1/I/L, 5/S, 8/B: easy to read aloud and to compare
	userCodeAlphabet = "ACDEFGHJKMNPQRTUVWXYZ234679"
)

type deviceReq struct {
	userCode string
	name     string
	created  time.Time
	approved bool
	denied   bool
	token    string // the secret, once approved; cleared when delivered
	username string
}

type deviceFlows struct {
	mu     sync.Mutex
	byCode map[string]*deviceReq // by device_code (secret)
	byUser map[string]string     // user_code → device_code
}

func newDeviceFlows() *deviceFlows {
	return &deviceFlows{byCode: map[string]*deviceReq{}, byUser: map[string]string{}}
}

// sweepLocked drops expired requests.
func (f *deviceFlows) sweepLocked(now time.Time) {
	for dc, r := range f.byCode {
		if now.Sub(r.created) > deviceTTL {
			delete(f.byCode, dc)
			delete(f.byUser, r.userCode)
		}
	}
}

func randomString(n int, alphabet string) string {
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// normalizeUserCode accepts "abcd efgh", "ABCD-EFGH" and the like.
func normalizeUserCode(s string) string {
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(s)))
	if len(s) != 8 {
		return ""
	}
	return s[:4] + "-" + s[4:]
}

// deviceStart creates a request (no session: the caller is the CLI).
func (d *Dashboard) deviceStart(w http.ResponseWriter, r *http.Request) {
	ip := d.rateKey(r)
	if retry, blocked := d.deviceByIP.Blocked(ip); blocked {
		d.tooMany(w, retry)
		return
	}
	d.deviceByIP.Fail(ip)
	var in struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "expected JSON with name")
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "mancar login"
	}
	if len(name) > 64 {
		name = name[:64]
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		d.internal(w, "random", err)
		return
	}
	deviceCode := base64.RawURLEncoding.EncodeToString(b)
	now := d.opts.Now()

	f := d.devices
	f.mu.Lock()
	f.sweepLocked(now)
	if len(f.byCode) >= maxDevicePends {
		f.mu.Unlock()
		writeErr(w, http.StatusServiceUnavailable, "busy", "too many sign-ins in progress; try again in a few minutes")
		return
	}
	var userCode string
	for {
		raw := randomString(8, userCodeAlphabet)
		userCode = raw[:4] + "-" + raw[4:]
		if _, taken := f.byUser[userCode]; !taken {
			break
		}
	}
	f.byCode[deviceCode] = &deviceReq{userCode: userCode, name: name, created: now}
	f.byUser[userCode] = deviceCode
	f.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":      deviceCode,
		"user_code":        userCode,
		"verification_url": d.origin() + "/dashboard/#device=" + userCode,
		"interval":         int(devicePoll / time.Second),
		"expires_in":       int(deviceTTL / time.Second),
	})
}

// deviceToken is polled by the CLI until the request is allowed, denied or
// expired. The token is handed out exactly once.
func (d *Dashboard) deviceToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		DeviceCode string `json:"device_code"`
	}
	if err := readJSON(r, &in); err != nil || in.DeviceCode == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "expected JSON with device_code")
		return
	}
	f := d.devices
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweepLocked(d.opts.Now())
	var req *deviceReq
	var key string
	for dc, x := range f.byCode { // constant-time compare: the code is a secret
		if subtle.ConstantTimeCompare([]byte(dc), []byte(in.DeviceCode)) == 1 {
			req, key = x, dc
		}
	}
	switch {
	case req == nil:
		writeErr(w, http.StatusGone, "expired_token", "this sign-in expired or was already used; run mancar login again")
	case req.denied:
		delete(f.byCode, key)
		delete(f.byUser, req.userCode)
		writeErr(w, http.StatusForbidden, "access_denied", "the sign-in was denied in the dashboard")
	case !req.approved:
		writeErr(w, http.StatusPreconditionRequired, "authorization_pending", "waiting for approval in the dashboard")
	default:
		tok, user := req.token, req.username
		delete(f.byCode, key)
		delete(f.byUser, req.userCode)
		writeJSON(w, http.StatusOK, map[string]string{"token": tok, "username": user, "name": req.name, "server": d.origin()})
	}
}

// pending finds an open request by user code (for the dashboard).
func (d *Dashboard) pending(code string) (*deviceReq, bool) {
	f := d.devices
	f.sweepLocked(d.opts.Now())
	dc, ok := f.byUser[normalizeUserCode(code)]
	if !ok {
		return nil, false
	}
	req := f.byCode[dc]
	if req == nil || req.approved || req.denied {
		return nil, false
	}
	return req, true
}

func (d *Dashboard) myDevice(w http.ResponseWriter, r *http.Request) {
	d.devices.mu.Lock()
	req, ok := d.pending(r.PathValue("code"))
	var out map[string]any
	if ok {
		out = map[string]any{"user_code": req.userCode, "name": req.name, "created_at": req.created}
	}
	d.devices.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "not_found", "this code is unknown, expired or already used; run mancar login again")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (d *Dashboard) myDeviceDeny(w http.ResponseWriter, r *http.Request) {
	d.devices.mu.Lock()
	req, ok := d.pending(r.PathValue("code"))
	if ok {
		req.denied = true
	}
	d.devices.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "not_found", "this code is unknown, expired or already used")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// myDeviceApprove creates a token for the signed-in account and parks it
// for the waiting client.
func (d *Dashboard) myDeviceApprove(w http.ResponseWriter, r *http.Request) {
	a := accountFrom(r)
	d.devices.mu.Lock()
	req, ok := d.pending(r.PathValue("code"))
	var name string
	if ok {
		name = req.name
	}
	d.devices.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "not_found", "this code is unknown, expired or already used; run mancar login again")
		return
	}
	tok, tokID, status, code, msg := d.createOwnToken(r, a, name)
	if status != 0 {
		writeErr(w, status, code, msg)
		return
	}
	d.devices.mu.Lock()
	req, ok = d.pending(r.PathValue("code"))
	if ok {
		req.approved, req.token, req.username = true, tok, a.Username
	}
	d.devices.mu.Unlock()
	if !ok {
		// expired, or allowed in another tab, while the token was being
		// made: revoke it rather than leave an active token nobody holds
		if err := d.opts.Store.RevokeAgentToken(r.Context(), tokID); err != nil {
			d.log.Warn("dashboard: revoking an undelivered device token failed", "err", err)
		}
		writeErr(w, http.StatusGone, "expired_token", "the sign-in expired or was already allowed; run mancar login again")
		return
	}
	d.audit(r, "device.login", a.Username, name)
	w.WriteHeader(http.StatusNoContent)
}

// createOwnToken makes a token for the signed-in account, enforcing email
// confirmation and the token limit. A non-zero status is an API error.
func (d *Dashboard) createOwnToken(r *http.Request, a postgres.Account, name string) (tok, id string, status int, code, msg string) {
	if !a.Verified() {
		return "", "", http.StatusForbidden, "email_unverified", "confirm your email address before creating tokens"
	}
	if max := d.limits(a).Tokens; max != nil {
		toks, err := d.ownTokens(r, a.ID)
		if err != nil {
			d.log.Error("dashboard: list tokens", "err", err)
			return "", "", http.StatusInternalServerError, "internal", "internal error"
		}
		active := 0
		for _, t := range toks {
			if t.RevokedAt == nil {
				active++
			}
		}
		if active >= *max {
			return "", "", http.StatusConflict, "limit_reached", "you have as many active tokens as your account allows; revoke one first"
		}
	}
	tok, id, err := d.opts.Store.CreateAgentToken(r.Context(), a.ID, name)
	if err != nil {
		d.log.Error("dashboard: create token", "err", err)
		return "", "", http.StatusInternalServerError, "internal", "internal error"
	}
	return tok, id, 0, "", ""
}
