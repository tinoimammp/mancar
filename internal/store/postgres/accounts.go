package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/lib/pq"
)

// ---- accounts ----------------------------------------------------------------
//
// An account is a row of users. Role "admin" manages the gateway; role "user"
// manages their own tunnels. A user created by an admin making a token has
// no email and no password until one is set.

// Roles.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// Limits given to an account created by web sign up. Admins can change them
// per account; NULL means no limit.
const (
	SignupMaxTokens        = 3
	SignupMaxCustomDomains = 3
)

var (
	// ErrUsernameTaken and ErrEmailTaken report a unique conflict.
	ErrUsernameTaken = errors.New("postgres: username is taken")
	ErrEmailTaken    = errors.New("postgres: email is taken")
	// ErrLastAdmin refuses a change that would leave no active admin.
	ErrLastAdmin = errors.New("postgres: the last active admin cannot be removed")
)

// Account is a sign-in identity (admin or user).
type Account struct {
	ID                string
	Username          string
	Email             string // "" when none
	PasswordHash      string // "" when the account cannot sign in
	Role              string
	EmailVerifiedAt   *time.Time
	DisabledAt        *time.Time
	PasswordChangedAt time.Time
	LastLoginAt       *time.Time
	CreatedAt         time.Time
	SignedUp          bool
	MaxTokens         *int // nil: no limit
	MaxCustomDomains  *int
}

// IsAdmin reports the admin role.
func (a Account) IsAdmin() bool { return a.Role == RoleAdmin }

// Verified reports whether the account may act as a confirmed owner: it has
// no email to confirm, or confirmed it.
func (a Account) Verified() bool { return a.Email == "" || a.EmailVerifiedAt != nil }

const accountCols = `u.id, u.username, coalesce(u.email, ''), coalesce(u.password_hash, ''), u.role,
	u.email_verified_at, u.disabled_at, u.password_changed_at, u.last_login_at, u.created_at,
	u.signed_up, u.max_tokens, u.max_custom_domains`

// scanAccount reads accountCols, then any extra columns into extra.
func scanAccount(row interface{ Scan(...any) error }, extra ...any) (Account, error) {
	var a Account
	var verified, disabled, last sql.NullTime
	var maxTok, maxDom sql.NullInt64
	dest := append([]any{&a.ID, &a.Username, &a.Email, &a.PasswordHash, &a.Role,
		&verified, &disabled, &a.PasswordChangedAt, &last, &a.CreatedAt,
		&a.SignedUp, &maxTok, &maxDom}, extra...)
	if err := row.Scan(dest...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Account{}, ErrNotFound
		}
		return Account{}, err
	}
	a.EmailVerifiedAt, a.DisabledAt, a.LastLoginAt = timePtr(verified), timePtr(disabled), timePtr(last)
	a.MaxTokens, a.MaxCustomDomains = intPtr(maxTok), intPtr(maxDom)
	return a, nil
}

func timePtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	return &t.Time
}

func intPtr(n sql.NullInt64) *int {
	if !n.Valid {
		return nil
	}
	v := int(n.Int64)
	return &v
}

func nullInt(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// uniqueErr maps a unique violation to ErrUsernameTaken or ErrEmailTaken.
func uniqueErr(err error) error {
	var pe *pq.Error
	if errors.As(err, &pe) && pe.Code == "23505" {
		if strings.Contains(pe.Constraint, "email") {
			return ErrEmailTaken
		}
		return ErrUsernameTaken
	}
	return err
}

// NormalizeEmail lowercases and trims an address.
func NormalizeEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

// AccountByID looks an account up (session validation).
func (s *Store) AccountByID(ctx context.Context, id string) (Account, error) {
	return scanAccount(s.DB.QueryRowContext(ctx, `SELECT `+accountCols+` FROM users u WHERE u.id::text = $1`, id))
}

// AccountByLogin looks an account up by username or email (sign in).
func (s *Store) AccountByLogin(ctx context.Context, login string) (Account, error) {
	login = strings.ToLower(strings.TrimSpace(login))
	col := "username"
	if strings.Contains(login, "@") {
		col = "email"
	}
	return scanAccount(s.DB.QueryRowContext(ctx, `SELECT `+accountCols+` FROM users u WHERE u.`+col+` = $1`, login))
}

// AccountByEmail looks an account up by email.
func (s *Store) AccountByEmail(ctx context.Context, email string) (Account, error) {
	return scanAccount(s.DB.QueryRowContext(ctx, `SELECT `+accountCols+` FROM users u WHERE u.email = $1`, NormalizeEmail(email)))
}

// NewAccount describes an account to create.
type NewAccount struct {
	Username     string
	Email        string // "" for none
	PasswordHash string
	Role         string
	Verified     bool // email already confirmed (created by an admin)
	SignedUp     bool // web sign up: gets the sign-up limits
}

// CreateAccount inserts an account. A username that exists as a token-only
// user (no password, no email) is taken over only by an admin creating it
// (SignedUp false); otherwise ErrUsernameTaken.
func (s *Store) CreateAccount(ctx context.Context, n NewAccount) (string, error) {
	var maxTok, maxDom any
	if n.SignedUp {
		maxTok, maxDom = SignupMaxTokens, SignupMaxCustomDomains
	}
	role := n.Role
	if role == "" {
		role = RoleUser
	}
	var verified any
	if n.Verified && n.Email != "" {
		verified = time.Now()
	}
	var id string
	q := `INSERT INTO users (username, email, password_hash, role, email_verified_at, signed_up, max_tokens, max_custom_domains)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	if !n.SignedUp {
		// an admin may give a password to an existing token-only user
		q += ` ON CONFLICT (username) DO UPDATE SET email = EXCLUDED.email, password_hash = EXCLUDED.password_hash,
			role = EXCLUDED.role, email_verified_at = EXCLUDED.email_verified_at, password_changed_at = now(), updated_at = now()
			WHERE users.password_hash IS NULL AND users.email IS NULL`
	}
	q += ` RETURNING id`
	err := s.DB.QueryRowContext(ctx, q, strings.ToLower(strings.TrimSpace(n.Username)), nullStr(NormalizeEmail(n.Email)),
		n.PasswordHash, role, verified, n.SignedUp, maxTok, maxDom).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrUsernameTaken
	}
	return id, uniqueErr(err)
}

// ErrSetupDone means the server has been set up, so first-run setup is closed.
var ErrSetupDone = errors.New("postgres: the server is already set up")

// setupDoneSQL: the server counts as set up once any account is an admin or
// has a password. Removing or demoting the last admin later must not reopen
// the public first-run page (anyone could become admin); the way back is
// "mancard user role NAME admin" on the server.
const setupDoneSQL = `SELECT EXISTS (SELECT 1 FROM users WHERE role = 'admin' OR password_hash IS NOT NULL)`

// SetupDone reports whether first-run setup is over (see setupDoneSQL).
func (s *Store) SetupDone(ctx context.Context) (bool, error) {
	var ok bool
	err := s.DB.QueryRowContext(ctx, setupDoneSQL).Scan(&ok)
	return ok, err
}

// CreateFirstAdmin creates an admin only while the server is not set up
// (first-run setup in the dashboard, see setupDoneSQL). The table lock makes two concurrent setups
// impossible: exactly one wins, the other gets ErrSetupDone.
func (s *Store) CreateFirstAdmin(ctx context.Context, n NewAccount) (string, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return "", err
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, setupDoneSQL).Scan(&exists); err != nil {
		return "", err
	}
	if exists {
		return "", ErrSetupDone
	}
	var verified any
	if n.Email != "" {
		verified = time.Now()
	}
	var id string
	err = tx.QueryRowContext(ctx, `INSERT INTO users (username, email, password_hash, role, email_verified_at)
		VALUES ($1, $2, $3, 'admin', $4) RETURNING id`,
		strings.ToLower(strings.TrimSpace(n.Username)), nullStr(NormalizeEmail(n.Email)), n.PasswordHash, verified).Scan(&id)
	if err != nil {
		return "", uniqueErr(err)
	}
	return id, tx.Commit()
}

// TouchLogin records a successful sign in.
func (s *Store) TouchLogin(ctx context.Context, id string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE users SET last_login_at = now() WHERE id::text = $1`, id)
	return err
}

// SetPassword replaces the password; sessions issued before now end.
func (s *Store) SetPassword(ctx context.Context, id, hash string) error {
	return s.exec1(ctx, `UPDATE users SET password_hash = $2, password_changed_at = now(), updated_at = now() WHERE id::text = $1`, id, hash)
}

// EndSessions signs the account out everywhere (its dashboard sessions
// started before now stop working), without changing the password.
func (s *Store) EndSessions(ctx context.Context, id string) error {
	return s.exec1(ctx, `UPDATE users SET password_changed_at = now(), updated_at = now() WHERE id::text = $1`, id)
}

// SetEmailVerified confirms (or un-confirms) the account's email.
func (s *Store) SetEmailVerified(ctx context.Context, id string, verified bool) error {
	return s.exec1(ctx, `UPDATE users SET email_verified_at = CASE WHEN $2 THEN coalesce(email_verified_at, now()) END,
		updated_at = now() WHERE id::text = $1`, id, verified)
}

// SetEmail changes the address; it is unconfirmed again, and links sent to
// the old address stop working.
func (s *Store) SetEmail(ctx context.Context, id, email string) error {
	err := s.exec1(ctx, `UPDATE users SET email = $2, email_verified_at = NULL, updated_at = now() WHERE id::text = $1`,
		id, nullStr(NormalizeEmail(email)))
	return uniqueErr(err)
}

// SetLimits sets the per-account limits (nil: no limit).
func (s *Store) SetLimits(ctx context.Context, id string, maxTokens, maxCustomDomains *int) error {
	return s.exec1(ctx, `UPDATE users SET max_tokens = $2, max_custom_domains = $3, updated_at = now() WHERE id::text = $1`,
		id, nullInt(maxTokens), nullInt(maxCustomDomains))
}

// SetRole changes the role. Demoting the last active admin is refused.
func (s *Store) SetRole(ctx context.Context, id, role string) error {
	return s.guardAdmins(ctx, id, func(tx *sql.Tx) error {
		return exec1(tx.ExecContext(ctx, `UPDATE users SET role = $2, updated_at = now() WHERE id::text = $1`, id, role))
	})
}

// SetDisabled disables or enables an account. Disabling the last active
// admin is refused.
func (s *Store) SetDisabled(ctx context.Context, id string, disabled bool) error {
	return s.guardAdmins(ctx, id, func(tx *sql.Tx) error {
		return exec1(tx.ExecContext(ctx, `UPDATE users SET disabled_at = CASE WHEN $2 THEN coalesce(disabled_at, now()) END,
			updated_at = now() WHERE id::text = $1`, id, disabled))
	})
}

// DeleteAccount removes an account like DeleteUser, refusing the last admin.
func (s *Store) DeleteAccount(ctx context.Context, id string) error {
	return s.guardAdmins(ctx, id, func(tx *sql.Tx) error {
		for _, table := range []string{"captured_requests", "usage_hourly", "usage_daily", "usage_total"} {
			if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE user_id::text = $1`, id); err != nil {
				return err
			}
		}
		return exec1(tx.ExecContext(ctx, `DELETE FROM users WHERE id::text = $1`, id))
	})
}

// guardAdmins runs change in a transaction that holds a lock on the admin
// rows, and rolls it back when no active admin is left afterwards. The lock
// makes two concurrent demotions of the last two admins impossible.
func (s *Store) guardAdmins(ctx context.Context, _ string, change func(tx *sql.Tx) error) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT id FROM users WHERE role = 'admin' FOR UPDATE`); err != nil {
		return err
	}
	var before int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE role = 'admin' AND disabled_at IS NULL`).Scan(&before); err != nil {
		return err
	}
	if err := change(tx); err != nil {
		return err
	}
	var after int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE role = 'admin' AND disabled_at IS NULL`).Scan(&after); err != nil {
		return err
	}
	if before > 0 && after == 0 {
		return ErrLastAdmin
	}
	return tx.Commit()
}

func (s *Store) exec1(ctx context.Context, q string, args ...any) error {
	return exec1(s.DB.ExecContext(ctx, q, args...))
}

// exec1 turns "no row changed" into ErrNotFound.
func exec1(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ErrHasEmail means "mancard admin set" found an account with an email
// address (typically one made by web sign up): promoting it would leave
// that address able to reset the new admin's password.
var ErrHasEmail = errors.New("postgres: the account has an email address")

// SetAdmin creates an admin or gives an existing account without an email
// address the admin role and a new password ("mancard admin set").
// Changing the password ends that account's sessions. An account with an
// email address is left alone (ErrHasEmail): whoever owns that address,
// for example someone who signed up with the name first, could reset the
// password and take the admin role over.
func (s *Store) SetAdmin(ctx context.Context, username, passwordHash string) (created bool, err error) {
	err = s.DB.QueryRowContext(ctx, `
		INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'admin')
		ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = 'admin',
			disabled_at = NULL, password_changed_at = now(), updated_at = now()
		WHERE users.email IS NULL AND NOT users.signed_up
		RETURNING xmax = 0`, strings.ToLower(strings.TrimSpace(username)), passwordHash).Scan(&created)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrHasEmail
	}
	return created, err
}

// ListAdmins returns every admin, by name.
func (s *Store) ListAdmins(ctx context.Context) ([]Account, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+accountCols+` FROM users u WHERE u.role = 'admin' ORDER BY u.username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteAdmin takes the admin role away from username ("mancard admin
// delete"); the account stays as a user. The server operator may remove the
// last admin this way: "mancard user role NAME admin" makes a new one.
func (s *Store) DeleteAdmin(ctx context.Context, username string) error {
	return s.exec1(ctx, `UPDATE users SET role = 'user', updated_at = now() WHERE username = $1 AND role = 'admin'`,
		strings.ToLower(strings.TrimSpace(username)))
}

// PurgeUnconfirmed deletes abandoned web sign-ups, and expired email links.
// An abandoned sign-up never confirmed its email, never signed in, has no
// tokens, and was not changed (by itself or an admin, e.g. a new email
// address) since olderThan; an account in real use is never caught.
func (s *Store) PurgeUnconfirmed(ctx context.Context, olderThan time.Time) (int64, error) {
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM email_tokens WHERE expires_at < now()`); err != nil {
		return 0, err
	}
	res, err := s.DB.ExecContext(ctx, `DELETE FROM users
		WHERE signed_up AND role = 'user' AND email_verified_at IS NULL AND email IS NOT NULL
		  AND last_login_at IS NULL AND created_at < $1 AND updated_at < $1
		  AND NOT EXISTS (SELECT 1 FROM agent_tokens t WHERE t.user_id = users.id)`, olderThan)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---- email links ---------------------------------------------------------------

// Email link purposes.
const (
	LinkVerify = "verify"
	LinkReset  = "reset"
)

// ErrLinkInvalid means the link is unknown, used, expired, or was sent to
// an address the account no longer has.
var ErrLinkInvalid = errors.New("postgres: link is invalid or expired")

func hashLink(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

// CreateEmailLink makes a one-time link secret for the account's current
// email. Earlier links of the same purpose stop working.
func (s *Store) CreateEmailLink(ctx context.Context, userID, purpose string, ttl time.Duration) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(b)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM email_tokens WHERE user_id::text = $1 AND purpose = $2`, userID, purpose); err != nil {
		return "", err
	}
	if err := exec1(tx.ExecContext(ctx, `INSERT INTO email_tokens (token_hash, user_id, purpose, email, expires_at)
		SELECT $1, id, $3, email, now() + make_interval(secs => $4) FROM users WHERE id::text = $2 AND email IS NOT NULL`,
		hashLink(secret), userID, purpose, ttl.Seconds())); err != nil {
		return "", err
	}
	return secret, tx.Commit()
}

// UseEmailLink consumes a link: it returns the account and deletes the link,
// so it works once.
func (s *Store) UseEmailLink(ctx context.Context, purpose, secret string) (string, error) {
	var id string
	err := s.DB.QueryRowContext(ctx, `
		DELETE FROM email_tokens e USING users u
		WHERE e.token_hash = $1 AND e.purpose = $2 AND e.user_id = u.id
		  AND e.expires_at > now() AND u.email = e.email
		RETURNING u.id`, hashLink(secret), purpose).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrLinkInvalid
	}
	return id, err
}

// ---- audit log -------------------------------------------------------------

// AuditEntry is one recorded admin action.
type AuditEntry struct {
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	Detail string    `json:"detail"`
}

// AddAudit records an action.
func (s *Store) AddAudit(ctx context.Context, e AuditEntry) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO audit_log (actor, action, target, detail) VALUES ($1, $2, $3, $4)`,
		e.Actor, e.Action, e.Target, e.Detail)
	return err
}

// ListAudit returns the newest entries first.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT at, actor, action, target, detail FROM audit_log ORDER BY at DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.At, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PurgeAudit deletes entries older than before.
func (s *Store) PurgeAudit(ctx context.Context, before time.Time) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM audit_log WHERE at < $1`, before)
	return err
}
