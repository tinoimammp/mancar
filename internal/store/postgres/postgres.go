// Package postgres is the PostgreSQL implementation of the storage
// interfaces: auth.Authenticator, domain.Registry and token administration.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver

	"github.com/tinoimammp/mancar/internal/auth"
	"github.com/tinoimammp/mancar/internal/domain"
)

// Store wraps a connection pool.
type Store struct{ DB *sql.DB }

// Open connects with a bounded pool and waits (up to wait) for the database
// to accept connections.
func Open(ctx context.Context, databaseURL string, wait time.Duration) (*Store, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)

	deadline := time.Now().Add(wait)
	for {
		pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err = db.PingContext(pctx)
		cancel()
		if err == nil {
			return &Store{DB: db}, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			db.Close()
			return nil, fmt.Errorf("postgres: database not reachable: %w", err)
		}
		time.Sleep(time.Second)
	}
}

// Close releases the pool.
func (s *Store) Close() error { return s.DB.Close() }

// Ping checks connectivity (health endpoint).
func (s *Store) Ping(ctx context.Context) error { return s.DB.PingContext(ctx) }

const migrationLockID = 724195301

// Migrate applies pending migrations from fsys. It is safe to run from
// several processes at once (advisory lock) and each migration is atomic.
func (s *Store) Migrate(ctx context.Context, fsys fs.FS) error {
	conn, err := s.DB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrationLockID); err != nil {
		return err
	}
	defer conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrationLockID)

	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	names, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		version := strings.TrimSuffix(name, ".sql")
		var exists bool
		if err := conn.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`,
			version).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migration %s: %w", name, err)
		}
	}
	return nil
}

// ---- users and agent tokens -------------------------------------------

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("postgres: not found")

// EnsureUser returns the ID of username, creating the user if needed.
func (s *Store) EnsureUser(ctx context.Context, username string) (string, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return "", errors.New("postgres: username must not be empty")
	}
	var id string
	err := s.DB.QueryRowContext(ctx, `
		INSERT INTO users (username) VALUES ($1)
		ON CONFLICT (username) DO UPDATE SET updated_at = now()
		RETURNING id`, username).Scan(&id)
	return id, err
}

// TokenInfo describes a stored agent token (never the secret itself).
type TokenInfo struct {
	ID         string
	Username   string
	Name       string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// CreateAgentToken stores a new token for userID and returns the plaintext
// exactly once.
func (s *Store) CreateAgentToken(ctx context.Context, userID, name string) (plaintext, id string, err error) {
	plaintext, hash, err := auth.NewToken()
	if err != nil {
		return "", "", err
	}
	err = s.DB.QueryRowContext(ctx, `INSERT INTO agent_tokens (user_id, name, token_hash) VALUES ($1, $2, $3) RETURNING id`,
		userID, name, hash).Scan(&id)
	return plaintext, id, err
}

// ListAgentTokens returns all tokens, newest first.
func (s *Store) ListAgentTokens(ctx context.Context) ([]TokenInfo, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT t.id, u.username, t.name, t.created_at, t.last_used_at, t.revoked_at
		FROM agent_tokens t JOIN users u ON u.id = t.user_id ORDER BY t.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TokenInfo
	for rows.Next() {
		var t TokenInfo
		var used, revoked sql.NullTime
		if err := rows.Scan(&t.ID, &t.Username, &t.Name, &t.CreatedAt, &used, &revoked); err != nil {
			return nil, err
		}
		if used.Valid {
			t.LastUsedAt = &used.Time
		}
		if revoked.Valid {
			t.RevokedAt = &revoked.Time
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAgentToken revokes a token by ID.
func (s *Store) RevokeAgentToken(ctx context.Context, id string) error {
	res, err := s.DB.ExecContext(ctx, `UPDATE agent_tokens SET revoked_at = now() WHERE id::text = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AuthenticateAgent implements auth.Authenticator.
func (s *Store) AuthenticateAgent(ctx context.Context, token string) (auth.Principal, error) {
	var p auth.Principal
	err := s.DB.QueryRowContext(ctx, `
		UPDATE agent_tokens SET last_used_at = now()
		WHERE token_hash = $1 AND revoked_at IS NULL
		RETURNING id, user_id`, auth.HashToken(token)).Scan(&p.TokenID, &p.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.Principal{}, auth.ErrInvalidToken
	}
	return p, err
}

// UserInfo summarises a user for the dashboard.
type UserInfo struct {
	ID           string
	Username     string
	CreatedAt    time.Time
	ActiveTokens int
	Domains      int
}

// ListUsers returns every user with token and hostname counts, by name.
func (s *Store) ListUsers(ctx context.Context) ([]UserInfo, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT u.id, u.username, u.created_at,
		       (SELECT count(*) FROM agent_tokens t WHERE t.user_id = u.id AND t.revoked_at IS NULL),
		       (SELECT count(*) FROM domains d WHERE d.user_id = u.id)
		FROM users u ORDER BY u.username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserInfo
	for rows.Next() {
		var u UserInfo
		if err := rows.Scan(&u.ID, &u.Username, &u.CreatedAt, &u.ActiveTokens, &u.Domains); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// DeleteUser removes a user and, by cascade, their tokens and hostnames.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM users WHERE id::text = $1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DomainInfo describes a hostname reservation.
type DomainInfo struct {
	Hostname  string
	Username  string
	Kind      string
	Online    bool
	HoldUntil time.Time
}

// ListDomains returns every reserved hostname, by name.
func (s *Store) ListDomains(ctx context.Context) ([]DomainInfo, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT d.hostname, u.username, d.kind, d.active_tunnel_id IS NOT NULL, d.hold_until
		FROM domains d JOIN users u ON u.id = d.user_id ORDER BY d.hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DomainInfo
	for rows.Next() {
		var d DomainInfo
		if err := rows.Scan(&d.Hostname, &d.Username, &d.Kind, &d.Online, &d.HoldUntil); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ReleaseDomain deletes a reservation that has no connected tunnel, making
// the name available to anyone at once.
func (s *Store) ReleaseDomain(ctx context.Context, hostname string) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM domains WHERE hostname = $1 AND active_tunnel_id IS NULL`, hostname)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- dashboard admins ---------------------------------------------------

// Admin is a dashboard operator account.
type Admin struct {
	ID                string
	Username          string
	PasswordHash      string
	PasswordChangedAt time.Time
	LastLoginAt       *time.Time
	CreatedAt         time.Time
}

const adminCols = `id, username, password_hash, password_changed_at, last_login_at, created_at`

func scanAdmin(row interface{ Scan(...any) error }) (Admin, error) {
	var a Admin
	var last sql.NullTime
	err := row.Scan(&a.ID, &a.Username, &a.PasswordHash, &a.PasswordChangedAt, &last, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Admin{}, ErrNotFound
	}
	if last.Valid {
		a.LastLoginAt = &last.Time
	}
	return a, err
}

// SetAdmin creates an admin or replaces the password of an existing one.
// Changing the password invalidates that admin's existing sessions.
func (s *Store) SetAdmin(ctx context.Context, username, passwordHash string) (created bool, err error) {
	err = s.DB.QueryRowContext(ctx, `
		INSERT INTO admins (username, password_hash) VALUES ($1, $2)
		ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash, password_changed_at = now()
		RETURNING xmax = 0`, strings.ToLower(strings.TrimSpace(username)), passwordHash).Scan(&created)
	return created, err
}

// AdminByUsername looks an admin up for login.
func (s *Store) AdminByUsername(ctx context.Context, username string) (Admin, error) {
	return scanAdmin(s.DB.QueryRowContext(ctx, `SELECT `+adminCols+` FROM admins WHERE username = $1`,
		strings.ToLower(strings.TrimSpace(username))))
}

// AdminByID looks an admin up for session validation.
func (s *Store) AdminByID(ctx context.Context, id string) (Admin, error) {
	return scanAdmin(s.DB.QueryRowContext(ctx, `SELECT `+adminCols+` FROM admins WHERE id::text = $1`, id))
}

// TouchAdminLogin records a successful login.
func (s *Store) TouchAdminLogin(ctx context.Context, id string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE admins SET last_login_at = now() WHERE id::text = $1`, id)
	return err
}

// ListAdmins returns every admin, by name.
func (s *Store) ListAdmins(ctx context.Context) ([]Admin, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+adminCols+` FROM admins ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Admin
	for rows.Next() {
		a, err := scanAdmin(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteAdmin removes an admin by username.
func (s *Store) DeleteAdmin(ctx context.Context, username string) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM admins WHERE username = $1`, strings.ToLower(strings.TrimSpace(username)))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- domain.Registry ---------------------------------------------------

// Claim implements domain.Registry with a single atomic statement: the
// UNIQUE(hostname) constraint serialises concurrent claims, and the WHERE
// clause on the conflict branch encodes the ownership rules.
func (s *Store) Claim(ctx context.Context, c domain.Claim) (string, error) {
	var kind string
	err := s.DB.QueryRowContext(ctx, `
		INSERT INTO domains AS d (hostname, user_id, kind, active_tunnel_id, hold_until)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (hostname) DO UPDATE SET
			kind = CASE WHEN d.user_id = EXCLUDED.user_id AND d.hold_until > now()
			            THEN d.kind ELSE EXCLUDED.kind END,
			user_id = EXCLUDED.user_id,
			active_tunnel_id = EXCLUDED.active_tunnel_id,
			hold_until = now(),
			updated_at = now()
		WHERE d.active_tunnel_id IS NULL
		  AND (d.user_id = EXCLUDED.user_id OR d.hold_until <= now())
		RETURNING d.kind`, c.Hostname, c.OwnerID, c.Kind, c.TunnelID).Scan(&kind)
	if errors.Is(err, sql.ErrNoRows) {
		return "", domain.ErrHostnameTaken
	}
	return kind, err
}

// Release implements domain.Registry.
func (s *Store) Release(ctx context.Context, hostname, tunnelID string, hold time.Duration) error {
	_, err := s.DB.ExecContext(ctx, `
		UPDATE domains SET active_tunnel_id = NULL, hold_until = now() + make_interval(secs => $3), updated_at = now()
		WHERE hostname = $1 AND active_tunnel_id = $2`, hostname, tunnelID, hold.Seconds())
	return err
}

// ReleaseAll implements domain.Registry.
func (s *Store) ReleaseAll(ctx context.Context, hold time.Duration) error {
	_, err := s.DB.ExecContext(ctx, `
		UPDATE domains SET active_tunnel_id = NULL, hold_until = now() + make_interval(secs => $1), updated_at = now()
		WHERE active_tunnel_id IS NOT NULL`, hold.Seconds())
	return err
}

// Purge implements domain.Registry.
func (s *Store) Purge(ctx context.Context) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM domains WHERE active_tunnel_id IS NULL AND hold_until <= now()`)
	return err
}
