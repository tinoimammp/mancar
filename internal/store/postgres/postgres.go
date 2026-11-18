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

	"github.com/lib/pq" // PostgreSQL driver

	"github.com/tinoimammp/mancar/internal/auth"
	"github.com/tinoimammp/mancar/internal/domain"
	"github.com/tinoimammp/mancar/internal/inspect"
	"github.com/tinoimammp/mancar/internal/usage"
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
// several processes at once and each migration is atomic. The lock is a
// transaction-level advisory lock taken in each migration's own
// transaction, so it also works through PgBouncer in transaction pooling
// mode (a session-level lock could be taken on one server connection and
// released on another).
func (s *Store) Migrate(ctx context.Context, fsys fs.FS) error {
	if err := s.migrationTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
			version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`)
		return err
	}); err != nil {
		return err
	}
	names, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		version := strings.TrimSuffix(name, ".sql")
		err := s.migrationTx(ctx, func(tx *sql.Tx) error {
			var exists bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`,
				version).Scan(&exists); err != nil {
				return err
			}
			if exists { // checked under the lock: another process may have just applied it
				return nil
			}
			body, err := fs.ReadFile(fsys, name)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, string(body)); err != nil {
				return fmt.Errorf("migration %s: %w", name, err)
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version)
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// migrationTx runs fn in a transaction holding the migration lock.
func (s *Store) migrationTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLockID); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// PendingMigrations lists the migrations in fsys not applied yet. fresh is
// true for a database that was never migrated at all.
func (s *Store) PendingMigrations(ctx context.Context, fsys fs.FS) (pending []string, fresh bool, err error) {
	var applied int
	err = s.DB.QueryRowContext(ctx, `SELECT CASE WHEN to_regclass('schema_migrations') IS NULL THEN -1
		ELSE (SELECT count(*) FROM schema_migrations) END`).Scan(&applied)
	if err != nil {
		return nil, false, err
	}
	names, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return nil, false, err
	}
	sort.Strings(names)
	if applied <= 0 {
		return names, true, nil
	}
	for _, name := range names {
		var done bool
		if err := s.DB.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`,
			strings.TrimSuffix(name, ".sql")).Scan(&done); err != nil {
			return nil, false, err
		}
		if !done {
			pending = append(pending, name)
		}
	}
	return pending, false, nil
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
	UserID     string
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
		SELECT t.id, u.id, u.username, t.name, t.created_at, t.last_used_at, t.revoked_at
		FROM agent_tokens t JOIN users u ON u.id = t.user_id ORDER BY t.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TokenInfo
	for rows.Next() {
		var t TokenInfo
		var used, revoked sql.NullTime
		if err := rows.Scan(&t.ID, &t.UserID, &t.Username, &t.Name, &t.CreatedAt, &used, &revoked); err != nil {
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

// RevokeUserTokens revokes every active token of a user and returns the IDs.
func (s *Store) RevokeUserTokens(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, `UPDATE agent_tokens SET revoked_at = now()
		WHERE user_id::text = $1 AND revoked_at IS NULL RETURNING id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// UsableTokens returns which of ids still authenticate: not revoked, and
// the account exists and is not disabled. The gateway uses it to drop
// agents whose access was taken away by another process (mancard CLI).
func (s *Store) UsableTokens(ctx context.Context, ids []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT t.id FROM agent_tokens t JOIN users u ON u.id = t.user_id
		WHERE t.id::text = ANY($1) AND t.revoked_at IS NULL AND u.disabled_at IS NULL`, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// AuthenticateAgent implements auth.Authenticator. Tokens of a disabled
// account are refused (and work again when it is enabled).
func (s *Store) AuthenticateAgent(ctx context.Context, token string) (auth.Principal, error) {
	var p auth.Principal
	err := s.DB.QueryRowContext(ctx, `
		UPDATE agent_tokens t SET last_used_at = now()
		FROM users u
		WHERE t.token_hash = $1 AND t.revoked_at IS NULL AND u.id = t.user_id AND u.disabled_at IS NULL
		RETURNING t.id, t.user_id`, auth.HashToken(token)).Scan(&p.TokenID, &p.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.Principal{}, auth.ErrInvalidToken
	}
	return p, err
}

// UserInfo summarises an account for the dashboard.
type UserInfo struct {
	Account
	ActiveTokens  int
	Domains       int
	CustomDomains int
}

// ListUsers returns every account with token and hostname counts, by name.
func (s *Store) ListUsers(ctx context.Context) ([]UserInfo, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT `+accountCols+`,
		       (SELECT count(*) FROM agent_tokens t WHERE t.user_id = u.id AND t.revoked_at IS NULL),
		       (SELECT count(*) FROM domains d WHERE d.user_id = u.id),
		       (SELECT count(*) FROM domains d WHERE d.user_id = u.id AND d.kind = 'custom')
		FROM users u ORDER BY u.username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserInfo
	for rows.Next() {
		var u UserInfo
		a, err := scanAccount(rows, &u.ActiveTokens, &u.Domains, &u.CustomDomains)
		if err != nil {
			return nil, err
		}
		u.Account = a
		out = append(out, u)
	}
	return out, rows.Err()
}

// DeleteUser removes a user and, by cascade, their tokens and hostnames, and
// deletes their captured requests and traffic statistics.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	for _, table := range []string{"captured_requests", "usage_hourly", "usage_daily", "usage_total"} {
		if _, err := s.DB.ExecContext(ctx, `DELETE FROM `+table+` WHERE user_id::text = $1`, id); err != nil {
			return err
		}
	}
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
	UserID    string
	Username  string
	Kind      string
	Online    bool
	HoldUntil time.Time
}

// ListDomains returns every reserved hostname, by name.
func (s *Store) ListDomains(ctx context.Context) ([]DomainInfo, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT d.hostname, u.id, u.username, d.kind, d.active_tunnel_id IS NOT NULL, d.hold_until
		FROM domains d JOIN users u ON u.id = d.user_id ORDER BY d.hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DomainInfo
	for rows.Next() {
		var d DomainInfo
		if err := rows.Scan(&d.Hostname, &d.UserID, &d.Username, &d.Kind, &d.Online, &d.HoldUntil); err != nil {
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

// ---- request inspector --------------------------------------------------

// InsertCaptures stores sealed captures in one statement.
func (s *Store) InsertCaptures(ctx context.Context, rows []inspect.Row) error {
	if len(rows) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString(`INSERT INTO captured_requests (id, user_id, hostname, status, duration_ms,
		request_bytes, response_bytes, created_at, nonce, ciphertext) VALUES `)
	args := make([]any, 0, len(rows)*10)
	for i, r := range rows {
		if i > 0 {
			b.WriteString(",")
		}
		n := i * 10
		fmt.Fprintf(&b, "($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)", n+1, n+2, n+3, n+4, n+5, n+6, n+7, n+8, n+9, n+10)
		var uid any
		if r.UserID != "" {
			uid = r.UserID
		}
		args = append(args, r.ID, uid, r.Hostname, r.Status, r.DurationMs, r.ReqSize, r.RespSize, r.CreatedAt, r.Nonce, r.Ciphertext)
	}
	b.WriteString(` ON CONFLICT DO NOTHING`)
	_, err := s.DB.ExecContext(ctx, b.String(), args...)
	return err
}

const captureCols = `id, coalesce(user_id::text, ''), hostname, status, duration_ms, request_bytes, response_bytes, created_at, nonce, ciphertext`

func scanCapture(row interface{ Scan(...any) error }) (inspect.Row, error) {
	var r inspect.Row
	err := row.Scan(&r.ID, &r.UserID, &r.Hostname, &r.Status, &r.DurationMs, &r.ReqSize, &r.RespSize, &r.CreatedAt, &r.Nonce, &r.Ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return inspect.Row{}, ErrNotFound
	}
	return r, err
}

// ListCaptures returns captures newest first.
func (s *Store) ListCaptures(ctx context.Context, f inspect.Filter) ([]inspect.Row, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	before := f.Before
	if before.IsZero() {
		before = time.Now().Add(time.Hour)
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT `+captureCols+` FROM captured_requests
		WHERE ($1 = '' OR hostname = $1) AND created_at < $2 AND ($4 = '' OR user_id::text = $4)
		ORDER BY created_at DESC LIMIT $3`, strings.ToLower(f.Hostname), before, f.Limit, f.UserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []inspect.Row
	for rows.Next() {
		r, err := scanCapture(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetCapture returns one capture.
func (s *Store) GetCapture(ctx context.Context, id string) (inspect.Row, error) {
	return scanCapture(s.DB.QueryRowContext(ctx, `SELECT `+captureCols+` FROM captured_requests WHERE id::text = $1`, id))
}

// DeleteCaptures deletes the captures of one hostname, or all when empty.
func (s *Store) DeleteCaptures(ctx context.Context, hostname string) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM captured_requests WHERE $1 = '' OR hostname = $1`, strings.ToLower(hostname))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteUserCaptures deletes one account's captures, of one hostname or all
// of them when hostname is empty.
func (s *Store) DeleteUserCaptures(ctx context.Context, userID, hostname string) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM captured_requests WHERE user_id::text = $1 AND ($2 = '' OR hostname = $2)`,
		userID, strings.ToLower(hostname))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PurgeCaptures enforces retention: it deletes captures older than
// olderThan and then everything beyond the newest keep rows.
func (s *Store) PurgeCaptures(ctx context.Context, olderThan time.Time, keep int) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM captured_requests WHERE created_at < $1`, olderThan)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	res, err = s.DB.ExecContext(ctx, `DELETE FROM captured_requests WHERE created_at < (
		SELECT created_at FROM captured_requests ORDER BY created_at DESC OFFSET $1 LIMIT 1)`, keep-1)
	if err != nil {
		return n, err
	}
	m, _ := res.RowsAffected()
	return n + m, nil
}

// ---- traffic statistics -------------------------------------------------

// upsertCounts adds counts to table in one statement. keyCols name the
// conflict target and keys holds each row's key values; extra names further
// columns ("first_seen,last_seen") whose values are in extraVals.
func upsertCounts(ctx context.Context, tx *sql.Tx, table string, keyCols []string, extra string,
	keys [][]any, counts []usage.Totals, extraVals [][]any) error {
	if len(keys) == 0 {
		return nil
	}
	cols := append(append([]string{}, keyCols...), "requests", "errors", "bytes_in", "bytes_out")
	if extra != "" {
		cols = append(cols, strings.Split(extra, ",")...)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "INSERT INTO %s AS u (%s) VALUES ", table, strings.Join(cols, ", "))
	args := make([]any, 0, len(keys)*len(cols))
	for i := range keys {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("(")
		row := append(append([]any{}, keys[i]...), counts[i].Requests, counts[i].Errors, counts[i].BytesIn, counts[i].BytesOut)
		if extraVals != nil {
			row = append(row, extraVals[i]...)
		}
		for j, v := range row {
			if j > 0 {
				b.WriteString(",")
			}
			args = append(args, v)
			fmt.Fprintf(&b, "$%d", len(args))
		}
		b.WriteString(")")
	}
	fmt.Fprintf(&b, ` ON CONFLICT (%s) DO UPDATE SET
		requests = u.requests + EXCLUDED.requests, errors = u.errors + EXCLUDED.errors,
		bytes_in = u.bytes_in + EXCLUDED.bytes_in, bytes_out = u.bytes_out + EXCLUDED.bytes_out`, strings.Join(keyCols, ", "))
	if extra != "" {
		b.WriteString(`, last_seen = greatest(u.last_seen, EXCLUDED.last_seen)`)
	}
	_, err := tx.ExecContext(ctx, b.String(), args...)
	return err
}

func addTotals(dst *usage.Totals, r usage.Row) {
	dst.Requests += r.Requests
	dst.Errors += r.Errors
	dst.BytesIn += r.BytesIn
	dst.BytesOut += r.BytesOut
}

// AddUsage adds hourly counts to the hourly, daily and lifetime tables in
// one transaction, so the three always agree.
func (s *Store) AddUsage(ctx context.Context, rows []usage.Row) error {
	if len(rows) == 0 {
		return nil
	}
	// One INSERT ... ON CONFLICT may not touch the same row twice, so rows
	// are first combined per key of each table.
	type hourKey struct {
		host, user string
		hour       time.Time
	}
	type dayKey struct{ host, user, day string }
	type totalKey struct{ host, user string }
	hours, days, totals := map[hourKey]*usage.Totals{}, map[dayKey]*usage.Totals{}, map[totalKey]*usage.Totals{}
	first, last := map[totalKey]time.Time{}, map[totalKey]time.Time{}
	var hourOrder []hourKey
	var dayOrder []dayKey
	var totalOrder []totalKey
	for _, r := range rows {
		hk := hourKey{r.Hostname, r.UserID, r.Hour.UTC()}
		if hours[hk] == nil {
			hours[hk] = &usage.Totals{}
			hourOrder = append(hourOrder, hk)
		}
		addTotals(hours[hk], r)
		dk := dayKey{r.Hostname, r.UserID, r.Hour.UTC().Format("2006-01-02")}
		if days[dk] == nil {
			days[dk] = &usage.Totals{}
			dayOrder = append(dayOrder, dk)
		}
		addTotals(days[dk], r)
		tk := totalKey{r.Hostname, r.UserID}
		if totals[tk] == nil {
			totals[tk] = &usage.Totals{}
			totalOrder = append(totalOrder, tk)
			first[tk], last[tk] = r.Hour, r.Hour
		}
		addTotals(totals[tk], r)
		if r.Hour.Before(first[tk]) {
			first[tk] = r.Hour
		}
		if r.Hour.After(last[tk]) {
			last[tk] = r.Hour
		}
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var keys [][]any
	var counts []usage.Totals
	for _, k := range hourOrder {
		keys, counts = append(keys, []any{k.host, k.hour, k.user}), append(counts, *hours[k])
	}
	if err := upsertCounts(ctx, tx, "usage_hourly", []string{"hostname", "hour", "user_id"}, "", keys, counts, nil); err != nil {
		return err
	}
	keys, counts = nil, nil
	for _, k := range dayOrder {
		keys, counts = append(keys, []any{k.host, k.day, k.user}), append(counts, *days[k])
	}
	if err := upsertCounts(ctx, tx, "usage_daily", []string{"hostname", "day", "user_id"}, "", keys, counts, nil); err != nil {
		return err
	}
	keys, counts = nil, nil
	var seen [][]any
	for _, k := range totalOrder {
		keys, counts = append(keys, []any{k.host, k.user}), append(counts, *totals[k])
		seen = append(seen, []any{first[k], last[k]})
	}
	if err := upsertCounts(ctx, tx, "usage_total", []string{"hostname", "user_id"}, "first_seen,last_seen", keys, counts, seen); err != nil {
		return err
	}
	return tx.Commit()
}

// PurgeUsage deletes hourly counts older than before. Daily and lifetime
// counts are kept forever.
func (s *Store) PurgeUsage(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM usage_hourly WHERE hour < $1`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// UsageWindows are the periods the dashboard shows.
type UsageWindows struct {
	Day   usage.Totals `json:"day"`
	Week  usage.Totals `json:"week"`
	Total usage.Totals `json:"total"` // since the hostname was first used
}

// usageBy sums the last 24 hours, the last 7 days and all time, grouped by
// col (hostname or user_id).
func (s *Store) usageBy(ctx context.Context, col string) (map[string]UsageWindows, error) {
	out := map[string]UsageWindows{}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT `+col+`::text,
		       coalesce(sum(requests)  FILTER (WHERE hour >= now() - interval '24 hours'), 0),
		       coalesce(sum(errors)    FILTER (WHERE hour >= now() - interval '24 hours'), 0),
		       coalesce(sum(bytes_in)  FILTER (WHERE hour >= now() - interval '24 hours'), 0),
		       coalesce(sum(bytes_out) FILTER (WHERE hour >= now() - interval '24 hours'), 0),
		       sum(requests), sum(errors), sum(bytes_in), sum(bytes_out)
		FROM usage_hourly WHERE hour >= now() - interval '7 days'
		GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k string
		var w UsageWindows
		if err := rows.Scan(&k, &w.Day.Requests, &w.Day.Errors, &w.Day.BytesIn, &w.Day.BytesOut,
			&w.Week.Requests, &w.Week.Errors, &w.Week.BytesIn, &w.Week.BytesOut); err != nil {
			rows.Close()
			return nil, err
		}
		out[k] = w
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = s.DB.QueryContext(ctx, `SELECT `+col+`::text, sum(requests), sum(errors), sum(bytes_in), sum(bytes_out)
		FROM usage_total GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var t usage.Totals
		if err := rows.Scan(&k, &t.Requests, &t.Errors, &t.BytesIn, &t.BytesOut); err != nil {
			return nil, err
		}
		w := out[k]
		w.Total = t
		out[k] = w
	}
	return out, rows.Err()
}

// UsageByHost returns 24-hour, 7-day and lifetime totals per hostname.
func (s *Store) UsageByHost(ctx context.Context) (map[string]UsageWindows, error) {
	return s.usageBy(ctx, "hostname")
}

// UsageByUser returns 24-hour, 7-day and lifetime totals per user ID.
func (s *Store) UsageByUser(ctx context.Context) (map[string]UsageWindows, error) {
	return s.usageBy(ctx, "user_id")
}

// ---- domain.Registry ---------------------------------------------------

// Claim implements domain.Registry with a single atomic statement: the
// UNIQUE(hostname) constraint serialises concurrent claims, and the WHERE
// clause on the conflict branch encodes the ownership rules.
func (s *Store) Claim(ctx context.Context, c domain.Claim) (string, error) {
	// A user with a custom subdomain limit may hold at most that many custom
	// names (admins and accounts without a limit are not counted). The check
	// is not part of the claim statement, so two concurrent claims can both
	// pass it; the limit is a fair-use rule, not a security boundary.
	if c.Kind == domain.KindCustom {
		var over bool
		err := s.DB.QueryRowContext(ctx, `
			SELECT u.role = 'user' AND u.max_custom_domains IS NOT NULL AND u.max_custom_domains <= (
				SELECT count(*) FROM domains d
				WHERE d.user_id = u.id AND d.kind = 'custom' AND d.hostname <> $2)
			FROM users u WHERE u.id::text = $1`, c.OwnerID, c.Hostname).Scan(&over)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return "", err
		}
		if over {
			return "", domain.ErrLimitReached
		}
	}
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
