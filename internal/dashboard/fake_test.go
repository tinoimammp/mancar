package dashboard_test

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tinoimammp/mancar/internal/mail"
	"github.com/tinoimammp/mancar/internal/store/postgres"
)

// fakeStore is an in-memory dashboard.Store that follows the PostgreSQL
// store's rules (unique names and emails, last admin kept, links once).
type fakeStore struct {
	accounts map[string]postgres.Account // by ID
	tokens   []postgres.TokenInfo
	domains  []postgres.DomainInfo
	usage    map[string]postgres.UsageWindows
	links    map[string]fakeLink // by secret
	audit    []postgres.AuditEntry
	nextID   int
}

type fakeLink struct {
	userID, purpose, email string
	expires                time.Time
}

func newFakeStore() *fakeStore {
	return &fakeStore{accounts: map[string]postgres.Account{}, links: map[string]fakeLink{}}
}

func (f *fakeStore) add(a postgres.Account) {
	if a.Role == "" {
		a.Role = postgres.RoleUser
	}
	f.accounts[a.ID] = a
}

func (f *fakeStore) byName(name string) (postgres.Account, bool) {
	for _, a := range f.accounts {
		if a.Username == name {
			return a, true
		}
	}
	return postgres.Account{}, false
}

func (f *fakeStore) AccountByID(_ context.Context, id string) (postgres.Account, error) {
	if a, ok := f.accounts[id]; ok {
		return a, nil
	}
	return postgres.Account{}, postgres.ErrNotFound
}

func (f *fakeStore) AccountByLogin(ctx context.Context, login string) (postgres.Account, error) {
	login = strings.ToLower(strings.TrimSpace(login))
	if strings.Contains(login, "@") {
		return f.AccountByEmail(ctx, login)
	}
	if a, ok := f.byName(login); ok {
		return a, nil
	}
	return postgres.Account{}, postgres.ErrNotFound
}

func (f *fakeStore) AccountByEmail(_ context.Context, email string) (postgres.Account, error) {
	for _, a := range f.accounts {
		if a.Email != "" && a.Email == postgres.NormalizeEmail(email) {
			return a, nil
		}
	}
	return postgres.Account{}, postgres.ErrNotFound
}

func (f *fakeStore) SetupDone(context.Context) (bool, error) {
	for _, a := range f.accounts {
		if a.IsAdmin() || a.PasswordHash != "" {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeStore) CreateFirstAdmin(ctx context.Context, n postgres.NewAccount) (string, error) {
	if ok, _ := f.SetupDone(ctx); ok {
		return "", postgres.ErrSetupDone
	}
	n.Role, n.Verified = postgres.RoleAdmin, true
	return f.CreateAccount(ctx, n)
}

func (f *fakeStore) TouchLogin(_ context.Context, id string) error { return nil }

func (f *fakeStore) CreateAccount(_ context.Context, n postgres.NewAccount) (string, error) {
	if _, ok := f.byName(n.Username); ok {
		return "", postgres.ErrUsernameTaken
	}
	if n.Email != "" {
		if _, err := f.AccountByEmail(context.Background(), n.Email); err == nil {
			return "", postgres.ErrEmailTaken
		}
	}
	f.nextID++
	a := postgres.Account{ID: fmt.Sprintf("u%d", f.nextID), Username: n.Username, Email: n.Email, PasswordHash: n.PasswordHash,
		Role: n.Role, SignedUp: n.SignedUp, CreatedAt: time.Now(), PasswordChangedAt: time.Now().Add(-time.Minute)}
	if n.Verified && n.Email != "" {
		now := time.Now()
		a.EmailVerifiedAt = &now
	}
	if n.SignedUp {
		t, d := postgres.SignupMaxTokens, postgres.SignupMaxCustomDomains
		a.MaxTokens, a.MaxCustomDomains = &t, &d
	}
	f.add(a)
	return a.ID, nil
}

func (f *fakeStore) update(id string, change func(*postgres.Account)) error {
	a, ok := f.accounts[id]
	if !ok {
		return postgres.ErrNotFound
	}
	change(&a)
	f.accounts[id] = a
	return nil
}

func (f *fakeStore) SetPassword(_ context.Context, id, hash string) error {
	return f.update(id, func(a *postgres.Account) { a.PasswordHash, a.PasswordChangedAt = hash, time.Now() })
}

func (f *fakeStore) EndSessions(_ context.Context, id string) error {
	return f.update(id, func(a *postgres.Account) { a.PasswordChangedAt = time.Now() })
}

func (f *fakeStore) SetEmailVerified(_ context.Context, id string, v bool) error {
	return f.update(id, func(a *postgres.Account) {
		a.EmailVerifiedAt = nil
		if v {
			now := time.Now()
			a.EmailVerifiedAt = &now
		}
	})
}

func (f *fakeStore) SetEmail(_ context.Context, id, email string) error {
	if other, err := f.AccountByEmail(context.Background(), email); err == nil && other.ID != id {
		return postgres.ErrEmailTaken
	}
	return f.update(id, func(a *postgres.Account) { a.Email, a.EmailVerifiedAt = email, nil })
}

func (f *fakeStore) SetLimits(_ context.Context, id string, t, d *int) error {
	return f.update(id, func(a *postgres.Account) { a.MaxTokens, a.MaxCustomDomains = t, d })
}

func (f *fakeStore) activeAdmins() int {
	n := 0
	for _, a := range f.accounts {
		if a.IsAdmin() && a.DisabledAt == nil {
			n++
		}
	}
	return n
}

// guard applies change and undoes it when no active admin is left.
func (f *fakeStore) guard(id string, change func(*postgres.Account)) error {
	before, ok := f.accounts[id]
	if !ok {
		return postgres.ErrNotFound
	}
	f.update(id, change)
	if f.activeAdmins() == 0 {
		f.accounts[id] = before
		return postgres.ErrLastAdmin
	}
	return nil
}

func (f *fakeStore) SetRole(_ context.Context, id, role string) error {
	return f.guard(id, func(a *postgres.Account) { a.Role = role })
}

func (f *fakeStore) SetDisabled(_ context.Context, id string, v bool) error {
	return f.guard(id, func(a *postgres.Account) {
		a.DisabledAt = nil
		if v {
			now := time.Now()
			a.DisabledAt = &now
		}
	})
}

func (f *fakeStore) DeleteAccount(_ context.Context, id string) error {
	a, ok := f.accounts[id]
	if !ok {
		return postgres.ErrNotFound
	}
	delete(f.accounts, id)
	if f.activeAdmins() == 0 {
		f.accounts[id] = a
		return postgres.ErrLastAdmin
	}
	return nil
}

func (f *fakeStore) CreateEmailLink(_ context.Context, userID, purpose string, ttl time.Duration) (string, error) {
	a, ok := f.accounts[userID]
	if !ok || a.Email == "" {
		return "", postgres.ErrNotFound
	}
	for k, l := range f.links {
		if l.userID == userID && l.purpose == purpose {
			delete(f.links, k)
		}
	}
	f.nextID++
	secret := fmt.Sprintf("secret-%s-%d", purpose, f.nextID)
	f.links[secret] = fakeLink{userID, purpose, a.Email, time.Now().Add(ttl)}
	return secret, nil
}

func (f *fakeStore) UseEmailLink(_ context.Context, purpose, secret string) (string, error) {
	l, ok := f.links[secret]
	if !ok || l.purpose != purpose || time.Now().After(l.expires) || f.accounts[l.userID].Email != l.email {
		return "", postgres.ErrLinkInvalid
	}
	delete(f.links, secret)
	return l.userID, nil
}

func (f *fakeStore) PurgeUnconfirmed(context.Context, time.Time) (int64, error) { return 0, nil }

func (f *fakeStore) AddAudit(_ context.Context, e postgres.AuditEntry) error {
	e.At = time.Now()
	f.audit = append(f.audit, e)
	return nil
}

func (f *fakeStore) ListAudit(context.Context, int) ([]postgres.AuditEntry, error) {
	var out []postgres.AuditEntry
	for i := len(f.audit) - 1; i >= 0; i-- { // newest first
		out = append(out, f.audit[i])
	}
	return out, nil
}

func (f *fakeStore) PurgeAudit(context.Context, time.Time) error { return nil }

func (f *fakeStore) ListUsers(context.Context) ([]postgres.UserInfo, error) {
	var out []postgres.UserInfo
	for _, a := range f.accounts {
		out = append(out, postgres.UserInfo{Account: a})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

func (f *fakeStore) EnsureUser(_ context.Context, u string) (string, error) {
	if a, ok := f.byName(u); ok {
		return a.ID, nil
	}
	f.add(postgres.Account{ID: "u-" + u, Username: u})
	return "u-" + u, nil
}

func (f *fakeStore) ListAgentTokens(context.Context) ([]postgres.TokenInfo, error) {
	return f.tokens, nil
}

func (f *fakeStore) CreateAgentToken(_ context.Context, uid, name string) (string, string, error) {
	id := fmt.Sprintf("t%d", len(f.tokens)+1)
	f.tokens = append(f.tokens, postgres.TokenInfo{ID: id, UserID: uid, Username: f.accounts[uid].Username, Name: name})
	return "mc_secret", id, nil
}

func (f *fakeStore) UsableTokens(_ context.Context, ids []string) (map[string]bool, error) {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	out := map[string]bool{}
	for _, t := range f.tokens {
		a, ok := f.accounts[t.UserID]
		if want[t.ID] && t.RevokedAt == nil && ok && a.DisabledAt == nil {
			out[t.ID] = true
		}
	}
	return out, nil
}

func (f *fakeStore) RevokeAgentToken(_ context.Context, id string) error {
	for i := range f.tokens {
		if f.tokens[i].ID == id && f.tokens[i].RevokedAt == nil {
			now := time.Now()
			f.tokens[i].RevokedAt = &now
			return nil
		}
	}
	return postgres.ErrNotFound
}

func (f *fakeStore) RevokeUserTokens(_ context.Context, uid string) ([]string, error) {
	var ids []string
	for i := range f.tokens {
		if f.tokens[i].UserID == uid && f.tokens[i].RevokedAt == nil {
			now := time.Now()
			f.tokens[i].RevokedAt = &now
			ids = append(ids, f.tokens[i].ID)
		}
	}
	return ids, nil
}

func (f *fakeStore) ListDomains(context.Context) ([]postgres.DomainInfo, error) {
	return f.domains, nil
}

func (f *fakeStore) ReleaseDomain(_ context.Context, host string) error {
	for i, x := range f.domains {
		if x.Hostname == host && !x.Online {
			f.domains = append(f.domains[:i], f.domains[i+1:]...)
			return nil
		}
	}
	return postgres.ErrNotFound
}

func (f *fakeStore) UsageByHost(context.Context) (map[string]postgres.UsageWindows, error) {
	return f.usage, nil
}

func (f *fakeStore) UsageByUser(context.Context) (map[string]postgres.UsageWindows, error) {
	return nil, nil
}

// fakeMailer records sent messages.
type fakeMailer struct {
	mu   sync.Mutex
	sent []mail.Message
}

func (m *fakeMailer) Send(_ context.Context, msg mail.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	return nil
}

// wait returns the messages once n have been sent (sending is asynchronous).
func (m *fakeMailer) wait(n int) []mail.Message {
	for i := 0; i < 200; i++ {
		m.mu.Lock()
		if len(m.sent) >= n {
			out := append([]mail.Message{}, m.sent...)
			m.mu.Unlock()
			return out
		}
		m.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]mail.Message{}, m.sent...)
}
