// Package domain implements the Domain Registry: hostname validation, random
// name generation and atomic hostname reservation.
//
// Responsibility: decide who may use which public hostname. Random and custom
// hostnames go through exactly the same Registry.Claim call; availability is
// decided by the registry (the database in production), never by DNS lookups.
//
// Interfaces:
//   - Registry: storage contract (atomic Claim / Release). Implemented by
//     MemoryRegistry here and by internal/store/postgres.
//   - Service: business rules on top of a Registry, used by the gateway.
package domain

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"
)

// Hostname kinds.
const (
	KindRandom = "random"
	KindCustom = "custom"
)

var (
	// ErrHostnameTaken means the hostname is active or held by another owner.
	ErrHostnameTaken = errors.New("domain: hostname is not available")
	// ErrInvalidLabel means the requested subdomain is not acceptable.
	ErrInvalidLabel = errors.New("domain: invalid subdomain")
	// ErrExhausted means no free random hostname could be found.
	ErrExhausted = errors.New("domain: could not allocate a random hostname")
	// ErrLimitReached means the owner holds as many custom hostnames as
	// their account allows.
	ErrLimitReached = errors.New("domain: custom subdomain limit reached")
)

// Claim is one reservation request.
type Claim struct {
	Hostname string
	OwnerID  string
	Kind     string
	TunnelID string
}

// Registry is the storage contract for hostname reservations.
//
// Claim must be atomic: when several callers race for one hostname exactly
// one succeeds. A claim succeeds when the hostname
//   - has never been claimed, or
//   - is inactive and owned by the same owner (reconnect / reuse), or
//   - is inactive and its hold period has expired.
//
// It returns the effective kind: an owner re-claiming a name it still holds
// keeps the original kind, so a random name does not turn into a long-lived
// custom reservation just because the agent reconnected to it.
type Registry interface {
	Claim(ctx context.Context, c Claim) (kind string, err error)
	// Release marks the hostname inactive if tunnelID still owns it and
	// keeps it reserved for the owner for the hold duration.
	Release(ctx context.Context, hostname, tunnelID string, hold time.Duration) error
	// ReleaseAll clears every active marker. Called at gateway start-up,
	// when no tunnel can possibly be connected (single-node deployment).
	ReleaseAll(ctx context.Context, hold time.Duration) error
	// Purge deletes inactive reservations whose hold has expired.
	Purge(ctx context.Context) error
}

var labelRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$`)

// reservedLabels can never be claimed as tunnel subdomains: they are either
// used by the platform itself or are classic phishing / takeover targets.
var reservedLabels = map[string]struct{}{}

func init() {
	for _, l := range strings.Fields(`www api app admin dashboard console panel
		auth login sso oauth account accounts mail smtp imap pop ftp ssh vpn
		ns ns1 ns2 dns mx autoconfig autodiscover wpad localhost internal
		static assets cdn status health metrics agent tunnel gateway edge
		root support security abuse postmaster hostmaster webmaster`) {
		reservedLabels[l] = struct{}{}
	}
}

// NormalizeLabel lower-cases and trims a user supplied subdomain.
func NormalizeLabel(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// ValidateLabel checks a single, already normalized DNS label.
func ValidateLabel(label string) error {
	switch {
	case len(label) < 3 || len(label) > 63:
		return fmt.Errorf("%w: must be 3-63 characters", ErrInvalidLabel)
	case !labelRE.MatchString(label):
		return fmt.Errorf("%w: use a-z, 0-9 and '-', starting and ending with a letter or digit", ErrInvalidLabel)
	case strings.Contains(label, "--"):
		// Also rejects punycode ("xn--") labels, avoiding homograph hosts.
		return fmt.Errorf("%w: consecutive hyphens are not allowed", ErrInvalidLabel)
	}
	if _, ok := reservedLabels[label]; ok {
		return fmt.Errorf("%w: %q is reserved", ErrInvalidLabel, label)
	}
	return nil
}

// Lease is a successful reservation held by one tunnel.
type Lease struct {
	Hostname string
	Kind     string
}

// ServiceOptions configures a Service.
type ServiceOptions struct {
	BaseDomain string
	HoldCustom time.Duration // how long a custom name stays reserved after disconnect
	HoldRandom time.Duration // same for random names (covers short reconnects)
	// Generate returns a random label; nil uses the built-in word lists.
	Generate func() string
}

// Service applies hostname business rules on top of a Registry.
type Service struct {
	reg  Registry
	opts ServiceOptions
}

// NewService builds a Service.
func NewService(reg Registry, opts ServiceOptions) *Service {
	if opts.Generate == nil {
		opts.Generate = RandomLabel
	}
	if opts.HoldCustom <= 0 {
		opts.HoldCustom = 24 * time.Hour
	}
	if opts.HoldRandom <= 0 {
		opts.HoldRandom = 5 * time.Minute
	}
	opts.BaseDomain = strings.ToLower(opts.BaseDomain)
	return &Service{reg: reg, opts: opts}
}

// Acquire reserves a hostname for tunnelID. An empty label requests a random
// hostname.
func (s *Service) Acquire(ctx context.Context, ownerID, label, tunnelID string) (Lease, error) {
	label = NormalizeLabel(label)
	if label != "" {
		if err := ValidateLabel(label); err != nil {
			return Lease{}, err
		}
		host := label + "." + s.opts.BaseDomain
		kind, err := s.reg.Claim(ctx, Claim{Hostname: host, OwnerID: ownerID, Kind: KindCustom, TunnelID: tunnelID})
		if err != nil {
			s.undoClaim(err, host, tunnelID, KindCustom)
			return Lease{}, err
		}
		return Lease{Hostname: host, Kind: kind}, nil
	}
	const attempts = 20
	for i := 0; i < attempts; i++ {
		l := s.opts.Generate()
		if i >= attempts/2 { // name space is getting crowded: widen it
			l = fmt.Sprintf("%s-%04d", l, randInt(10000))
		}
		if ValidateLabel(l) != nil {
			continue
		}
		host := l + "." + s.opts.BaseDomain
		kind, err := s.reg.Claim(ctx, Claim{Hostname: host, OwnerID: ownerID, Kind: KindRandom, TunnelID: tunnelID})
		if errors.Is(err, ErrHostnameTaken) {
			continue
		}
		if err != nil {
			s.undoClaim(err, host, tunnelID, KindRandom)
			return Lease{}, err
		}
		return Lease{Hostname: host, Kind: kind}, nil
	}
	return Lease{}, ErrExhausted
}

// undoClaim releases host for tunnelID after an unexpected Claim error (a
// timeout, a lost connection): the claim may have been committed although
// the answer never arrived, which would leave the name marked active until
// the next restart. Release only touches a row held by tunnelID, so this is
// a no-op when nothing was written.
func (s *Service) undoClaim(err error, host, tunnelID, kind string) {
	if errors.Is(err, ErrHostnameTaken) || errors.Is(err, ErrLimitReached) || errors.Is(err, ErrInvalidLabel) {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = s.reg.Release(ctx, host, tunnelID, s.hold(kind))
	}()
}

// Release returns a lease, keeping the name held for its owner for a while.
func (s *Service) Release(ctx context.Context, l Lease, tunnelID string) error {
	return s.reg.Release(ctx, l.Hostname, tunnelID, s.hold(l.Kind))
}

// Reset clears stale active markers at start-up and purges expired rows.
func (s *Service) Reset(ctx context.Context) error {
	if err := s.reg.ReleaseAll(ctx, s.opts.HoldRandom); err != nil {
		return err
	}
	return s.reg.Purge(ctx)
}

// Purge removes expired reservations.
func (s *Service) Purge(ctx context.Context) error { return s.reg.Purge(ctx) }

func (s *Service) hold(kind string) time.Duration {
	if kind == KindCustom {
		return s.opts.HoldCustom
	}
	return s.opts.HoldRandom
}

func randInt(n int64) int64 {
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		panic("domain: crypto/rand failed: " + err.Error())
	}
	return v.Int64()
}

var adjectives = strings.Fields(`amber ancient autumn azure bold brave bright calm
	clever cosmic crimson crystal daring dawn eager early electric emerald
	fancy fearless gentle golden grand happy hidden humble icy jolly keen
	lively lucky lunar mellow mighty misty noble olive polar proud quick
	quiet rapid royal rustic scarlet silent silver snowy solar steady stormy
	sunny swift tidy vivid wild winter wise young blue green red violet`)

var nouns = strings.Fields(`falcon otter tiger panda eagle whale heron badger
	beaver bison cobra crane dingo dolphin ferret finch gecko hawk ibis
	jaguar koala lemur lynx marmot moose newt ocelot osprey owl panther
	puffin quail raven robin salmon seal shark sparrow stork swan tapir
	toucan turtle viper walrus wombat yak zebra comet delta ember forest
	glacier harbor island meadow nebula orchid prairie river summit canyon`)

// RandomLabel returns an "adjective-noun" label such as "blue-falcon".
func RandomLabel() string {
	return adjectives[randInt(int64(len(adjectives)))] + "-" + nouns[randInt(int64(len(nouns)))]
}
