// Package config loads and validates the gateway configuration from the
// environment. Only seven variables are required in production; everything
// else has a safe default. All problems are reported together so an operator
// can fix the .env file in one pass.
package config

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tinoimammp/mancar/internal/auth"
	"github.com/tinoimammp/mancar/internal/netutil"
)

// Config is the validated gateway configuration.
type Config struct {
	Env          string
	BaseDomain   string
	ListenAddr   string
	PublicScheme string
	PublicPort   string
	LogLevel     string

	Storage       string // "postgres" or "memory" (development only)
	DatabaseURL   string
	DevAgentToken string

	// JWTSecret keys the dashboard session cookies. EncryptionKey encrypts
	// captured requests (request inspector).
	JWTSecret     string
	EncryptionKey []byte

	TCPPortMin, TCPPortMax int
	TrustedProxies         []netip.Prefix

	MaxTunnelsPerAgent    int
	MaxAgentsPerUser      int
	MaxConnsPerTunnel     int
	MaxRequestBodyBytes   int64
	AuthFailureLimit      int // failed agent logins per client address per minute; 0 = unlimited
	ResponseHeaderTimeout time.Duration
	HoldCustom            time.Duration
	HoldRandom            time.Duration

	// Request inspector (needs PostgreSQL and ENCRYPTION_KEY).
	Inspect          bool
	InspectRetention time.Duration
	InspectMaxBody   int
	InspectMaxRows   int

	// Web sign up (needs PostgreSQL and SMTP_URL: the address is confirmed
	// by email). SMTPURL also enables "forgot password" when sign up is off.
	RegisterEnabled bool
	SMTPURL         string
}

// Error lists every configuration problem found.
type Error struct{ Problems []string }

func (e *Error) Error() string {
	return "invalid configuration:\n  - " + strings.Join(e.Problems, "\n  - ")
}

var domainRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

var placeholders = map[string]bool{"": true, "changeme": true, "change-me": true, "secret": true, "password": true}

// IsProduction reports whether production safety rules apply.
func (c *Config) IsProduction() bool { return c.Env == "production" }

// PublicURL renders the public URL for an HTTP tunnel hostname.
func (c *Config) PublicURL(hostname string) string {
	if c.PublicPort != "" {
		return c.PublicScheme + "://" + hostname + ":" + c.PublicPort
	}
	return c.PublicScheme + "://" + hostname
}

// Load reads configuration through getenv (os.Getenv in production).
func Load(getenv func(string) string) (*Config, error) {
	var problems []string
	bad := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	get := func(key, def string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		return def
	}
	getInt := func(key string, def, min int) int {
		v, err := strconv.Atoi(get(key, strconv.Itoa(def)))
		if err != nil || v < min {
			bad("%s must be an integer >= %d", key, min)
			return def
		}
		return v
	}
	getDur := func(key, def string) time.Duration {
		d, err := time.ParseDuration(get(key, def))
		if err != nil || d <= 0 {
			bad("%s must be a positive duration such as 30s or 24h", key)
		}
		return d
	}

	c := &Config{
		Env:          strings.ToLower(get("APP_ENV", "production")),
		BaseDomain:   strings.ToLower(strings.TrimSuffix(get("BASE_DOMAIN", ""), ".")),
		ListenAddr:   get("LISTEN_ADDR", ":8080"),
		PublicScheme: strings.ToLower(get("PUBLIC_SCHEME", "https")),
		PublicPort:   get("PUBLIC_PORT", ""),
		LogLevel:     strings.ToLower(get("LOG_LEVEL", "info")),
	}
	if c.Env != "production" && c.Env != "development" {
		bad("APP_ENV must be \"production\" or \"development\" (got %q)", c.Env)
	}
	switch {
	case c.BaseDomain == "":
		bad("BASE_DOMAIN is required (for example: tunnel.example.com)")
	case !domainRE.MatchString(c.BaseDomain):
		bad("BASE_DOMAIN %q is not a valid domain name (no scheme, port or wildcard)", c.BaseDomain)
	}
	if c.PublicScheme != "http" && c.PublicScheme != "https" {
		bad("PUBLIC_SCHEME must be http or https")
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		bad("LOG_LEVEL must be debug, info, warn or error (got %q)", c.LogLevel)
	}
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		bad("LISTEN_ADDR %q must look like host:port, for example :8080", c.ListenAddr)
	}
	if c.PublicPort != "" {
		if n, err := strconv.Atoi(c.PublicPort); err != nil || n < 1 || n > 65535 {
			bad("PUBLIC_PORT must be a port number between 1 and 65535 (or empty)")
		}
	}

	c.Storage = strings.ToLower(get("STORAGE", "postgres"))
	switch c.Storage {
	case "postgres":
		c.DatabaseURL = get("DATABASE_URL", "")
		if c.DatabaseURL == "" {
			pw := getenv("POSTGRES_PASSWORD")
			if placeholders[strings.ToLower(pw)] {
				bad("POSTGRES_PASSWORD is required and must not be a placeholder value")
			}
			u := url.URL{
				Scheme: "postgres",
				User:   url.UserPassword(get("POSTGRES_USER", "mancar"), pw),
				Host:   get("POSTGRES_HOST", "postgres") + ":" + get("POSTGRES_PORT", "5432"),
				Path:   "/" + get("POSTGRES_DB", "mancar"),
			}
			q := url.Values{"sslmode": {get("POSTGRES_SSLMODE", "disable")}}
			u.RawQuery = q.Encode()
			c.DatabaseURL = u.String()
		}
	case "memory":
		if c.Env == "production" {
			bad("STORAGE=memory is only allowed with APP_ENV=development")
		}
		c.DevAgentToken = get("DEV_AGENT_TOKEN", "")
		if c.DevAgentToken != "" && !auth.WellFormed(c.DevAgentToken) {
			bad("DEV_AGENT_TOKEN must be %q followed by 64 characters (generate one with: mancard token generate)", auth.TokenPrefix)
		}
	default:
		bad("STORAGE must be postgres or memory")
	}

	c.JWTSecret = getenv("JWT_SECRET")
	encKey := strings.TrimSpace(getenv("ENCRYPTION_KEY"))
	if c.Env == "production" || c.JWTSecret != "" {
		if len(c.JWTSecret) < 32 || placeholders[strings.ToLower(c.JWTSecret)] {
			bad("JWT_SECRET is required and must be at least 32 characters (generate with: openssl rand -hex 32)")
		}
	}
	if c.Env == "production" || encKey != "" {
		key, err := hex.DecodeString(encKey)
		if err != nil || len(key) != 32 {
			bad("ENCRYPTION_KEY is required and must be exactly 64 hex characters (generate with: openssl rand -hex 32)")
		}
		c.EncryptionKey = key
	}

	if r := strings.ToLower(get("TCP_PORT_RANGE", "20000-20099")); r != "off" {
		lo, hi, ok := strings.Cut(r, "-")
		min, err1 := strconv.Atoi(lo)
		max, err2 := strconv.Atoi(hi)
		if !ok || err1 != nil || err2 != nil || min < 1024 || max > 65535 || min > max {
			bad("TCP_PORT_RANGE must look like 20000-20099 (ports 1024-65535) or \"off\"")
		} else {
			c.TCPPortMin, c.TCPPortMax = min, max
		}
	}

	tp, err := netutil.ParsePrefixes(get("TRUSTED_PROXIES",
		"127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128,fc00::/7"))
	if err != nil {
		bad("TRUSTED_PROXIES must be a comma separated list of CIDR ranges: %v", err)
	}
	c.TrustedProxies = tp

	c.MaxTunnelsPerAgent = getInt("MAX_TUNNELS_PER_AGENT", 10, 1)
	c.MaxAgentsPerUser = getInt("MAX_AGENTS_PER_USER", 10, 1)
	c.MaxConnsPerTunnel = getInt("MAX_CONNECTIONS_PER_TUNNEL", 256, 1)
	c.MaxRequestBodyBytes = int64(getInt("MAX_REQUEST_BODY_BYTES", 100<<20, 0))
	c.AuthFailureLimit = getInt("AUTH_FAILURE_LIMIT_PER_MINUTE", 10, 0)
	c.ResponseHeaderTimeout = getDur("RESPONSE_HEADER_TIMEOUT", "2m")
	c.HoldCustom = getDur("HOSTNAME_HOLD_CUSTOM", "24h")
	c.HoldRandom = getDur("HOSTNAME_HOLD_RANDOM", "5m")

	switch v := strings.ToLower(get("INSPECT", "on")); v {
	case "on", "true", "1":
		c.Inspect = true
	case "off", "false", "0":
	default:
		bad("INSPECT must be on or off (got %q)", v)
	}
	c.InspectRetention = getDur("INSPECT_RETENTION", "24h")
	c.InspectMaxBody = getInt("INSPECT_MAX_BODY_BYTES", 64<<10, 0)
	c.InspectMaxRows = getInt("INSPECT_MAX_ROWS", 50_000, 1)
	if c.InspectMaxBody > 1<<20 {
		bad("INSPECT_MAX_BODY_BYTES must be at most 1048576 (1 MiB)")
	}

	switch v := strings.ToLower(get("REGISTER_ENABLED", "false")); v {
	case "on", "true", "1":
		c.RegisterEnabled = true
	case "off", "false", "0":
	default:
		bad("REGISTER_ENABLED must be true or false (got %q)", v)
	}
	c.SMTPURL = get("SMTP_URL", "")
	if c.SMTPURL != "" {
		if u, err := url.Parse(c.SMTPURL); err != nil || (u.Scheme != "smtp" && u.Scheme != "smtps") || u.Hostname() == "" {
			bad("SMTP_URL must look like smtps://user:password@smtp.example.com:465 or smtp://user:password@smtp.example.com:587 (URL-encode special characters in the password)")
		}
	}
	if c.RegisterEnabled {
		if c.SMTPURL == "" {
			bad("REGISTER_ENABLED=true needs SMTP_URL: new accounts confirm their email address")
		}
		if c.Storage != "postgres" {
			bad("REGISTER_ENABLED=true needs STORAGE=postgres")
		}
	}

	if len(problems) > 0 {
		return nil, &Error{Problems: problems}
	}
	return c, nil
}
