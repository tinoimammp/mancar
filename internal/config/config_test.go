package config_test

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tinoimammp/mancar/internal/config"
)

const (
	validJWT = "0123456789abcdef0123456789abcdef0123456789abcdef" // 48 chars
	validKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
)

type env map[string]string

func (e env) get(k string) string { return e[k] }

func (e env) with(k, v string) env {
	out := env{}
	for key, val := range e {
		out[key] = val
	}
	out[k] = v
	return out
}

func (e env) without(k string) env {
	out := env{}
	for key, val := range e {
		if key != k {
			out[key] = val
		}
	}
	return out
}

func prodEnv() env {
	return env{
		"APP_ENV":           "production",
		"BASE_DOMAIN":       "mydomain.com",
		"JWT_SECRET":        validJWT,
		"ENCRYPTION_KEY":    validKey,
		"POSTGRES_PASSWORD": "s3cr3t-pg-pass",
	}
}

func devEnv() env {
	return env{"APP_ENV": "development", "BASE_DOMAIN": "tunnel.test", "STORAGE": "memory"}
}

func mustLoad(t *testing.T, e env) *config.Config {
	t.Helper()
	c, err := config.Load(e.get)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

func loadWith(e env) (*config.Config, error) { return config.Load(e.get) }

func loadErr(t *testing.T, e env) *config.Error {
	t.Helper()
	c, err := config.Load(e.get)
	if err == nil {
		t.Fatal("Load: expected an error")
	}
	if c != nil {
		t.Error("Load must return a nil Config together with an error")
	}
	var ce *config.Error
	if !errors.As(err, &ce) {
		t.Fatalf("error type = %T, want *config.Error", err)
	}
	return ce
}

func hasProblem(ce *config.Error, substr string) bool {
	for _, p := range ce.Problems {
		if strings.Contains(p, substr) {
			return true
		}
	}
	return false
}

func TestLoad_ProductionDefaults(t *testing.T) {
	c := mustLoad(t, prodEnv())

	if c.Env != "production" || !c.IsProduction() {
		t.Errorf("Env = %q, IsProduction = %v", c.Env, c.IsProduction())
	}
	if c.BaseDomain != "mydomain.com" {
		t.Errorf("BaseDomain = %q", c.BaseDomain)
	}
	if c.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q", c.ListenAddr)
	}
	if c.PublicScheme != "https" || c.PublicPort != "" {
		t.Errorf("PublicScheme/Port = %q/%q", c.PublicScheme, c.PublicPort)
	}
	if c.LogLevel != "info" {
		t.Errorf("LogLevel = %q", c.LogLevel)
	}
	if c.Storage != "postgres" {
		t.Errorf("Storage = %q", c.Storage)
	}
	if c.JWTSecret != validJWT {
		t.Error("JWTSecret not carried over")
	}
	if len(c.EncryptionKey) != 32 {
		t.Errorf("EncryptionKey length = %d, want 32 bytes", len(c.EncryptionKey))
	}
	if c.TCPPortMin != 20000 || c.TCPPortMax != 20099 {
		t.Errorf("TCP range = %d-%d", c.TCPPortMin, c.TCPPortMax)
	}
	if len(c.TrustedProxies) != 6 {
		t.Errorf("default TrustedProxies = %d entries, want 6 private ranges", len(c.TrustedProxies))
	}
	if c.MaxTunnelsPerAgent != 10 || c.MaxAgentsPerUser != 10 || c.MaxConnsPerTunnel != 256 {
		t.Errorf("limits = %d/%d/%d", c.MaxTunnelsPerAgent, c.MaxAgentsPerUser, c.MaxConnsPerTunnel)
	}
	if c.MaxRequestBodyBytes != 100<<20 {
		t.Errorf("MaxRequestBodyBytes = %d", c.MaxRequestBodyBytes)
	}
	if c.ResponseHeaderTimeout != 2*time.Minute {
		t.Errorf("ResponseHeaderTimeout = %v", c.ResponseHeaderTimeout)
	}
	if c.HoldCustom != 24*time.Hour || c.HoldRandom != 5*time.Minute {
		t.Errorf("holds = %v / %v", c.HoldCustom, c.HoldRandom)
	}
}

func TestLoad_AppEnvDefaultsToProduction(t *testing.T) {
	c := mustLoad(t, prodEnv().without("APP_ENV"))
	if c.Env != "production" {
		t.Errorf("Env = %q, want production", c.Env)
	}
}

func TestLoad_DatabaseURLFromPostgresVariables(t *testing.T) {
	c := mustLoad(t, prodEnv())
	u, err := url.Parse(c.DatabaseURL)
	if err != nil {
		t.Fatalf("DatabaseURL %q does not parse: %v", c.DatabaseURL, err)
	}
	pw, _ := u.User.Password()
	if u.Scheme != "postgres" || u.User.Username() != "mancar" || pw != "s3cr3t-pg-pass" ||
		u.Host != "postgres:5432" || u.Path != "/mancar" || u.Query().Get("sslmode") != "disable" {
		t.Errorf("unexpected DatabaseURL: %s", c.DatabaseURL)
	}
}

func TestLoad_DatabaseURLOverridesAreHonoured(t *testing.T) {
	e := prodEnv()
	e["POSTGRES_USER"] = "tunnel"
	e["POSTGRES_HOST"] = "db.internal"
	e["POSTGRES_PORT"] = "6543"
	e["POSTGRES_DB"] = "prod"
	e["POSTGRES_SSLMODE"] = "require"
	c := mustLoad(t, e)
	u, _ := url.Parse(c.DatabaseURL)
	if u.User.Username() != "tunnel" || u.Host != "db.internal:6543" || u.Path != "/prod" || u.Query().Get("sslmode") != "require" {
		t.Errorf("unexpected DatabaseURL: %s", c.DatabaseURL)
	}
}

func TestLoad_PasswordWithSpecialCharactersRoundTrips(t *testing.T) {
	const pw = "p@ss:w/rd?#%&=+ x"
	c := mustLoad(t, prodEnv().with("POSTGRES_PASSWORD", pw))
	u, err := url.Parse(c.DatabaseURL)
	if err != nil {
		t.Fatalf("DatabaseURL does not parse: %v", err)
	}
	got, _ := u.User.Password()
	if got != pw {
		t.Errorf("password after round trip = %q, want %q", got, pw)
	}
	if u.Host != "postgres:5432" {
		t.Errorf("special characters leaked into host: %q", u.Host)
	}
}

func TestLoad_ExplicitDatabaseURLWinsAndNeedsNoPassword(t *testing.T) {
	const dsn = "postgres://u:p@db.example:5432/app?sslmode=require"
	c := mustLoad(t, prodEnv().without("POSTGRES_PASSWORD").with("DATABASE_URL", dsn))
	if c.DatabaseURL != dsn {
		t.Errorf("DatabaseURL = %q", c.DatabaseURL)
	}
}

func TestLoad_NormalisesValues(t *testing.T) {
	e := prodEnv().with("BASE_DOMAIN", "  MyDomain.COM. ").with("PUBLIC_SCHEME", "HTTP").
		with("LOG_LEVEL", "DEBUG").with("APP_ENV", "PRODUCTION")
	c := mustLoad(t, e)
	if c.BaseDomain != "mydomain.com" {
		t.Errorf("BaseDomain = %q", c.BaseDomain)
	}
	if c.PublicScheme != "http" || c.LogLevel != "debug" || c.Env != "production" {
		t.Errorf("scheme/log/env = %q/%q/%q", c.PublicScheme, c.LogLevel, c.Env)
	}
}

func TestLoad_CustomValues(t *testing.T) {
	e := prodEnv()
	e["LISTEN_ADDR"] = "127.0.0.1:9000"
	e["PUBLIC_PORT"] = "8443"
	e["MAX_TUNNELS_PER_AGENT"] = "3"
	e["MAX_AGENTS_PER_USER"] = "4"
	e["MAX_CONNECTIONS_PER_TUNNEL"] = "5"
	e["MAX_REQUEST_BODY_BYTES"] = "0" // unlimited
	e["RESPONSE_HEADER_TIMEOUT"] = "30s"
	e["HOSTNAME_HOLD_CUSTOM"] = "48h"
	e["HOSTNAME_HOLD_RANDOM"] = "10m"
	e["TRUSTED_PROXIES"] = "10.0.0.0/8, 192.168.0.0/16"
	c := mustLoad(t, e)

	if c.ListenAddr != "127.0.0.1:9000" || c.PublicPort != "8443" {
		t.Errorf("listen/public port = %q/%q", c.ListenAddr, c.PublicPort)
	}
	if c.MaxTunnelsPerAgent != 3 || c.MaxAgentsPerUser != 4 || c.MaxConnsPerTunnel != 5 {
		t.Errorf("limits = %d/%d/%d", c.MaxTunnelsPerAgent, c.MaxAgentsPerUser, c.MaxConnsPerTunnel)
	}
	if c.MaxRequestBodyBytes != 0 {
		t.Errorf("MaxRequestBodyBytes = %d, want 0 (unlimited)", c.MaxRequestBodyBytes)
	}
	if c.ResponseHeaderTimeout != 30*time.Second || c.HoldCustom != 48*time.Hour || c.HoldRandom != 10*time.Minute {
		t.Errorf("durations = %v/%v/%v", c.ResponseHeaderTimeout, c.HoldCustom, c.HoldRandom)
	}
	if len(c.TrustedProxies) != 2 || c.TrustedProxies[0].String() != "10.0.0.0/8" || c.TrustedProxies[1].String() != "192.168.0.0/16" {
		t.Errorf("TrustedProxies = %v", c.TrustedProxies)
	}
}

func TestLoad_AllMissingProblemsAreReportedTogether(t *testing.T) {
	ce := loadErr(t, env{}) // APP_ENV defaults to production
	for _, name := range []string{"BASE_DOMAIN", "POSTGRES_PASSWORD", "JWT_SECRET", "ENCRYPTION_KEY"} {
		if !hasProblem(ce, name) {
			t.Errorf("problems should mention %s: %v", name, ce.Problems)
		}
	}
	if len(ce.Problems) < 4 {
		t.Errorf("got %d problems, want all of them in one pass: %v", len(ce.Problems), ce.Problems)
	}
	msg := ce.Error()
	if !strings.HasPrefix(msg, "invalid configuration:") {
		t.Errorf("Error() = %q", msg)
	}
	for _, p := range ce.Problems {
		if !strings.Contains(msg, "  - "+p) {
			t.Errorf("Error() is missing the line for %q", p)
		}
	}
}

func TestLoad_EachRequiredProductionVariable(t *testing.T) {
	for _, name := range []string{"BASE_DOMAIN", "POSTGRES_PASSWORD", "JWT_SECRET", "ENCRYPTION_KEY"} {
		name := name
		t.Run(name, func(t *testing.T) {
			ce := loadErr(t, prodEnv().without(name))
			if !hasProblem(ce, name) {
				t.Errorf("problems should mention %s: %v", name, ce.Problems)
			}
		})
	}
}

func TestLoad_InvalidValues(t *testing.T) {
	tests := []struct{ name, key, val, want string }{
		{"unknown app env", "APP_ENV", "staging", "APP_ENV"},
		{"domain with scheme", "BASE_DOMAIN", "https://mydomain.com", "BASE_DOMAIN"},
		{"domain with port", "BASE_DOMAIN", "mydomain.com:8080", "BASE_DOMAIN"},
		{"domain with path", "BASE_DOMAIN", "mydomain.com/path", "BASE_DOMAIN"},
		{"wildcard domain", "BASE_DOMAIN", "*.mydomain.com", "BASE_DOMAIN"},
		{"single label domain", "BASE_DOMAIN", "localhost", "BASE_DOMAIN"},
		{"leading hyphen", "BASE_DOMAIN", "-bad.com", "BASE_DOMAIN"},
		{"space in domain", "BASE_DOMAIN", "a b.com", "BASE_DOMAIN"},
		{"ip address", "BASE_DOMAIN", "1.2.3.4", "BASE_DOMAIN"},
		{"one letter tld", "BASE_DOMAIN", "mydomain.c", "BASE_DOMAIN"},
		{"bad scheme", "PUBLIC_SCHEME", "ftp", "PUBLIC_SCHEME"},
		{"unknown storage", "STORAGE", "mysql", "STORAGE"},
		{"short jwt", "JWT_SECRET", strings.Repeat("a", 31), "JWT_SECRET"},
		{"placeholder jwt", "JWT_SECRET", "changeme", "JWT_SECRET"},
		{"non-hex key", "ENCRYPTION_KEY", strings.Repeat("z", 64), "ENCRYPTION_KEY"},
		{"short key", "ENCRYPTION_KEY", validKey[:62], "ENCRYPTION_KEY"},
		{"long key", "ENCRYPTION_KEY", validKey + "00", "ENCRYPTION_KEY"},
		{"placeholder password changeme", "POSTGRES_PASSWORD", "changeme", "POSTGRES_PASSWORD"},
		{"placeholder password hyphen", "POSTGRES_PASSWORD", "Change-Me", "POSTGRES_PASSWORD"},
		{"placeholder password secret", "POSTGRES_PASSWORD", "secret", "POSTGRES_PASSWORD"},
		{"placeholder password upper", "POSTGRES_PASSWORD", "PASSWORD", "POSTGRES_PASSWORD"},
		{"port range words", "TCP_PORT_RANGE", "abc", "TCP_PORT_RANGE"},
		{"port range single", "TCP_PORT_RANGE", "30000", "TCP_PORT_RANGE"},
		{"port range privileged", "TCP_PORT_RANGE", "1000-2000", "TCP_PORT_RANGE"},
		{"port range too high", "TCP_PORT_RANGE", "30000-70000", "TCP_PORT_RANGE"},
		{"port range reversed", "TCP_PORT_RANGE", "30010-30000", "TCP_PORT_RANGE"},
		{"trusted proxies junk", "TRUSTED_PROXIES", "not-a-cidr", "TRUSTED_PROXIES"},
		{"trusted proxies bad mask", "TRUSTED_PROXIES", "10.0.0.0/33", "TRUSTED_PROXIES"},
		{"trusted proxies bare ip", "TRUSTED_PROXIES", "10.0.0.1", "TRUSTED_PROXIES"},
		{"tunnels zero", "MAX_TUNNELS_PER_AGENT", "0", "MAX_TUNNELS_PER_AGENT"},
		{"tunnels words", "MAX_TUNNELS_PER_AGENT", "many", "MAX_TUNNELS_PER_AGENT"},
		{"agents negative", "MAX_AGENTS_PER_USER", "-1", "MAX_AGENTS_PER_USER"},
		{"conns zero", "MAX_CONNECTIONS_PER_TUNNEL", "0", "MAX_CONNECTIONS_PER_TUNNEL"},
		{"body negative", "MAX_REQUEST_BODY_BYTES", "-1", "MAX_REQUEST_BODY_BYTES"},
		{"timeout words", "RESPONSE_HEADER_TIMEOUT", "soon", "RESPONSE_HEADER_TIMEOUT"},
		{"timeout zero", "RESPONSE_HEADER_TIMEOUT", "0s", "RESPONSE_HEADER_TIMEOUT"},
		{"hold custom negative", "HOSTNAME_HOLD_CUSTOM", "-5m", "HOSTNAME_HOLD_CUSTOM"},
		{"hold random bad", "HOSTNAME_HOLD_RANDOM", "5 minutes", "HOSTNAME_HOLD_RANDOM"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ce := loadErr(t, prodEnv().with(tc.key, tc.val))
			if !hasProblem(ce, tc.want) {
				t.Errorf("%s=%q: problems should mention %s, got %v", tc.key, tc.val, tc.want, ce.Problems)
			}
		})
	}
}

func TestLoad_ValidDomains(t *testing.T) {
	for _, d := range []string{"mydomain.com", "tunnel.example.com", "a-b.co.uk", "x1.dev", "MYDOMAIN.COM"} {
		if _, err := config.Load(prodEnv().with("BASE_DOMAIN", d).get); err != nil {
			t.Errorf("BASE_DOMAIN=%q rejected: %v", d, err)
		}
	}
}

func TestLoad_TCPPortRange(t *testing.T) {
	t.Run("custom", func(t *testing.T) {
		c := mustLoad(t, prodEnv().with("TCP_PORT_RANGE", "30000-30010"))
		if c.TCPPortMin != 30000 || c.TCPPortMax != 30010 {
			t.Errorf("range = %d-%d", c.TCPPortMin, c.TCPPortMax)
		}
	})
	t.Run("off disables TCP tunnels", func(t *testing.T) {
		for _, v := range []string{"off", "OFF"} {
			c := mustLoad(t, prodEnv().with("TCP_PORT_RANGE", v))
			if c.TCPPortMin != 0 || c.TCPPortMax != 0 {
				t.Errorf("TCP_PORT_RANGE=%s: range = %d-%d, want 0-0", v, c.TCPPortMin, c.TCPPortMax)
			}
		}
	})
	t.Run("single port", func(t *testing.T) {
		c := mustLoad(t, prodEnv().with("TCP_PORT_RANGE", "30000-30000"))
		if c.TCPPortMin != 30000 || c.TCPPortMax != 30000 {
			t.Errorf("range = %d-%d", c.TCPPortMin, c.TCPPortMax)
		}
	})
}

func TestLoad_Development(t *testing.T) {
	t.Run("memory storage needs no secrets", func(t *testing.T) {
		c := mustLoad(t, devEnv())
		if c.IsProduction() || c.Env != "development" {
			t.Errorf("Env = %q", c.Env)
		}
		if c.Storage != "memory" || c.DatabaseURL != "" {
			t.Errorf("Storage/DatabaseURL = %q/%q", c.Storage, c.DatabaseURL)
		}
		if c.JWTSecret != "" || c.EncryptionKey != nil {
			t.Error("secrets should stay empty when not provided in development")
		}
	})
	t.Run("dev agent token is read", func(t *testing.T) {
		c := mustLoad(t, devEnv().with("DEV_AGENT_TOKEN", "mc_"+strings.Repeat("a", 64)))
		if c.DevAgentToken != "mc_"+strings.Repeat("a", 64) {
			t.Errorf("DevAgentToken = %q", c.DevAgentToken)
		}
	})
	t.Run("provided secrets are still validated", func(t *testing.T) {
		if ce := loadErr(t, devEnv().with("JWT_SECRET", "tiny")); !hasProblem(ce, "JWT_SECRET") {
			t.Errorf("short JWT_SECRET accepted: %v", ce.Problems)
		}
		if ce := loadErr(t, devEnv().with("ENCRYPTION_KEY", "nothex")); !hasProblem(ce, "ENCRYPTION_KEY") {
			t.Errorf("bad ENCRYPTION_KEY accepted: %v", ce.Problems)
		}
		c := mustLoad(t, devEnv().with("JWT_SECRET", validJWT).with("ENCRYPTION_KEY", validKey))
		if len(c.EncryptionKey) != 32 {
			t.Errorf("EncryptionKey length = %d", len(c.EncryptionKey))
		}
	})
	t.Run("app env is case-insensitive", func(t *testing.T) {
		if c := mustLoad(t, devEnv().with("APP_ENV", "Development")); c.Env != "development" {
			t.Errorf("Env = %q", c.Env)
		}
	})
	t.Run("postgres storage still requires a password", func(t *testing.T) {
		ce := loadErr(t, devEnv().without("STORAGE"))
		if !hasProblem(ce, "POSTGRES_PASSWORD") {
			t.Errorf("problems: %v", ce.Problems)
		}
	})
}

func TestLoad_MemoryStorageForbiddenInProduction(t *testing.T) {
	ce := loadErr(t, prodEnv().with("STORAGE", "memory"))
	if !hasProblem(ce, "STORAGE=memory") {
		t.Errorf("problems: %v", ce.Problems)
	}
}

func TestLoad_ErrorsNeverEchoSecretValues(t *testing.T) {
	const badKey = "super-secret-but-invalid-value"
	const badJWT = "tiny-secret-xyz"
	e := prodEnv().with("ENCRYPTION_KEY", badKey).with("JWT_SECRET", badJWT).with("POSTGRES_PASSWORD", "changeme")
	_, err := config.Load(e.get)
	if err == nil {
		t.Fatal("expected error")
	}
	for _, secret := range []string{badKey, badJWT} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error leaks secret value %q: %v", secret, err)
		}
	}
}

func TestConfig_PublicURL(t *testing.T) {
	tests := []struct {
		scheme, port, host, want string
	}{
		{"https", "", "a.mydomain.com", "https://a.mydomain.com"},
		{"http", "8080", "a.mydomain.com", "http://a.mydomain.com:8080"},
		{"https", "8443", "x.example.org", "https://x.example.org:8443"},
	}
	for _, tc := range tests {
		c := mustLoad(t, prodEnv().with("PUBLIC_SCHEME", tc.scheme).with("PUBLIC_PORT", tc.port))
		if got := c.PublicURL(tc.host); got != tc.want {
			t.Errorf("PublicURL(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

func TestLoad_RegisterIsOffByDefault(t *testing.T) {
	c := mustLoad(t, prodEnv())
	if c.RegisterEnabled || c.SMTPURL != "" {
		t.Errorf("sign up must be off by default: %+v", c)
	}
}

func TestLoad_RegisterNeedsSMTPAndPostgres(t *testing.T) {
	ce := loadErr(t, prodEnv().with("REGISTER_ENABLED", "true"))
	if !hasProblem(ce, "needs SMTP_URL") {
		t.Errorf("problems: %v", ce.Problems)
	}
	c := mustLoad(t, prodEnv().with("REGISTER_ENABLED", "true").with("SMTP_URL", "smtps://resend:re_x@smtp.resend.com:465"))
	if !c.RegisterEnabled || c.SMTPURL == "" {
		t.Errorf("config: %+v", c)
	}
	ce = loadErr(t, devEnv().with("REGISTER_ENABLED", "true").with("SMTP_URL", "smtp://localhost:1025"))
	if !hasProblem(ce, "needs STORAGE=postgres") {
		t.Errorf("problems: %v", ce.Problems)
	}
	ce = loadErr(t, prodEnv().with("REGISTER_ENABLED", "maybe"))
	if !hasProblem(ce, "REGISTER_ENABLED must be true or false") {
		t.Errorf("problems: %v", ce.Problems)
	}
}

func TestLoad_SMTPURLIsValidated(t *testing.T) {
	for _, bad := range []string{"http://mail.example.com", "smtps://", "mail.example.com:587"} {
		ce := loadErr(t, prodEnv().with("SMTP_URL", bad))
		if !hasProblem(ce, "SMTP_URL must look like") {
			t.Errorf("%q: problems %v", bad, ce.Problems)
		}
	}
	if c := mustLoad(t, prodEnv().with("SMTP_URL", "smtp://user:p%40ss@mail.example.com:587")); c.RegisterEnabled {
		t.Error("SMTP_URL alone must not open sign up")
	}
}
