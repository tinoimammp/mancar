// Package daemon implements the mancard command: it wires configuration,
// storage and the gateway server together and provides the operator
// commands (database migration, agent-token administration, health check).
//
// Everything lives here, not in cmd/, so it can be tested; cmd/mancard is
// a few lines that call Main.
//
// Exit codes: 0 success, 1 runtime failure, 2 usage or configuration error.
package daemon

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/tinoimammp/mancar/internal/auth"
	"github.com/tinoimammp/mancar/internal/config"
	"github.com/tinoimammp/mancar/internal/domain"
	"github.com/tinoimammp/mancar/internal/server"
	"github.com/tinoimammp/mancar/internal/store/postgres"
	"github.com/tinoimammp/mancar/internal/version"
	"github.com/tinoimammp/mancar/migrations"
)

// Env is everything the commands need from the outside world.
type Env struct {
	Getenv         func(string) string
	Stdout, Stderr io.Writer
	// Listener is an optional pre-bound listener for "serve" (tests). When
	// nil the server listens on LISTEN_ADDR.
	Listener net.Listener
	// DBWait bounds how long commands wait for the database to accept
	// connections (default: 60s for serve, 30s for the admin commands).
	DBWait time.Duration
}

func (e Env) dbWait(def time.Duration) time.Duration {
	if e.DBWait > 0 {
		return e.DBWait
	}
	return def
}

// OSEnv returns an Env backed by the real process environment.
func OSEnv() Env { return Env{Getenv: os.Getenv, Stdout: os.Stdout, Stderr: os.Stderr} }

const usage = `mancard - self-hosted tunnel gateway

Usage:
  mancard [serve]                         run the gateway (default)
  mancard migrate                         apply database migrations and exit
  mancard token create --user NAME [--name LABEL]
                                            create an agent token (shown once)
  mancard token list                      list agent tokens
  mancard token revoke ID                 revoke an agent token
  mancard token generate                  print a random token (for DEV_AGENT_TOKEN)
  mancard healthcheck                     exit 0 if the local gateway is healthy
  mancard version

Configuration is read from environment variables; see .env.example.
`

// Main runs one command and returns the process exit code.
func Main(ctx context.Context, args []string, e Env) int {
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "serve":
		return withConfig(e, true, func(cfg *config.Config, log *slog.Logger) int { return cmdServe(ctx, e, cfg, log) })
	case "migrate":
		return withConfig(e, false, func(cfg *config.Config, log *slog.Logger) int { return cmdMigrate(ctx, e, cfg, log) })
	case "token":
		return cmdToken(ctx, e, args)
	case "healthcheck":
		return withConfig(e, false, func(cfg *config.Config, _ *slog.Logger) int { return cmdHealthcheck(ctx, e, cfg) })
	case "version", "--version", "-v":
		fmt.Fprintf(e.Stdout, "mancard %s\n", version.Version)
		return 0
	case "help", "--help", "-h":
		fmt.Fprint(e.Stdout, usage)
		return 0
	default:
		fmt.Fprintf(e.Stderr, "mancard: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
}

// withConfig loads and validates the configuration. Problems are printed
// together (never the secret values) and yield exit code 2.
func withConfig(e Env, logToStdout bool, run func(*config.Config, *slog.Logger) int) int {
	cfg, err := config.Load(e.Getenv)
	if err != nil {
		fmt.Fprintf(e.Stderr, "mancard: %v\n", err)
		return 2
	}
	w := e.Stderr
	if logToStdout {
		w = e.Stdout // container convention: service logs on stdout
	}
	return run(cfg, newLogger(w, cfg))
}

func newLogger(w io.Writer, cfg *config.Config) *slog.Logger {
	var lvl slog.Level
	switch cfg.LogLevel {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if cfg.IsProduction() {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

// ---- serve -----------------------------------------------------------------

func cmdServe(ctx context.Context, e Env, cfg *config.Config, log *slog.Logger) int {
	deps := server.Deps{Config: cfg, Logger: log}
	switch cfg.Storage {
	case "postgres":
		st, err := postgres.Open(ctx, cfg.DatabaseURL, e.dbWait(60*time.Second))
		if err != nil {
			log.Error("cannot connect to the database", "err", redactDSN(err, cfg.DatabaseURL))
			return 1
		}
		defer st.Close()
		if err := st.Migrate(ctx, migrations.FS); err != nil {
			log.Error("database migration failed", "err", err)
			return 1
		}
		deps.Auth, deps.Registry, deps.HealthCheck = st, st, st.Ping
	case "memory":
		mem := auth.NewMemory()
		token := cfg.DevAgentToken
		if token == "" {
			var err error
			if token, err = mem.Issue("dev"); err != nil {
				log.Error("cannot create a development token", "err", err)
				return 1
			}
			fmt.Fprintf(e.Stderr, "development agent token (not persisted): %s\n", token)
		} else {
			mem.Add(token, "dev")
		}
		log.Warn("running with in-memory storage: all state is lost on restart (development only)")
		deps.Auth, deps.Registry = mem, domain.NewMemoryRegistry()
	}

	srv := server.New(deps)
	var err error
	if e.Listener != nil {
		err = srv.Serve(ctx, e.Listener)
	} else {
		err = srv.Run(ctx)
	}
	if err != nil {
		log.Error("server stopped with an error", "err", err)
		return 1
	}
	log.Info("server stopped")
	return 0
}

// redactDSN removes the database URL (which contains the password) from
// error text, should a driver ever echo it.
func redactDSN(err error, dsn string) string {
	msg := err.Error()
	if dsn != "" {
		msg = strings.ReplaceAll(msg, dsn, "[redacted]")
	}
	return msg
}

// ---- migrate ---------------------------------------------------------------

func openStore(ctx context.Context, e Env, cfg *config.Config) (*postgres.Store, error) {
	if cfg.Storage != "postgres" {
		return nil, errors.New("this command needs STORAGE=postgres")
	}
	st, err := postgres.Open(ctx, cfg.DatabaseURL, e.dbWait(30*time.Second))
	if err != nil {
		return nil, errors.New(redactDSN(err, cfg.DatabaseURL))
	}
	return st, nil
}

func cmdMigrate(ctx context.Context, e Env, cfg *config.Config, log *slog.Logger) int {
	st, err := openStore(ctx, e, cfg)
	if err != nil {
		fmt.Fprintf(e.Stderr, "mancard: %v\n", err)
		return 1
	}
	defer st.Close()
	if err := st.Migrate(ctx, migrations.FS); err != nil {
		fmt.Fprintf(e.Stderr, "mancard: migration failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(e.Stdout, "database schema is up to date")
	return 0
}

// ---- token administration ---------------------------------------------------

var usernameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func cmdToken(ctx context.Context, e Env, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(e.Stderr, "mancard token: expected create, list, revoke or generate\n\n"+usage)
		return 2
	}
	sub, args := args[0], args[1:]

	if sub == "generate" { // needs neither configuration nor a database
		tok, _, err := auth.NewToken()
		if err != nil {
			fmt.Fprintf(e.Stderr, "mancard: %v\n", err)
			return 1
		}
		fmt.Fprintln(e.Stdout, tok)
		return 0
	}

	switch sub {
	case "create", "list", "revoke":
	default:
		fmt.Fprintf(e.Stderr, "mancard token: unknown subcommand %q\n\n%s", sub, usage)
		return 2
	}

	fs := flag.NewFlagSet("token "+sub, flag.ContinueOnError)
	fs.SetOutput(e.Stderr)
	user := fs.String("user", "", "username that owns the token")
	name := fs.String("name", "", "label for the token, for example the machine name")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	return withConfig(e, false, func(cfg *config.Config, _ *slog.Logger) int {
		switch sub {
		case "create":
			u := strings.ToLower(strings.TrimSpace(*user))
			if !usernameRE.MatchString(u) {
				fmt.Fprintln(e.Stderr, "mancard: --user is required: 1-64 characters from a-z, 0-9, '.', '_' and '-'")
				return 2
			}
			label := strings.TrimSpace(*name)
			if label == "" {
				label = "cli"
			}
			st, err := openStore(ctx, e, cfg)
			if err != nil {
				fmt.Fprintf(e.Stderr, "mancard: %v\n", err)
				return 1
			}
			defer st.Close()
			uid, err := st.EnsureUser(ctx, u)
			if err != nil {
				fmt.Fprintf(e.Stderr, "mancard: %v\n", err)
				return 1
			}
			tok, id, err := st.CreateAgentToken(ctx, uid, label)
			if err != nil {
				fmt.Fprintf(e.Stderr, "mancard: %v\n", err)
				return 1
			}
			// The secret goes alone on stdout so it can be captured with
			// $(...); the explanation goes to stderr.
			fmt.Fprintln(e.Stdout, tok)
			fmt.Fprintf(e.Stderr, "Created token %s for user %q. It is shown only once; store it safely.\n", id, u)
			return 0
		case "list":
			st, err := openStore(ctx, e, cfg)
			if err != nil {
				fmt.Fprintf(e.Stderr, "mancard: %v\n", err)
				return 1
			}
			defer st.Close()
			list, err := st.ListAgentTokens(ctx)
			if err != nil {
				fmt.Fprintf(e.Stderr, "mancard: %v\n", err)
				return 1
			}
			tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tUSER\tNAME\tCREATED\tLAST USED\tSTATUS")
			for _, t := range list {
				status, last := "active", "never"
				if t.RevokedAt != nil {
					status = "revoked"
				}
				if t.LastUsedAt != nil {
					last = t.LastUsedAt.UTC().Format("2006-01-02 15:04")
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", t.ID, t.Username, t.Name, t.CreatedAt.UTC().Format("2006-01-02 15:04"), last, status)
			}
			tw.Flush()
			return 0
		default: // revoke
			if fs.NArg() != 1 {
				fmt.Fprintln(e.Stderr, "mancard token revoke: expected exactly one token ID")
				return 2
			}
			st, err := openStore(ctx, e, cfg)
			if err != nil {
				fmt.Fprintf(e.Stderr, "mancard: %v\n", err)
				return 1
			}
			defer st.Close()
			switch err := st.RevokeAgentToken(ctx, fs.Arg(0)); {
			case errors.Is(err, postgres.ErrNotFound):
				fmt.Fprintln(e.Stderr, "mancard: no active token with that ID")
				return 1
			case err != nil:
				fmt.Fprintf(e.Stderr, "mancard: %v\n", err)
				return 1
			}
			fmt.Fprintln(e.Stdout, "token revoked; connected agents using it are disconnected on their next reconnect")
			return 0
		}
	})
}

// ---- healthcheck ------------------------------------------------------------

// cmdHealthcheck probes the local gateway. It exists so the container image
// needs no curl or wget (it is distroless).
func cmdHealthcheck(ctx context.Context, e Env, cfg *config.Config) int {
	host, port, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		fmt.Fprintf(e.Stderr, "unhealthy: %v\n", err)
		return 1
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(host, port)+"/healthz", nil)
	if err != nil {
		fmt.Fprintf(e.Stderr, "unhealthy: %v\n", err)
		return 1
	}
	req.Host = cfg.BaseDomain // the router only serves /healthz on the base domain
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(e.Stderr, "unhealthy: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(e.Stderr, "unhealthy: /healthz answered %s\n", resp.Status)
		return 1
	}
	fmt.Fprintln(e.Stdout, "healthy")
	return 0
}
