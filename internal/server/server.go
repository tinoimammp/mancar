// Package server wires the gateway, routing engine and management endpoints
// into one HTTP server and owns its lifecycle (start-up reset, graceful
// shutdown).
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/tinoimammp/mancar/internal/auth"
	"github.com/tinoimammp/mancar/internal/config"
	"github.com/tinoimammp/mancar/internal/dashboard"
	"github.com/tinoimammp/mancar/internal/domain"
	"github.com/tinoimammp/mancar/internal/gateway"
	"github.com/tinoimammp/mancar/internal/inspect"
	"github.com/tinoimammp/mancar/internal/netutil"
	"github.com/tinoimammp/mancar/internal/protocol"
	"github.com/tinoimammp/mancar/internal/router"
	"github.com/tinoimammp/mancar/internal/usage"
	"github.com/tinoimammp/mancar/internal/version"
)

// Deps are the infrastructure dependencies injected into the server.
type Deps struct {
	Config   *config.Config
	Auth     auth.Authenticator
	Registry domain.Registry
	// HealthCheck verifies backing services (database); may be nil.
	HealthCheck func(ctx context.Context) error
	// Admin backs the web dashboard; nil disables it (in-memory mode).
	Admin dashboard.Store
	// Captures stores the request inspector's records; nil disables it.
	Captures inspect.Store
	// Usage stores traffic statistics; nil disables them.
	Usage  usage.Store
	Logger *slog.Logger
	// TCPBindHost overrides the TCP tunnel bind address (tests use 127.0.0.1).
	TCPBindHost string
	// KeepAlive overrides the session heartbeat interval (tests).
	KeepAlive time.Duration
}

// Server is the assembled gateway process.
type Server struct {
	cfg      *config.Config
	log      *slog.Logger
	domains  *domain.Service
	hub      *gateway.Hub
	recorder *inspect.Recorder // nil when the inspector is off
	counter  *usage.Counter    // nil when statistics are off
	handler  http.Handler
}

// New assembles a Server.
func New(d Deps) *Server {
	if d.Logger == nil {
		d.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	cfg := d.Config
	domains := domain.NewService(d.Registry, domain.ServiceOptions{
		BaseDomain: cfg.BaseDomain, HoldCustom: cfg.HoldCustom, HoldRandom: cfg.HoldRandom,
	})
	hub := gateway.NewHub(d.Auth, domains, gateway.Options{
		PublicURL: cfg.PublicURL, TCPHost: cfg.BaseDomain, TCPBindHost: d.TCPBindHost,
		TCPPortMin: cfg.TCPPortMin, TCPPortMax: cfg.TCPPortMax,
		MaxTunnelsPerSession: cfg.MaxTunnelsPerAgent, MaxSessionsPerUser: cfg.MaxAgentsPerUser,
		MaxConnsPerTunnel: cfg.MaxConnsPerTunnel, KeepAliveInterval: d.KeepAlive, Logger: d.Logger,
		TrustedProxies: cfg.TrustedProxies, AuthFailureLimit: authFailureLimit(cfg), AuthFailureWindow: time.Minute,
	})

	mgmt := http.NewServeMux()
	mgmt.Handle(protocol.ConnectPath, hub)
	mgmt.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok\n"))
	})
	mgmt.HandleFunc("GET /api/v1/system/health", func(w http.ResponseWriter, r *http.Request) {
		type health struct {
			Status   string        `json:"status"`
			Version  string        `json:"version"`
			Database string        `json:"database"`
			Gateway  gateway.Stats `json:"gateway"`
		}
		h := health{Status: "ok", Version: version.Version, Database: "ok", Gateway: hub.Stats()}
		code := http.StatusOK
		if d.HealthCheck != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			defer cancel()
			if err := d.HealthCheck(ctx); err != nil {
				h.Status, h.Database, code = "degraded", "unreachable", http.StatusServiceUnavailable
			}
		} else {
			h.Database = "not_configured"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		// Version and counters help an attacker fingerprint the gateway, so
		// only internal clients (the trusted-proxy ranges, seen through the
		// real client address) get them; everybody else gets the verdict.
		client := netutil.ClientFromRequest(r, cfg.TrustedProxies)
		if netutil.InPrefixes(cfg.TrustedProxies, client.IP) {
			json.NewEncoder(w).Encode(h)
			return
		}
		json.NewEncoder(w).Encode(struct {
			Status string `json:"status"`
		}{h.Status})
	})
	// The inspector needs somewhere to store captures and a key to encrypt
	// them with; without either it stays off.
	var recorder *inspect.Recorder
	if cfg.Inspect && d.Captures != nil && len(cfg.EncryptionKey) == 32 {
		sealer, err := inspect.NewSealer(cfg.EncryptionKey)
		if err == nil {
			recorder = inspect.NewRecorder(inspect.Options{
				Store: d.Captures, Sealer: sealer, MaxBody: cfg.InspectMaxBody,
				Retention: cfg.InspectRetention, MaxRows: cfg.InspectMaxRows, Logger: d.Logger,
			})
		}
	}
	ropts := router.Options{
		BaseDomain: cfg.BaseDomain, Tunnels: hub, Management: mgmt, TrustedProxies: cfg.TrustedProxies,
		MaxBodyBytes: cfg.MaxRequestBodyBytes, ResponseHeaderTimeout: cfg.ResponseHeaderTimeout, Logger: d.Logger,
	}
	if recorder != nil {
		ropts.Inspector = recorder
	}
	var counter *usage.Counter
	if d.Usage != nil {
		counter = usage.NewCounter(d.Usage, d.Logger)
		ropts.Usage = counter
	}
	rt := router.New(ropts)

	dash := dashboard.New(dashboard.Options{
		Store: d.Admin, Hub: hub, SessionSecret: cfg.JWTSecret, Secure: cfg.PublicScheme == "https",
		BaseDomain: cfg.BaseDomain, PublicScheme: cfg.PublicScheme, PublicPort: cfg.PublicPort,
		TCPPortMin: cfg.TCPPortMin, TCPPortMax: cfg.TCPPortMax, TrustedProxies: cfg.TrustedProxies,
		HealthCheck: d.HealthCheck, Logger: d.Logger, Inspector: recorder, Replay: rt,
	})
	mgmt.Handle("/dashboard", dash)
	mgmt.Handle("/dashboard/", dash)
	mgmt.Handle("/api/v1/admin/", dash)
	mgmt.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("mancar gateway\n"))
	})

	return &Server{cfg: cfg, log: d.Logger, domains: domains, hub: hub, recorder: recorder, counter: counter, handler: rt}
}

// Handler returns the public HTTP handler.
func (s *Server) Handler() http.Handler { return s.handler }

// Hub exposes the gateway (tests, future management API).
func (s *Server) Hub() *gateway.Hub { return s.hub }

// Run listens on the configured address and serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Serve serves on ln until ctx is cancelled, then shuts down gracefully:
// stop accepting, let in-flight requests finish, close agent sessions and
// release their hostnames.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	// No tunnel can be connected to a process that just started, so any
	// "active" marker left in the registry is stale (crash, power loss).
	if err := s.domains.Reset(ctx); err != nil {
		ln.Close()
		return err
	}
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := s.domains.Purge(ctx); err != nil && ctx.Err() == nil {
					s.log.Warn("purging expired hostnames failed", "err", err)
				}
			}
		}
	}()

	recCtx, stopRecorder := context.WithCancel(context.WithoutCancel(ctx))
	defer stopRecorder()
	counterDone := make(chan struct{})
	if s.counter != nil {
		go func() { s.counter.Run(recCtx); close(counterDone) }()
	} else {
		close(counterDone)
	}
	if s.recorder != nil {
		go s.recorder.Run(recCtx)
		s.log.Info("request inspector enabled", "retention", s.recorder.Retention().String())
	}

	srv := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	s.log.Info("gateway listening", "addr", ln.Addr().String(), "base_domain", s.cfg.BaseDomain, "version", version.Version)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	s.log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		srv.Close()
	}
	s.hub.Shutdown(sctx)
	stopRecorder() // flush queued captures and pending traffic counts
	if s.recorder != nil {
		select {
		case <-s.recorder.Done():
		case <-sctx.Done():
		}
	}
	select {
	case <-counterDone:
	case <-sctx.Done():
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// authFailureLimit maps the configuration (0 = off) to the gateway option
// (0 = default, negative = off).
func authFailureLimit(cfg *config.Config) int {
	if cfg.AuthFailureLimit == 0 {
		return -1
	}
	return cfg.AuthFailureLimit
}
