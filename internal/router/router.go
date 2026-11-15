// Package router implements the Routing Engine.
//
// Responsibility: take a public HTTP request, resolve its Host header to a
// registered tunnel, forward it to the owning agent and stream the response
// back. WebSocket and other HTTP/1.1 upgrades are forwarded transparently.
// Requests for the base domain itself go to the management handler.
//
// Routing uses only the Host header matched against tunnels registered in
// the gateway; a host that is not registered is never forwarded anywhere,
// which is what prevents open-proxy behaviour.
package router

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strings"
	"time"

	"github.com/tinoimammp/mancar/internal/gateway"
	"github.com/tinoimammp/mancar/internal/netutil"
)

// Tunnels is the part of the gateway the router needs.
type Tunnels interface {
	LookupHost(hostname string) *gateway.Tunnel
	LookupID(id string) *gateway.Tunnel
}

// Options configures a Router.
type Options struct {
	BaseDomain            string
	Tunnels               Tunnels
	Management            http.Handler
	TrustedProxies        []netip.Prefix
	MaxBodyBytes          int64 // 0 = unlimited
	ResponseHeaderTimeout time.Duration
	Logger                *slog.Logger
}

// Router is the public HTTP entry point.
type Router struct {
	opts  Options
	proxy *httputil.ReverseProxy
	log   *slog.Logger
}

const upstreamSuffix = ".tunnel.invalid"

type ctxKey struct{}

type reqInfo struct {
	tunnel *gateway.Tunnel
	client netutil.ClientInfo
}

// HeaderError tells clients which platform error produced a response.
const HeaderError = "X-Mancar-Error"

// New builds a Router.
func New(opts Options) *Router {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.ResponseHeaderTimeout <= 0 {
		opts.ResponseHeaderTimeout = 2 * time.Minute
	}
	opts.BaseDomain = strings.ToLower(opts.BaseDomain)
	rt := &Router{opts: opts, log: opts.Logger}

	transport := &http.Transport{
		Proxy: nil,
		// The "address" is "<tunnel-id>.tunnel.invalid:80": a pool key, never
		// resolved. Each tunnel gets its own idle pool, so a connection
		// can never be reused across tunnels.
		DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(addr)
			t := opts.Tunnels.LookupID(strings.TrimSuffix(host, upstreamSuffix))
			if t == nil {
				return nil, gateway.ErrTunnelClosed
			}
			return t.OpenStream("")
		},
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: opts.ResponseHeaderTimeout,
		DisableCompression:    true,
	}
	rt.proxy = &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1, // stream responses (SSE, long polling)
		Rewrite: func(pr *httputil.ProxyRequest) {
			info := pr.In.Context().Value(ctxKey{}).(*reqInfo)
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = info.tunnel.ID + upstreamSuffix
			pr.Out.Host = pr.In.Host // local service sees the public host
			// Inbound X-Forwarded-* were already stripped by ReverseProxy;
			// set values we derived ourselves.
			pr.Out.Header.Set("X-Forwarded-For", info.client.IP)
			pr.Out.Header.Set("X-Forwarded-Proto", info.client.Proto)
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
		},
		ErrorHandler: rt.proxyError,
		ErrorLog:     slog.NewLogLogger(opts.Logger.Handler(), slog.LevelDebug),
	}
	return rt
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := netutil.NormalizeHost(r.Host)
	if host == rt.opts.BaseDomain {
		rt.opts.Management.ServeHTTP(w, r)
		return
	}
	if !strings.HasSuffix(host, "."+rt.opts.BaseDomain) {
		writeError(w, http.StatusNotFound, "unknown_host", "This host is not served by this gateway.")
		return
	}
	t := rt.opts.Tunnels.LookupHost(host)
	if t == nil {
		writeError(w, http.StatusNotFound, "tunnel_not_found",
			fmt.Sprintf("Tunnel %s not found. The agent may be offline.", host))
		return
	}
	info := &reqInfo{tunnel: t, client: netutil.ClientFromRequest(r, rt.opts.TrustedProxies)}
	if rt.opts.MaxBodyBytes > 0 {
		if r.ContentLength > rt.opts.MaxBodyBytes {
			writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "Request body exceeds the configured limit.")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, rt.opts.MaxBodyBytes)
	}
	start := time.Now()
	sw := &statusWriter{ResponseWriter: w}
	rt.proxy.ServeHTTP(sw, r.WithContext(context.WithValue(r.Context(), ctxKey{}, info)))
	// The query string is deliberately not logged: it often carries secrets.
	rt.log.Info("request", "host", host, "method", r.Method, "path", r.URL.Path, "status", sw.status,
		"duration_ms", time.Since(start).Milliseconds(), "client", info.client.IP, "tunnel", t.ID)
}

func (rt *Router) proxyError(w http.ResponseWriter, r *http.Request, err error) {
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig):
		writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "Request body exceeds the configured limit.")
	case errors.Is(err, gateway.ErrTooManyConnections):
		writeError(w, http.StatusServiceUnavailable, "tunnel_busy", "Tunnel connection limit reached.")
	case errors.Is(err, context.Canceled):
		w.WriteHeader(499) // client went away
	default:
		rt.log.Debug("proxy error", "host", r.Host, "err", err)
		writeError(w, http.StatusBadGateway, "tunnel_unreachable", "The tunnel agent did not respond.")
	}
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set(HeaderError, code)
	w.WriteHeader(status)
	fmt.Fprintf(w, "%s (%s)\n", msg, code)
}

// statusWriter records the response status for access logs while keeping
// Flush and Hijack (needed for streaming and WebSocket upgrades) working.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusWriter) Flush() { _ = http.NewResponseController(s.ResponseWriter).Flush() }

func (s *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if s.status == 0 {
		s.status = http.StatusSwitchingProtocols
	}
	return http.NewResponseController(s.ResponseWriter).Hijack()
}
