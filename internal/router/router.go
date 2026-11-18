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
	"sync/atomic"
	"time"

	"github.com/tinoimammp/mancar/internal/access"
	"github.com/tinoimammp/mancar/internal/gateway"
	"github.com/tinoimammp/mancar/internal/inspect"
	"github.com/tinoimammp/mancar/internal/netutil"
	"github.com/tinoimammp/mancar/internal/protocol"
)

// Tunnels is the part of the gateway the router needs.
type Tunnels interface {
	LookupHost(hostname string) *gateway.Tunnel
	LookupID(id string) *gateway.Tunnel
}

// Inspector receives a copy of every proxied HTTP exchange.
type Inspector interface {
	MaxBody() int
	Submit(*inspect.Record)
}

// Usage counts traffic per hostname (dashboard statistics).
type Usage interface {
	Add(userID, hostname string, status int, bytesIn, bytesOut int64)
}

type replayKey struct{}

// WithReplay marks a request as a dashboard replay of a capture recorded
// on a tunnel of account ownerID (shown as a replay in the
// inspector). It is a context value, so public clients cannot set it.
func WithReplay(ctx context.Context, ownerID string) context.Context {
	return context.WithValue(ctx, replayKey{}, ownerID)
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
	// Inspector, when set, records HTTP exchanges (request inspector).
	Inspector Inspector
	// Usage, when set, counts requests and bytes per hostname.
	Usage Usage
	// Access lets owners into private tunnels; without it private tunnels
	// answer 403 to everyone.
	Access *access.Keeper
	// SignInURL is the dashboard sign in page with target
	// ("host/path?query") as its ref: after signing in, the owner is sent
	// back there.
	SignInURL func(target string) string
	// Restricted, when set, renders the page a browser without access
	// sees (with a button to signIn); otherwise it is redirected there.
	Restricted func(w http.ResponseWriter, host, signIn string)
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

// spoofableIPHeaders name the client address in other proxies' dialects;
// a visitor could set them to anything.
var spoofableIPHeaders = []string{"X-Real-IP", "True-Client-IP", "CF-Connecting-IP", "X-Client-IP", "X-Cluster-Client-IP", "Fastly-Client-IP"}

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
			// Other client-IP headers apps commonly trust would otherwise
			// pass through as the visitor sent them: drop them, and give
			// X-Real-IP the address we derived.
			for _, h := range spoofableIPHeaders {
				pr.Out.Header.Del(h)
			}
			pr.Out.Header.Set("X-Real-IP", info.client.IP)
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
	// A dashboard replay (a context value: it cannot come from outside) goes
	// only to a tunnel of the account that recorded the capture: the name
	// may belong to someone else by now. Such a replay skips the private
	// access check, since the owner replays into their own tunnel.
	replayOwner, replay := r.Context().Value(replayKey{}).(string)
	if replay && (replayOwner == "" || replayOwner != t.UserID) {
		writeError(w, http.StatusConflict, "tunnel_changed", "This hostname now belongs to another tunnel; the request was not replayed.")
		return
	}
	if t.Private && !replay && !rt.letIn(w, r, host, t) {
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
	reqBytes := &countingBody{ReadCloser: r.Body}
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = reqBytes
	}
	var rec *inspect.Record
	var reqBuf *inspect.Buffer
	if ins := rt.opts.Inspector; ins != nil {
		rec = &inspect.Record{
			ID: inspect.NewID(), UserID: t.UserID, Hostname: host, TunnelID: t.ID, Time: start,
			Method: r.Method, URI: r.URL.RequestURI(), Proto: r.Proto, Client: info.client.IP,
			ReqHeader: r.Header.Clone(), Replay: replay,
		}
		reqBuf = inspect.NewBuffer(ins.MaxBody())
		r.Body = inspect.TeeBody(r.Body, reqBuf)
		sw.capture = inspect.NewBuffer(ins.MaxBody())
	}
	rt.proxy.ServeHTTP(sw, r.WithContext(context.WithValue(r.Context(), ctxKey{}, info)))
	if rec != nil {
		rec.DurationMs = time.Since(start).Milliseconds()
		rec.Status = sw.status
		rec.ReqBody, rec.ReqSize = reqBuf.Snapshot()
		rec.RespBody, rec.RespSize = sw.capture.Snapshot()
		rec.RespHeader = sw.header
		rt.opts.Inspector.Submit(rec)
	}
	dur := time.Since(start)
	in := reqBytes.n.Load()
	t.Notify(&protocol.Event{Time: start, Method: r.Method, Path: r.URL.Path, Status: sw.status,
		DurationMs: dur.Milliseconds(), BytesIn: in, BytesOut: sw.bytes, Remote: info.client.IP})
	if rt.opts.Usage != nil {
		rt.opts.Usage.Add(t.UserID, host, sw.status, in, sw.bytes)
	}
	// The query string is deliberately not logged: it often carries secrets.
	rt.log.Info("request", "host", host, "method", r.Method, "path", r.URL.Path, "status", sw.status,
		"duration_ms", dur.Milliseconds(), "client", info.client.IP, "tunnel", t.ID)
}

// letIn guards a private tunnel: it reports whether the request may go to
// the app, and otherwise answers it (sign-in redirect, ticket redemption
// or refusal). The access cookie never reaches the app.
func (rt *Router) letIn(w http.ResponseWriter, r *http.Request, host string, t *gateway.Tunnel) bool {
	k := rt.opts.Access
	if k == nil {
		writeError(w, http.StatusForbidden, "private_tunnel", "This tunnel is private.")
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == access.Path {
		user, ok := k.Redeem(r.URL.Query().Get("ticket"), host)
		if !ok || !t.MayOpen(user) {
			writeError(w, http.StatusForbidden, "access_denied", "This sign-in link has expired or was already used. Open the address again.")
			return false
		}
		k.SetCookie(w, host, user)
		http.Redirect(w, r, access.SafeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
		return false
	}
	if k.Allowed(r, host, t.MayOpen) {
		w.Header().Del("Cache-Control") // the app decides from here
		k.StripCookie(r.Header)
		return true
	}
	browser := (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		strings.Contains(r.Header.Get("Accept"), "text/html") && r.Header.Get("Upgrade") == ""
	if browser && rt.opts.SignInURL != nil {
		signIn := rt.opts.SignInURL(host + r.URL.RequestURI())
		if rt.opts.Restricted != nil {
			rt.opts.Restricted(w, host, signIn)
		} else {
			http.Redirect(w, r, signIn, http.StatusFound)
		}
		return false
	}
	writeError(w, http.StatusUnauthorized, "private_tunnel", "This tunnel is private. Open it in a browser and sign in as its owner.")
	return false
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

// statusWriter records the response status for access logs (and, for the
// inspector, the response headers and the start of the body) while keeping
// Flush and Hijack (needed for streaming and WebSocket upgrades) working.
type statusWriter struct {
	http.ResponseWriter
	status  int
	bytes   int64           // response body bytes written
	capture *inspect.Buffer // nil unless the inspector is on
	header  http.Header
}

// countingBody counts request body bytes read by the proxy. The counter is
// atomic because the transport may still be reading when ServeHTTP returns.
type countingBody struct {
	io.ReadCloser
	n atomic.Int64
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func (s *statusWriter) begin(code int) {
	if s.status == 0 {
		s.status = code
		if s.capture != nil {
			s.header = s.ResponseWriter.Header().Clone()
		}
	}
}

func (s *statusWriter) WriteHeader(code int) {
	s.begin(code)
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	s.begin(http.StatusOK)
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	if s.capture != nil && n > 0 {
		s.capture.Write(b[:n])
	}
	return n, err
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusWriter) Flush() { _ = http.NewResponseController(s.ResponseWriter).Flush() }

func (s *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	s.begin(http.StatusSwitchingProtocols)
	return http.NewResponseController(s.ResponseWriter).Hijack()
}
