// Package gateway implements the Tunnel Gateway.
//
// Responsibility: accept agent connections, authenticate them, keep one
// multiplexed session per agent, register/unregister tunnels on request and
// open a stream towards the agent for every public connection.
//
// Interfaces:
//   - Hub.ServeHTTP: the agent connect endpoint (protocol.ConnectPath).
//   - Hub.LookupHost / LookupID: used by the routing engine.
//   - Tunnel.OpenStream: one byte stream to the agent's local service.
//
// Liveness: yamux keep-alive pings act as the heartbeat. A session whose
// peer stops answering is closed and all of its tunnels are removed.
package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/tinoimammp/mancar/internal/auth"
	"github.com/tinoimammp/mancar/internal/domain"
	"github.com/tinoimammp/mancar/internal/netutil"
	"github.com/tinoimammp/mancar/internal/protocol"
	"github.com/tinoimammp/mancar/internal/ratelimit"
)

// ErrTooManyConnections is returned when a tunnel is at its connection limit.
var ErrTooManyConnections = errors.New("gateway: tunnel connection limit reached")

// ErrTunnelClosed is returned when the tunnel's session is gone.
var ErrTunnelClosed = errors.New("gateway: tunnel is closed")

// Options configures a Hub.
type Options struct {
	// PublicURL renders the public URL of an HTTP tunnel hostname.
	PublicURL func(hostname string) string
	// TCPHost is the host shown in tcp:// URLs (normally the base domain).
	TCPHost string
	// TCPBindHost is the address TCP tunnel listeners bind to ("" = all).
	TCPBindHost string
	// TCPPortMin/TCPPortMax is the inclusive port range for TCP tunnels.
	// Zero disables TCP tunnels.
	TCPPortMin, TCPPortMax int

	MaxTunnelsPerSession int
	MaxSessionsPerUser   int
	MaxConnsPerTunnel    int
	KeepAliveInterval    time.Duration
	Logger               *slog.Logger

	// TrustedProxies are the reverse proxies (the bundled TLS edge) whose
	// X-Forwarded-For header may be believed when working out the client
	// address that failed-authentication limits are keyed on.
	TrustedProxies []netip.Prefix
	// AuthFailureLimit is how many failed agent authentications one client
	// address may make per AuthFailureWindow before it is refused without
	// any database lookup. 0 selects the default (10); negative disables it.
	AuthFailureLimit  int
	AuthFailureWindow time.Duration
	// PrivateTunnels allows tunnels only their owner can open. It needs the
	// dashboard (accounts) to sign visitors in.
	PrivateTunnels bool
	// ResolveLogins turns the usernames or email addresses of --allow into
	// accounts (ID -> username). An unknown one is an error wrapping
	// ErrUnknownUser. Nil: --allow is not supported.
	ResolveLogins func(ctx context.Context, logins []string) (map[string]string, error)
}

// ErrUnknownUser is returned by Options.ResolveLogins for a name or email
// address with no account.
var ErrUnknownUser = errors.New("no account")

// MaxAllow bounds the accounts one private tunnel can be shared with.
const MaxAllow = 20

func (o *Options) defaults() {
	if o.MaxTunnelsPerSession <= 0 {
		o.MaxTunnelsPerSession = 10
	}
	if o.MaxSessionsPerUser <= 0 {
		o.MaxSessionsPerUser = 10
	}
	if o.MaxConnsPerTunnel <= 0 {
		o.MaxConnsPerTunnel = 256
	}
	if o.KeepAliveInterval <= 0 {
		o.KeepAliveInterval = 15 * time.Second
	}
	if o.AuthFailureLimit == 0 {
		o.AuthFailureLimit = 10
	}
	if o.AuthFailureWindow <= 0 {
		o.AuthFailureWindow = time.Minute
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if o.PublicURL == nil {
		o.PublicURL = func(h string) string { return "https://" + h }
	}
}

// Tunnel is one live public endpoint bound to an agent session.
type Tunnel struct {
	ID        string
	Proto     string
	Hostname  string // HTTP tunnels
	Port      int    // TCP tunnels
	PublicURL string
	UserID    string
	CreatedAt time.Time
	// Private: only the owner, and the accounts in Allow (user ID ->
	// username), may open it (checked by the router).
	Private bool
	Allow   map[string]string

	sess  *session
	lease domain.Lease
	ln    net.Listener
	sem   chan struct{}
}

// MayOpen reports whether the account may open this private tunnel.
func (t *Tunnel) MayOpen(userID string) bool {
	_, allowed := t.Allow[userID]
	return userID != "" && (userID == t.UserID || allowed)
}

// OpenStream opens a new stream to the agent for this tunnel.
func (t *Tunnel) OpenStream(remoteAddr string) (net.Conn, error) {
	select {
	case t.sem <- struct{}{}:
	default:
		return nil, ErrTooManyConnections
	}
	release := func() { <-t.sem }
	st, err := t.sess.mux.OpenStream()
	if err != nil {
		release()
		return nil, fmt.Errorf("%w: %v", ErrTunnelClosed, err)
	}
	_ = st.SetWriteDeadline(time.Now().Add(10 * time.Second))
	err = protocol.WriteJSONLine(st, protocol.StreamHeader{TunnelID: t.ID, RemoteAddr: remoteAddr})
	_ = st.SetWriteDeadline(time.Time{})
	if err != nil {
		st.Close()
		release()
		return nil, fmt.Errorf("%w: %v", ErrTunnelClosed, err)
	}
	return &streamConn{Stream: st, release: release}, nil
}

// Notify reports a finished exchange to the owning agent's request log. It
// never blocks: events are dropped when the agent cannot keep up or does not
// support them.
func (t *Tunnel) Notify(ev *protocol.Event) {
	if t.sess == nil || t.sess.events == nil {
		return
	}
	ev.TunnelID = t.ID
	select {
	case t.sess.events <- ev:
	default:
	}
}

// streamConn releases the tunnel's connection slot exactly once on Close.
type streamConn struct {
	*yamux.Stream
	once    sync.Once
	release func()
}

// CloseWrite half-closes the stream (yamux Close only shuts the send side).
func (c *streamConn) CloseWrite() error { return c.Stream.Close() }

func (c *streamConn) Close() error {
	err := c.Stream.Close()
	c.once.Do(c.release)
	return err
}

type session struct {
	id        string
	userID    string
	tokenID   string
	instance  string
	remote    string
	client    string // real client address (behind the TLS edge)
	version   string // agent version reported at connect
	connected time.Time
	mux       *yamux.Session
	tunnels   map[string]*Tunnel // guarded by Hub.mu
	done      chan struct{}
	// events feeds the agent's request log; nil when the agent did not
	// announce protocol.FeatureEvents.
	events chan *protocol.Event
}

// Stats is a point-in-time summary.
type Stats struct {
	Sessions int `json:"sessions"`
	Tunnels  int `json:"tunnels"`
}

// Hub owns all agent sessions and live tunnels.
type Hub struct {
	auth    auth.Authenticator
	domains *domain.Service
	opts    Options
	log     *slog.Logger

	failures *ratelimit.FailureLimiter

	mu         sync.RWMutex
	closing    bool
	sessions   map[string]*session
	byInstance map[string]*session
	byHost     map[string]*Tunnel
	byID       map[string]*Tunnel
	ports      map[int]struct{}
}

// NewHub builds a Hub.
func NewHub(a auth.Authenticator, d *domain.Service, opts Options) *Hub {
	opts.defaults()
	return &Hub{
		auth: a, domains: d, opts: opts, log: opts.Logger,
		failures: ratelimit.NewFailureLimiter(opts.AuthFailureLimit, opts.AuthFailureWindow),
		sessions: map[string]*session{}, byInstance: map[string]*session{},
		byHost: map[string]*Tunnel{}, byID: map[string]*Tunnel{}, ports: map[int]struct{}{},
	}
}

// LookupHost returns the HTTP tunnel serving hostname, or nil.
func (h *Hub) LookupHost(hostname string) *Tunnel {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.byHost[hostname]
}

// LookupID returns a tunnel by ID, or nil.
func (h *Hub) LookupID(id string) *Tunnel {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.byID[id]
}

// Stats returns current counters.
func (h *Hub) Stats() Stats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return Stats{Sessions: len(h.sessions), Tunnels: len(h.byID)}
}

// TunnelInfo is a read-only view of a live tunnel.
type TunnelInfo struct {
	ID          string    `json:"id"`
	Proto       string    `json:"proto"`
	Hostname    string    `json:"hostname,omitempty"`
	Port        int       `json:"port,omitempty"`
	PublicURL   string    `json:"public_url"`
	CreatedAt   time.Time `json:"created_at"`
	ActiveConns int       `json:"active_connections"`
	Private     bool      `json:"private,omitempty"`
	SharedWith  []string  `json:"shared_with,omitempty"` // usernames besides the owner
	AllowIDs    []string  `json:"-"`                     // their account IDs
}

// SessionInfo is a read-only view of a connected agent.
type SessionInfo struct {
	ID           string       `json:"id"`
	UserID       string       `json:"user_id"`
	TokenID      string       `json:"token_id"`
	Client       string       `json:"client"`
	AgentVersion string       `json:"agent_version,omitempty"`
	ConnectedAt  time.Time    `json:"connected_at"`
	Tunnels      []TunnelInfo `json:"tunnels"`
}

// Sessions returns a snapshot of every connected agent and its tunnels,
// oldest connection first.
func (h *Hub) Sessions() []SessionInfo {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]SessionInfo, 0, len(h.sessions))
	for _, s := range h.sessions {
		si := SessionInfo{
			ID: s.id, UserID: s.userID, TokenID: s.tokenID, Client: s.client,
			AgentVersion: s.version, ConnectedAt: s.connected, Tunnels: []TunnelInfo{},
		}
		for _, t := range s.tunnels {
			ti := TunnelInfo{
				ID: t.ID, Proto: t.Proto, Hostname: t.Hostname, Port: t.Port,
				PublicURL: t.PublicURL, CreatedAt: t.CreatedAt, ActiveConns: len(t.sem), Private: t.Private,
			}
			for id, name := range t.Allow {
				if id != t.UserID {
					ti.AllowIDs, ti.SharedWith = append(ti.AllowIDs, id), append(ti.SharedWith, name)
				}
			}
			sort.Strings(ti.SharedWith)
			si.Tunnels = append(si.Tunnels, ti)
		}
		sort.Slice(si.Tunnels, func(i, j int) bool { return si.Tunnels[i].CreatedAt.Before(si.Tunnels[j].CreatedAt) })
		out = append(out, si)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ConnectedAt.Before(out[j].ConnectedAt) })
	return out
}

// Disconnect closes the agent session with the given ID. Its tunnels are
// removed and their hostnames released as for any other disconnect; the
// agent will try to reconnect unless its token has been revoked.
func (h *Hub) Disconnect(sessionID string) bool {
	h.mu.RLock()
	s := h.sessions[sessionID]
	h.mu.RUnlock()
	if s == nil {
		return false
	}
	s.mux.Close()
	return true
}

// DisconnectToken closes every session authenticated with tokenID (used
// right after the token is revoked) and returns how many were closed.
func (h *Hub) DisconnectToken(tokenID string) int {
	h.mu.RLock()
	var hit []*session
	for _, s := range h.sessions {
		if s.tokenID == tokenID {
			hit = append(hit, s)
		}
	}
	h.mu.RUnlock()
	for _, s := range hit {
		s.mux.Close()
	}
	return len(hit)
}

// Shutdown closes every session and waits for clean-up (hostname release).
func (h *Hub) Shutdown(ctx context.Context) {
	h.mu.Lock()
	h.closing = true
	all := make([]*session, 0, len(h.sessions))
	for _, s := range h.sessions {
		all = append(all, s)
	}
	h.mu.Unlock()
	for _, s := range all {
		s.mux.Close()
	}
	for _, s := range all {
		select {
		case <-s.done:
		case <-ctx.Done():
			return
		}
	}
}

var instanceRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func randomID(nbytes int) string {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		panic("gateway: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, p := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(p), token) {
				return true
			}
		}
	}
	return false
}

func bearer(r *http.Request) string {
	const p = "Bearer "
	v := r.Header.Get("Authorization")
	if len(v) > len(p) && strings.EqualFold(v[:len(p)], p) {
		return strings.TrimSpace(v[len(p):])
	}
	return ""
}

func (h *Hub) userSessionsLocked(userID string) int {
	n := 0
	for _, s := range h.sessions {
		if s.userID == userID {
			n++
		}
	}
	return n
}

// ServeHTTP is the agent connect endpoint.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || !headerHasToken(r.Header, "Connection", "upgrade") ||
		!strings.EqualFold(r.Header.Get("Upgrade"), protocol.UpgradeToken) {
		w.Header().Set("Upgrade", protocol.UpgradeToken)
		http.Error(w, "this endpoint only accepts mancar agent connections", http.StatusUpgradeRequired)
		return
	}
	// Credential guessing must not translate into database load: a client
	// address that keeps failing is refused before any lookup happens.
	client := netutil.ClientFromRequest(r, h.opts.TrustedProxies).IP
	if retry, blocked := h.failures.Blocked(client); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry/time.Second)+1))
		http.Error(w, "too many failed authentication attempts; try again later", http.StatusTooManyRequests)
		return
	}
	token := bearer(r)
	if !auth.WellFormed(token) {
		h.failures.Fail(client)
		http.Error(w, "missing or malformed agent token", http.StatusUnauthorized)
		return
	}
	principal, err := h.auth.AuthenticateAgent(r.Context(), token)
	if errors.Is(err, auth.ErrInvalidToken) {
		h.failures.Fail(client)
		h.log.Warn("agent authentication failed", "client", client)
		http.Error(w, "invalid or revoked agent token", http.StatusUnauthorized)
		return
	}
	if err != nil {
		h.log.Error("agent authentication error", "err", err)
		http.Error(w, "authentication backend unavailable", http.StatusServiceUnavailable)
		return
	}
	instance := r.Header.Get(protocol.HeaderInstance)
	if !instanceRE.MatchString(instance) {
		instance = randomID(8)
	}
	instKey := principal.UserID + "/" + instance

	// A reconnecting agent may arrive before we noticed its old connection
	// died. The instance ID is scoped to the authenticated user, so this can
	// never be used to disconnect somebody else's agent.
	h.mu.RLock()
	old := h.byInstance[instKey]
	h.mu.RUnlock()
	if old != nil {
		old.mux.Close()
		select {
		case <-old.done:
		case <-time.After(5 * time.Second):
		}
	}

	h.mu.RLock()
	closing, count := h.closing, 0
	for _, s := range h.sessions {
		if s.userID == principal.UserID {
			count++
		}
	}
	h.mu.RUnlock()
	if closing {
		http.Error(w, "gateway is shutting down", http.StatusServiceUnavailable)
		return
	}
	if count >= h.opts.MaxSessionsPerUser {
		http.Error(w, "too many connected agents for this account", http.StatusTooManyRequests)
		return
	}

	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "connection cannot be upgraded", http.StatusInternalServerError)
		return
	}
	_ = conn.SetDeadline(time.Time{})
	if _, err := conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " +
		protocol.UpgradeToken + "\r\n\r\n")); err != nil {
		conn.Close()
		return
	}

	mux, err := yamux.Server(&netutil.BufferedConn{Conn: conn, R: brw.Reader}, protocol.YamuxConfig(h.opts.KeepAliveInterval))
	if err != nil {
		conn.Close()
		return
	}
	s := &session{
		id: randomID(8), userID: principal.UserID, tokenID: principal.TokenID, instance: instance,
		remote: r.RemoteAddr, client: client, version: r.Header.Get(protocol.HeaderAgentVersion),
		connected: time.Now(), mux: mux, tunnels: map[string]*Tunnel{}, done: make(chan struct{}),
	}
	if headerHasToken(r.Header, protocol.HeaderFeatures, protocol.FeatureEvents) {
		s.events = make(chan *protocol.Event, 256)
	}
	h.mu.Lock()
	if h.closing {
		h.mu.Unlock()
		mux.Close()
		return
	}
	// The earlier check was only a courtesy (it can answer 429 before the
	// upgrade); this one is authoritative because it happens under the lock.
	if h.userSessionsLocked(principal.UserID) >= h.opts.MaxSessionsPerUser {
		h.mu.Unlock()
		mux.Close()
		return
	}
	h.sessions[s.id] = s
	h.byInstance[instKey] = s
	h.mu.Unlock()

	h.log.Info("agent connected", "session", s.id, "user", s.userID, "remote", s.remote,
		"agent_version", r.Header.Get(protocol.HeaderAgentVersion))
	h.run(s)
}

func (h *Hub) run(s *session) {
	defer h.cleanup(s)
	if s.events != nil {
		go h.sendEvents(s)
	}

	// The agent must open the control stream promptly.
	type res struct {
		st  net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() { st, err := s.mux.Accept(); ch <- res{st, err} }()
	var ctrl net.Conn
	select {
	case r := <-ch:
		if r.err != nil {
			return
		}
		ctrl = r.st
	case <-time.After(10 * time.Second):
		return
	}

	br := protocol.NewControlReader(ctrl)
	for {
		msg, err := protocol.ReadMessage(br)
		if err != nil {
			return
		}
		reply := h.handle(s, msg)
		reply.ReqID = msg.ReqID
		_ = ctrl.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := protocol.WriteJSONLine(ctrl, reply); err != nil {
			return
		}
	}
}

// sendEvents writes events to one stream opened on the first event. A write
// failure ends it; the request log is best effort and never affects traffic.
func (h *Hub) sendEvents(s *session) {
	var st net.Conn
	defer func() {
		if st != nil {
			st.Close()
		}
	}()
	for {
		var ev *protocol.Event
		select {
		case ev = <-s.events:
		case <-s.done:
			return
		}
		if st == nil {
			// Assign only on success: a nil *yamux.Stream stored in the
			// interface would make the deferred Close panic.
			opened, err := s.mux.OpenStream()
			if err != nil {
				return
			}
			st = opened
			_ = st.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if protocol.WriteJSONLine(st, protocol.StreamHeader{Kind: protocol.StreamKindEvents}) != nil {
				return
			}
		}
		_ = st.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if protocol.WriteJSONLine(st, ev) != nil {
			return
		}
	}
}

func errMsg(code, format string, args ...any) *protocol.Message {
	return &protocol.Message{Type: protocol.TypeError, Error: &protocol.Error{Code: code, Message: fmt.Sprintf(format, args...)}}
}

func (h *Hub) handle(s *session, msg *protocol.Message) *protocol.Message {
	switch msg.Type {
	case protocol.TypeRegister:
		if msg.Register == nil {
			return errMsg(protocol.CodeBadRequest, "register payload missing")
		}
		return h.register(s, msg.Register)
	case protocol.TypeUnregister:
		if msg.Unregister == nil {
			return errMsg(protocol.CodeBadRequest, "unregister payload missing")
		}
		h.mu.Lock()
		t := s.tunnels[msg.Unregister.TunnelID] // only the session's own tunnels
		if t != nil {
			h.detachLocked(t)
		}
		h.mu.Unlock()
		if t == nil {
			return errMsg(protocol.CodeNotFound, "no such tunnel")
		}
		h.closeTunnel(t)
		return &protocol.Message{Type: protocol.TypeOK}
	default:
		return errMsg(protocol.CodeBadRequest, "unknown message type %q", msg.Type)
	}
}

func (h *Hub) register(s *session, reg *protocol.Register) *protocol.Message {
	h.mu.RLock()
	n := len(s.tunnels)
	h.mu.RUnlock()
	if n >= h.opts.MaxTunnelsPerSession {
		return errMsg(protocol.CodeLimitExceeded, "at most %d tunnels per agent", h.opts.MaxTunnelsPerSession)
	}
	if reg.Private && reg.Proto != protocol.ProtoHTTP {
		return errMsg(protocol.CodeUnsupported, "only http tunnels can be private")
	}
	if reg.Private && !h.opts.PrivateTunnels {
		return errMsg(protocol.CodeUnsupported, "private tunnels need the dashboard (PostgreSQL) on this server")
	}
	var allow map[string]string
	if len(reg.Allow) > 0 {
		switch {
		case !reg.Private:
			return errMsg(protocol.CodeBadRequest, "allow only applies to private tunnels")
		case len(reg.Allow) > MaxAllow:
			return errMsg(protocol.CodeLimitExceeded, "a tunnel can be shared with at most %d accounts", MaxAllow)
		case h.opts.ResolveLogins == nil:
			return errMsg(protocol.CodeUnsupported, "this server cannot share private tunnels")
		}
		rctx, rcancel := context.WithTimeout(context.Background(), 10*time.Second)
		var err error
		allow, err = h.opts.ResolveLogins(rctx, reg.Allow)
		rcancel()
		switch {
		case errors.Is(err, ErrUnknownUser):
			return errMsg(protocol.CodeBadRequest, "%s", err.Error())
		case err != nil:
			h.log.Error("resolving allowed accounts failed", "err", err)
			return errMsg(protocol.CodeInternal, "could not look up the allowed accounts")
		}
	}
	t := &Tunnel{
		ID: randomID(12), Proto: reg.Proto, UserID: s.userID, CreatedAt: time.Now(), Private: reg.Private, Allow: allow,
		sess: s, sem: make(chan struct{}, h.opts.MaxConnsPerTunnel),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	switch reg.Proto {
	case protocol.ProtoHTTP:
		lease, err := h.domains.Acquire(ctx, s.userID, reg.Subdomain, t.ID)
		switch {
		case errors.Is(err, domain.ErrHostnameTaken):
			return errMsg(protocol.CodeHostnameTaken, "%s is not available", domain.NormalizeLabel(reg.Subdomain))
		case errors.Is(err, domain.ErrInvalidLabel):
			return errMsg(protocol.CodeHostnameInvalid, "%s", strings.TrimPrefix(err.Error(), "domain: "))
		case errors.Is(err, domain.ErrLimitReached):
			return errMsg(protocol.CodeLimitExceeded, "you have reached your custom subdomain limit; release one in the dashboard or use a random subdomain")
		case err != nil:
			h.log.Error("hostname reservation failed", "err", err)
			return errMsg(protocol.CodeInternal, "could not reserve a hostname")
		}
		t.lease, t.Hostname, t.PublicURL = lease, lease.Hostname, h.opts.PublicURL(lease.Hostname)
	case protocol.ProtoTCP:
		if h.opts.TCPPortMin == 0 {
			return errMsg(protocol.CodeUnsupported, "TCP tunnels are disabled on this server")
		}
		ln, port, err := h.listenTCP()
		if err != nil {
			return errMsg(protocol.CodeLimitExceeded, "no free TCP port available")
		}
		t.ln, t.Port = ln, port
		t.PublicURL = fmt.Sprintf("tcp://%s:%d", h.opts.TCPHost, port)
	default:
		return errMsg(protocol.CodeUnsupported, "protocol %q is not supported", reg.Proto)
	}

	h.mu.Lock()
	s.tunnels[t.ID] = t
	h.byID[t.ID] = t
	if t.Hostname != "" {
		h.byHost[t.Hostname] = t
	}
	h.mu.Unlock()
	if t.ln != nil {
		go h.acceptTCP(t)
	}
	h.log.Info("tunnel registered", "tunnel", t.ID, "session", s.id, "user", s.userID, "url", t.PublicURL)
	var names []string
	for _, n := range t.Allow {
		names = append(names, n)
	}
	sort.Strings(names)
	return &protocol.Message{Type: protocol.TypeRegistered, Registered: &protocol.Registered{
		TunnelID: t.ID, Proto: t.Proto, Hostname: t.Hostname, Port: t.Port, PublicURL: t.PublicURL, Private: t.Private, Allow: names,
	}}
}

func (h *Hub) listenTCP() (net.Listener, int, error) {
	size := h.opts.TCPPortMax - h.opts.TCPPortMin + 1
	start := int(time.Now().UnixNano() % int64(size))
	for i := 0; i < size; i++ {
		port := h.opts.TCPPortMin + (start+i)%size
		h.mu.Lock()
		_, used := h.ports[port]
		if !used {
			h.ports[port] = struct{}{}
		}
		h.mu.Unlock()
		if used {
			continue
		}
		ln, err := net.Listen("tcp", net.JoinHostPort(h.opts.TCPBindHost, fmt.Sprint(port)))
		if err == nil {
			return ln, port, nil
		}
		h.mu.Lock()
		delete(h.ports, port)
		h.mu.Unlock()
	}
	return nil, 0, errors.New("gateway: TCP port range exhausted")
}

func (h *Hub) acceptTCP(t *Tunnel) {
	for {
		c, err := t.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			start := time.Now()
			st, err := t.OpenStream(c.RemoteAddr().String())
			if err != nil {
				c.Close()
				return
			}
			in, out := netutil.Pipe(c, st)
			t.Notify(&protocol.Event{Time: start, DurationMs: time.Since(start).Milliseconds(),
				BytesIn: in, BytesOut: out, Remote: c.RemoteAddr().String()})
		}()
	}
}

// detachLocked removes t from every index. Caller holds h.mu.
func (h *Hub) detachLocked(t *Tunnel) {
	delete(t.sess.tunnels, t.ID)
	delete(h.byID, t.ID)
	if t.Hostname != "" && h.byHost[t.Hostname] == t {
		delete(h.byHost, t.Hostname)
	}
}

// closeTunnel frees the external resources of a detached tunnel.
func (h *Hub) closeTunnel(t *Tunnel) {
	if t.ln != nil {
		t.ln.Close()
		h.mu.Lock()
		delete(h.ports, t.Port)
		h.mu.Unlock()
	}
	if t.Hostname != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.domains.Release(ctx, t.lease, t.ID); err != nil {
			h.log.Error("hostname release failed", "hostname", t.Hostname, "err", err)
		}
	}
	h.log.Info("tunnel closed", "tunnel", t.ID, "url", t.PublicURL)
}

func (h *Hub) cleanup(s *session) {
	s.mux.Close()
	h.mu.Lock()
	tunnels := make([]*Tunnel, 0, len(s.tunnels))
	for _, t := range s.tunnels {
		tunnels = append(tunnels, t)
	}
	for _, t := range tunnels {
		h.detachLocked(t)
	}
	delete(h.sessions, s.id)
	if key := s.userID + "/" + s.instance; h.byInstance[key] == s {
		delete(h.byInstance, key)
	}
	h.mu.Unlock()
	for _, t := range tunnels {
		h.closeTunnel(t)
	}
	h.log.Info("agent disconnected", "session", s.id, "user", s.userID)
	close(s.done)
}
