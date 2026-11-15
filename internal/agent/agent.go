// Package agent implements the tunnel agent: it keeps one outbound,
// authenticated, multiplexed connection to the gateway, registers tunnels
// and forwards every stream it receives to the configured local service.
//
// The agent only ever dials the local addresses the user configured. The
// gateway cannot ask it to connect anywhere else, so a compromised or
// misbehaving gateway cannot turn the agent into a proxy into the user's
// network.
package agent

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/tinoimammp/mancar/internal/netutil"
	"github.com/tinoimammp/mancar/internal/protocol"
	"github.com/tinoimammp/mancar/internal/version"
)

// TunnelSpec describes one tunnel the agent should maintain.
type TunnelSpec struct {
	Name      string `json:"name,omitempty"`
	Proto     string `json:"proto"`
	LocalAddr string `json:"addr"`                // host:port of the local service
	Subdomain string `json:"subdomain,omitempty"` // empty = random (HTTP only)
}

// Options configures an Agent.
type Options struct {
	ServerURL string // https://tunnel.example.com
	// DialAddr optionally overrides the TCP address to connect to while
	// ServerURL still provides the Host header and TLS server name.
	DialAddr string
	Token    string
	Tunnels  []TunnelSpec

	OnStatus   func(Status) // called on every state change
	Logger     *slog.Logger
	TLSConfig  *tls.Config
	KeepAlive  time.Duration
	MinBackoff time.Duration
	MaxBackoff time.Duration
}

// State of the agent connection.
type State string

const (
	StateConnecting   State = "connecting"
	StateOnline       State = "online"
	StateReconnecting State = "reconnecting"
)

// TunnelStatus pairs a spec with what the gateway assigned.
type TunnelStatus struct {
	Spec       TunnelSpec
	Registered protocol.Registered
}

// Status is a snapshot passed to Options.OnStatus.
type Status struct {
	State   State
	Tunnels []TunnelStatus
	Err     error // reason for (re)connecting, if any
}

// ErrUnauthorized means the gateway rejected the agent token.
var ErrUnauthorized = errors.New("agent: the server rejected the agent token")

// RegistrationError means the gateway refused to create a tunnel.
type RegistrationError struct {
	Spec TunnelSpec
	Err  *protocol.Error
}

func (e *RegistrationError) Error() string {
	return fmt.Sprintf("tunnel %s -> %s rejected: %s", e.Spec.Proto, e.Spec.LocalAddr, e.Err.Message)
}

// fatalError marks connection errors that retrying cannot fix.
type fatalError struct{ error }

func (e fatalError) Unwrap() error { return e.error }

// Agent maintains the tunnels described by Options.
type Agent struct {
	opts     Options
	log      *slog.Logger
	instance string
	assigned []string // subdomain label last assigned per tunnel (sticky across reconnects)
}

// New validates options and returns an Agent.
func New(opts Options) (*Agent, error) {
	u, err := url.Parse(opts.ServerURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("agent: server URL must look like https://tunnel.example.com (got %q)", opts.ServerURL)
	}
	if opts.Token == "" {
		return nil, errors.New("agent: an agent token is required")
	}
	if len(opts.Tunnels) == 0 {
		return nil, errors.New("agent: no tunnels configured")
	}
	for _, t := range opts.Tunnels {
		if t.Proto != protocol.ProtoHTTP && t.Proto != protocol.ProtoTCP {
			return nil, fmt.Errorf("agent: unsupported protocol %q", t.Proto)
		}
		if _, _, err := net.SplitHostPort(t.LocalAddr); err != nil {
			return nil, fmt.Errorf("agent: local address %q must be host:port", t.LocalAddr)
		}
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.MinBackoff <= 0 {
		opts.MinBackoff = time.Second
	}
	if opts.MaxBackoff <= 0 {
		opts.MaxBackoff = 30 * time.Second
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return &Agent{opts: opts, log: opts.Logger, instance: hex.EncodeToString(b), assigned: make([]string, len(opts.Tunnels))}, nil
}

func (a *Agent) notify(s Status) {
	if a.opts.OnStatus != nil {
		a.opts.OnStatus(s)
	}
}

// Run connects and serves until ctx is cancelled (returns nil) or a
// non-recoverable error occurs (bad token, rejected tunnel). Network
// failures are retried forever with exponential backoff and jitter.
func (a *Agent) Run(ctx context.Context) error {
	backoff := a.opts.MinBackoff
	state := StateConnecting
	var lastErr error
	for {
		a.notify(Status{State: state, Err: lastErr})
		sess, err := a.connect(ctx)
		if err == nil {
			var tunnels []TunnelStatus
			tunnels, err = a.registerAll(sess)
			if err == nil {
				backoff = a.opts.MinBackoff
				a.notify(Status{State: StateOnline, Tunnels: tunnels})
				err = a.serve(ctx, sess, tunnels)
			}
			sess.Close()
		}
		if ctx.Err() != nil {
			return nil
		}
		var regErr *RegistrationError
		var fatal fatalError
		if errors.Is(err, ErrUnauthorized) || errors.As(err, &regErr) || errors.As(err, &fatal) {
			return err
		}
		lastErr, state = err, StateReconnecting
		a.log.Warn("connection lost", "err", err, "retry_in", backoff)
		sleep := backoff/2 + time.Duration(mrand.Int64N(int64(backoff/2)+1))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(sleep):
		}
		if backoff *= 2; backoff > a.opts.MaxBackoff {
			backoff = a.opts.MaxBackoff
		}
	}
}

func (a *Agent) connect(ctx context.Context) (*yamux.Session, error) {
	u, _ := url.Parse(a.opts.ServerURL)
	addr := a.opts.DialAddr
	if addr == "" {
		addr = u.Host
		if u.Port() == "" {
			port := "443"
			if u.Scheme == "http" {
				port = "80"
			}
			addr = net.JoinHostPort(u.Hostname(), port)
		}
	}
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "https" {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if a.opts.TLSConfig != nil {
			cfg = a.opts.TLSConfig.Clone()
		}
		if cfg.ServerName == "" {
			cfg.ServerName = u.Hostname()
		}
		// The upgrade handshake is HTTP/1.1; do not let the edge pick h2.
		cfg.NextProtos = []string{"http/1.1"}
		tc := tls.Client(conn, cfg)
		hctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := tc.HandshakeContext(hctx)
		cancel()
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake with %s failed: %w", u.Hostname(), err)
		}
		conn = tc
	}

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	req, err := http.NewRequest(http.MethodGet, "http://"+u.Host+protocol.ConnectPath, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", protocol.UpgradeToken)
	req.Header.Set("Authorization", "Bearer "+a.opts.Token)
	req.Header.Set(protocol.HeaderInstance, a.instance)
	req.Header.Set(protocol.HeaderAgentVersion, version.Version)
	req.Header.Set("User-Agent", "mancar-agent/"+version.Version)
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("reading server response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		conn.Close()
		msg := fmt.Errorf("server answered %s: %s", resp.Status, strings.TrimSpace(string(body)))
		switch {
		case resp.StatusCode == http.StatusUnauthorized:
			return nil, ErrUnauthorized
		case resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests:
			return nil, fatalError{msg} // wrong URL or incompatible server
		}
		return nil, msg
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), protocol.UpgradeToken) {
		conn.Close()
		return nil, fatalError{errors.New("server does not speak the mancar protocol")}
	}
	_ = conn.SetDeadline(time.Time{})
	return yamux.Client(&netutil.BufferedConn{Conn: conn, R: br}, protocol.YamuxConfig(a.opts.KeepAlive))
}

func (a *Agent) registerAll(sess *yamux.Session) ([]TunnelStatus, error) {
	ctrl, err := sess.Open()
	if err != nil {
		return nil, err
	}
	br := protocol.NewControlReader(ctrl)
	call := func(i int, reg protocol.Register) (*protocol.Message, error) {
		_ = ctrl.SetDeadline(time.Now().Add(20 * time.Second))
		defer ctrl.SetDeadline(time.Time{})
		id := strconv.Itoa(i)
		if err := protocol.WriteJSONLine(ctrl, protocol.Message{Type: protocol.TypeRegister, ReqID: id, Register: &reg}); err != nil {
			return nil, err
		}
		m, err := protocol.ReadMessage(br)
		if err != nil {
			return nil, err
		}
		if m.ReqID != id {
			return nil, errors.New("agent: out-of-order control response")
		}
		return m, nil
	}

	out := make([]TunnelStatus, 0, len(a.opts.Tunnels))
	for i, spec := range a.opts.Tunnels {
		label := spec.Subdomain
		if a.assigned[i] != "" {
			label = a.assigned[i] // keep the same public name across reconnects
		}
		m, err := call(i, protocol.Register{Proto: spec.Proto, Subdomain: label})
		if err != nil {
			return nil, err
		}
		if m.Type == protocol.TypeError && m.Error != nil && m.Error.Code == protocol.CodeHostnameTaken &&
			spec.Subdomain == "" && label != "" {
			// Our previous random name was taken meanwhile: get a new one.
			if m, err = call(i, protocol.Register{Proto: spec.Proto}); err != nil {
				return nil, err
			}
		}
		if m.Type != protocol.TypeRegistered || m.Registered == nil {
			perr := m.Error
			if perr == nil {
				perr = &protocol.Error{Code: protocol.CodeInternal, Message: "unexpected server response"}
			}
			return nil, &RegistrationError{Spec: spec, Err: perr}
		}
		if m.Registered.Hostname != "" {
			a.assigned[i], _, _ = strings.Cut(m.Registered.Hostname, ".")
		}
		out = append(out, TunnelStatus{Spec: spec, Registered: *m.Registered})
	}
	// Keep reading the control stream so a closed session is noticed even
	// when no traffic flows.
	go io.Copy(io.Discard, br)
	return out, nil
}

func (a *Agent) serve(ctx context.Context, sess *yamux.Session, tunnels []TunnelStatus) error {
	byID := make(map[string]TunnelSpec, len(tunnels))
	for _, t := range tunnels {
		byID[t.Registered.TunnelID] = t.Spec
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			sess.Close() // graceful: the gateway sees the session end and frees the tunnels
		case <-stop:
		}
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		st, err := sess.Accept()
		if err != nil {
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.handleStream(st, byID)
		}()
	}
}

const localDown = "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\n" +
	"X-Mancar-Error: local_service_unreachable\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s"

func (a *Agent) handleStream(st net.Conn, tunnels map[string]TunnelSpec) {
	_ = st.SetReadDeadline(time.Now().Add(10 * time.Second))
	hdr, err := protocol.ReadStreamHeader(st)
	_ = st.SetReadDeadline(time.Time{})
	if err != nil {
		st.Close()
		return
	}
	spec, ok := tunnels[hdr.TunnelID]
	if !ok {
		st.Close() // never forward a stream for a tunnel we did not register
		return
	}
	local, err := net.DialTimeout("tcp", spec.LocalAddr, 5*time.Second)
	if err != nil {
		a.log.Warn("local service unreachable", "addr", spec.LocalAddr, "err", err)
		if spec.Proto == protocol.ProtoHTTP {
			body := fmt.Sprintf("mancar: the local service at %s is not reachable.\n", spec.LocalAddr)
			_ = st.SetWriteDeadline(time.Now().Add(5 * time.Second))
			fmt.Fprintf(st, localDown, len(body), body)
		}
		st.Close()
		return
	}
	netutil.Pipe(st, local)
}
