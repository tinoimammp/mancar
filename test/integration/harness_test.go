// Package integration_test runs the real gateway, routing engine and agent
// against each other over loopback TCP. Nothing is mocked except storage
// (in-memory implementations that share a contract test-suite with the
// PostgreSQL ones).
package integration_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/tinoimammp/mancar/internal/agent"
	"github.com/tinoimammp/mancar/internal/auth"
	"github.com/tinoimammp/mancar/internal/config"
	"github.com/tinoimammp/mancar/internal/domain"
	"github.com/tinoimammp/mancar/internal/server"
)

const baseDomain = "tunnel.test"

type env struct {
	t       *testing.T
	addr    string // gateway listen address
	auth    *auth.Memory
	reg     *domain.MemoryRegistry
	srv     *server.Server
	stop    context.CancelFunc
	done    chan error
	clockMu sync.Mutex
	offset  time.Duration
}

func newEnv(t *testing.T, overrides map[string]string) *env {
	t.Helper()
	vars := map[string]string{
		"APP_ENV": "development", "STORAGE": "memory", "BASE_DOMAIN": baseDomain,
		"PUBLIC_SCHEME": "http", "TCP_PORT_RANGE": "39200-39260",
	}
	for k, v := range overrides {
		vars[k] = v
	}
	cfg, err := config.Load(func(k string) string { return vars[k] })
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, auth: auth.NewMemory(), reg: domain.NewMemoryRegistry(), done: make(chan error, 1)}
	e.reg.Now = func() time.Time {
		e.clockMu.Lock()
		defer e.clockMu.Unlock()
		return time.Now().Add(e.offset)
	}
	e.srv = server.New(server.Deps{Config: cfg, Auth: e.auth, Registry: e.reg, TCPBindHost: "127.0.0.1", KeepAlive: time.Second})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e.addr = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	e.stop = cancel
	go func() { e.done <- e.srv.Serve(ctx, ln) }()
	t.Cleanup(func() { e.shutdown() })
	return e
}

func (e *env) shutdown() error {
	e.stop()
	select {
	case err := <-e.done:
		e.done <- err
		return err
	case <-time.After(20 * time.Second):
		return errors.New("gateway did not shut down")
	}
}

func (e *env) advanceClock(d time.Duration) {
	e.clockMu.Lock()
	e.offset += d
	e.clockMu.Unlock()
}

// waitReleased blocks until the gateway has finished its (asynchronous)
// clean-up of a disconnected agent and released hostname back to the
// registry. Gateway clean-up first removes the tunnel from the routing table
// and only then releases the name, so "the public URL returns 404" is not
// proof that the release happened. Tests that move the clock must wait for
// the release first, otherwise the hold period would be measured from the
// moved clock.
//
// It works by probing the registry: while the tunnel is still active a claim
// is refused; once released, the probe claim succeeds and is immediately
// released again with the real hold, which is exactly what the gateway does.
func (e *env) waitReleased(t *testing.T, hostname, owner string, hold time.Duration) {
	t.Helper()
	const probe = "release-probe"
	eventually(t, "the gateway to release "+hostname, func() bool {
		_, err := e.reg.Claim(context.Background(), domain.Claim{
			Hostname: hostname, OwnerID: owner, Kind: domain.KindCustom, TunnelID: probe,
		})
		return err == nil
	})
	if err := e.reg.Release(context.Background(), hostname, probe, hold); err != nil {
		t.Fatal(err)
	}
}

func (e *env) token(user string) string {
	tok, err := e.auth.Issue(user)
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

// runningAgent is an agent started in the background.
type runningAgent struct {
	status chan agent.Status
	result chan error
	cancel context.CancelFunc
}

func (e *env) startAgent(token, dialAddr string, specs ...agent.TunnelSpec) *runningAgent {
	e.t.Helper()
	if dialAddr == "" {
		dialAddr = e.addr
	}
	ra := &runningAgent{status: make(chan agent.Status, 64), result: make(chan error, 1)}
	a, err := agent.New(agent.Options{
		ServerURL: "http://" + baseDomain, DialAddr: dialAddr, Token: token, Tunnels: specs,
		KeepAlive: time.Second, MinBackoff: 20 * time.Millisecond, MaxBackoff: 200 * time.Millisecond,
		OnStatus: func(s agent.Status) {
			select {
			case ra.status <- s:
			default:
			}
		},
	})
	if err != nil {
		e.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ra.cancel = cancel
	go func() { ra.result <- a.Run(ctx) }()
	e.t.Cleanup(func() { cancel() })
	return ra
}

// waitOnline blocks until the agent reports StateOnline.
func (ra *runningAgent) waitOnline(t *testing.T) []agent.TunnelStatus {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case s := <-ra.status:
			if s.State == agent.StateOnline {
				return s.Tunnels
			}
		case err := <-ra.result:
			t.Fatalf("agent exited before coming online: %v", err)
		case <-deadline:
			t.Fatal("agent did not come online in time")
		}
	}
}

// waitExit returns the agent's final error.
func (ra *runningAgent) waitExit(t *testing.T) error {
	t.Helper()
	select {
	case err := <-ra.result:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not exit in time")
		return nil
	}
}

func (ra *runningAgent) stopAndWait(t *testing.T) {
	t.Helper()
	ra.cancel()
	if err := ra.waitExit(t); err != nil {
		t.Fatalf("agent stop: %v", err)
	}
}

// do sends a request to the gateway with the given public Host.
func (e *env) do(method, host, path string, body io.Reader, hdr map[string]string) (*http.Response, []byte) {
	e.t.Helper()
	req, err := http.NewRequest(method, "http://"+e.addr+path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	req.Host = host
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}).Do(req)
	if err != nil {
		e.t.Fatalf("%s %s%s: %v", method, host, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp, b
}

// eventually polls cond until it is true or the timeout expires.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func localAddr(url string) string { return url[len("http://"):] }

// flakyProxy is a TCP forwarder whose connections can be cut on demand to
// simulate a network interruption between agent and gateway.
type flakyProxy struct {
	ln     net.Listener
	target string
	mu     sync.Mutex
	conns  []net.Conn
}

func newFlakyProxy(t *testing.T, target string) *flakyProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &flakyProxy{ln: ln, target: target}
	t.Cleanup(func() { ln.Close(); p.cut() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, c, up)
			p.mu.Unlock()
			go func() { io.Copy(up, c); up.Close() }()
			go func() { io.Copy(c, up); c.Close() }()
		}
	}()
	return p
}

func (p *flakyProxy) cut() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.Close()
	}
	p.conns = nil
}
