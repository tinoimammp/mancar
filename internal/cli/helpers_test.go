package cli_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinoimammp/mancar/internal/cli"
	"github.com/tinoimammp/mancar/internal/daemon"
)

const (
	baseDomain = "tunnel.test"
	devToken   = "mc_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// syncBuf is a goroutine-safe buffer: commands write while tests read.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// ---- a real gateway (the daemon in memory mode) ---------------------------------

var portBlock atomic.Int32

type gateway struct {
	addr   string
	cancel context.CancelFunc
	done   chan int
	once   sync.Once
}

// startGateway runs the real mancard. addr "" picks a free loopback port.
func startGateway(t *testing.T, addr string) *gateway {
	t.Helper()
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	lo := 39300 + 10*int(portBlock.Add(1))
	vars := map[string]string{
		"APP_ENV": "development", "STORAGE": "memory", "BASE_DOMAIN": baseDomain,
		"PUBLIC_SCHEME": "http", "DEV_AGENT_TOKEN": devToken,
		"TCP_PORT_RANGE": fmt.Sprintf("%d-%d", lo, lo+9), "LOG_LEVEL": "error",
	}
	g := &gateway{addr: ln.Addr().String(), done: make(chan int, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	g.cancel = cancel
	go func() {
		g.done <- daemon.Main(ctx, []string{"serve"}, daemon.Env{
			Getenv: func(k string) string { return vars[k] }, Stdout: io.Discard, Stderr: io.Discard, Listener: ln,
		})
	}()
	t.Cleanup(g.stop)
	eventually(t, "the gateway to become healthy", func() bool {
		req, _ := http.NewRequest("GET", "http://"+g.addr+"/healthz", nil)
		req.Host = baseDomain
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})
	return g
}

// stop shuts the gateway down and waits for it; it is safe to call twice
// (once by the test, once by t.Cleanup).
func (g *gateway) stop() {
	g.once.Do(func() {
		g.cancel()
		select {
		case <-g.done:
		case <-time.After(30 * time.Second):
		}
	})
}

// get sends a public request to the gateway with the given Host.
func (g *gateway) get(t *testing.T, host, path string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://"+g.addr+path, nil)
	req.Host = host
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s%s: %v", host, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// ---- local services ---------------------------------------------------------------

func httpBackend(t *testing.T, name string) (port string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", name)
		fmt.Fprintf(w, "hello from %s path=%s host=%s", name, r.URL.Path, r.Host)
	}))
	t.Cleanup(srv.Close)
	_, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return p
}

func tcpEcho(t *testing.T) (port string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	return p
}

// ---- a user's machine -------------------------------------------------------------

// machine is one user's computer: a config directory, a state directory and
// a set of "processes" (CLI invocations running in goroutines). Nothing ever
// signals the real test process: "stop" cancels the invocation's context.
type machine struct {
	t        *testing.T
	vars     map[string]string
	cfgDir   string
	stateDir string

	mu      sync.Mutex
	nextPID int
	procs   map[int]context.CancelFunc
}

func newMachine(t *testing.T, vars map[string]string) *machine {
	t.Helper()
	return &machine{
		t: t, vars: vars, nextPID: 40000, procs: map[int]context.CancelFunc{},
		cfgDir: filepath.Join(t.TempDir(), "cfg"), stateDir: filepath.Join(t.TempDir(), "state"),
	}
}

// connected returns variables that point the CLI at gw with a valid token.
func connected(gw *gateway) map[string]string {
	return map[string]string{
		"MANCAR_SERVER": "http://" + baseDomain, "MANCAR_DIAL_ADDR": gw.addr, "MANCAR_TOKEN": devToken,
	}
}

func (m *machine) env(stdin string, interactive bool, pid int) (cli.Env, *syncBuf, *syncBuf) {
	var out, errb syncBuf
	return cli.Env{
		Getenv: func(k string) string { return m.vars[k] },
		Stdin:  strings.NewReader(stdin), Stdout: &out, Stderr: &errb,
		ConfigDir: m.cfgDir, StateDir: m.stateDir, Interactive: interactive,
		PID: func() int { return pid },
		PidAlive: func(p int) bool {
			m.mu.Lock()
			defer m.mu.Unlock()
			_, ok := m.procs[p]
			return ok
		},
		Terminate: func(p int) error {
			m.mu.Lock()
			cancel, ok := m.procs[p]
			m.mu.Unlock()
			if !ok {
				return fmt.Errorf("no such process %d", p)
			}
			cancel()
			return nil
		},
		HeartbeatEvery: 100 * time.Millisecond,
	}, &out, &errb
}

type result struct {
	code           int
	stdout, stderr string
}

// run executes a short-lived command synchronously.
func (m *machine) run(args ...string) result { return m.runIn("", false, args...) }

func (m *machine) runIn(stdin string, interactive bool, args ...string) result {
	m.t.Helper()
	m.mu.Lock()
	m.nextPID++
	pid := m.nextPID
	m.mu.Unlock()
	e, out, errb := m.env(stdin, interactive, pid)
	code := cli.Main(context.Background(), args, e)
	return result{code, out.String(), errb.String()}
}

// proc is a long-running invocation (an agent).
type proc struct {
	pid    int
	out    *syncBuf
	err    *syncBuf
	cancel context.CancelFunc
	done   chan int
}

func (m *machine) start(args ...string) *proc { return m.startIn("", false, args...) }

func (m *machine) startIn(stdin string, interactive bool, args ...string) *proc {
	m.t.Helper()
	m.mu.Lock()
	m.nextPID++
	pid := m.nextPID
	ctx, cancel := context.WithCancel(context.Background())
	m.procs[pid] = cancel
	m.mu.Unlock()

	e, out, errb := m.env(stdin, interactive, pid)
	p := &proc{pid: pid, out: out, err: errb, cancel: cancel, done: make(chan int, 1)}
	go func() {
		code := cli.Main(ctx, args, e)
		m.mu.Lock()
		delete(m.procs, pid)
		m.mu.Unlock()
		p.done <- code
	}()
	m.t.Cleanup(func() { cancel(); p.waitExit(m.t) })
	return p
}

func (p *proc) waitExit(t *testing.T) int {
	t.Helper()
	select {
	case code := <-p.done:
		p.done <- code
		return code
	case <-time.After(30 * time.Second):
		t.Fatalf("process %d did not exit\nstdout:\n%s\nstderr:\n%s", p.pid, p.out, p.err)
		return -1
	}
}

// waitOut waits until stdout contains s (failing early if the process died).
func (p *proc) waitOut(t *testing.T, s string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(p.out.String(), s) {
			return
		}
		select {
		case code := <-p.done:
			p.done <- code
			if strings.Contains(p.out.String(), s) {
				return
			}
			t.Fatalf("process exited with %d before printing %q\nstdout:\n%s\nstderr:\n%s", code, s, p.out, p.err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q\nstdout:\n%s\nstderr:\n%s", s, p.out, p.err)
}

func (m *machine) stateFiles() []string {
	f, _ := filepath.Glob(filepath.Join(m.stateDir, "agent-*.json"))
	return f
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}
