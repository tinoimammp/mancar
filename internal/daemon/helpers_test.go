package daemon_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/tinoimammp/mancar/internal/daemon"
	"github.com/tinoimammp/mancar/internal/protocol"
)

// syncBuf is a goroutine-safe buffer: the daemon logs while tests read.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type result struct {
	code           int
	stdout, stderr string
}

func envFn(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func devVars() map[string]string {
	return map[string]string{"APP_ENV": "development", "STORAGE": "memory", "BASE_DOMAIN": "tunnel.test"}
}

func with(m map[string]string, kv ...string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = kv[i+1]
	}
	return out
}

func run(t *testing.T, vars map[string]string, args ...string) result {
	t.Helper()
	var out, errb syncBuf
	code := daemon.Main(context.Background(), args, daemon.Env{
		Getenv: envFn(vars), Stdout: &out, Stderr: &errb, DBWait: 1500 * time.Millisecond,
	})
	return result{code, out.String(), errb.String()}
}

func runStdin(t *testing.T, vars map[string]string, stdin string, args ...string) result {
	t.Helper()
	var out, errb syncBuf
	code := daemon.Main(context.Background(), args, daemon.Env{
		Getenv: envFn(vars), Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errb, DBWait: 1500 * time.Millisecond,
	})
	return result{code, out.String(), errb.String()}
}

// running is a "serve" started in the background on a loopback port.
type running struct {
	addr           string
	stdout, stderr *syncBuf
	cancel         context.CancelFunc
	done           chan int
}

func serve(t *testing.T, vars map[string]string) *running {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &running{addr: ln.Addr().String(), stdout: &syncBuf{}, stderr: &syncBuf{}, done: make(chan int, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	vars = with(vars, "LISTEN_ADDR", r.addr)
	go func() {
		r.done <- daemon.Main(ctx, []string{"serve"}, daemon.Env{
			Getenv: envFn(vars), Stdout: r.stdout, Stderr: r.stderr, Listener: ln,
		})
	}()
	t.Cleanup(func() { cancel(); r.wait(t) })
	r.waitHealthy(t, vars["BASE_DOMAIN"])
	return r
}

func (r *running) wait(t *testing.T) int {
	t.Helper()
	select {
	case code := <-r.done:
		r.done <- code
		return code
	case <-time.After(30 * time.Second):
		t.Fatal("daemon did not stop")
		return -1
	}
}

func (r *running) waitHealthy(t *testing.T, host string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case code := <-r.done:
			t.Fatalf("daemon exited early with code %d\nstdout: %s\nstderr: %s", code, r.stdout, r.stderr)
		default:
		}
		req, _ := http.NewRequest("GET", "http://"+r.addr+"/healthz", nil)
		req.Host = host
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("daemon never became healthy\nstdout: %s\nstderr: %s", r.stdout, r.stderr)
}

// upgradeStatus performs the agent handshake and returns the HTTP status.
func upgradeStatus(t *testing.T, addr, host, token string) int {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: %s\r\nAuthorization: Bearer %s\r\n\r\n",
		protocol.ConnectPath, host, protocol.UpgradeToken, token)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return resp.StatusCode
}

// schemaURL returns a DATABASE_URL pointing at a private schema of the
// database in TEST_DATABASE_URL, or skips the test.
func schemaURL(t *testing.T) string {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping PostgreSQL tests")
	}
	admin, err := sql.Open("postgres", base)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	rand.Read(b)
	schema := "d_" + hex.EncodeToString(b)
	if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Exec("DROP SCHEMA " + schema + " CASCADE"); admin.Close() })
	u, _ := url.Parse(base)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

func prodVars(dsn string) map[string]string {
	return map[string]string{
		"APP_ENV": "production", "BASE_DOMAIN": "tunnel.test",
		"JWT_SECRET":     strings.Repeat("j", 40),
		"ENCRYPTION_KEY": strings.Repeat("ab", 32),
		"DATABASE_URL":   dsn,
	}
}
