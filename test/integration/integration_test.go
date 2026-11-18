package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tinoimammp/mancar/internal/agent"
	"github.com/tinoimammp/mancar/internal/domain"
	"github.com/tinoimammp/mancar/internal/protocol"
	"github.com/tinoimammp/mancar/internal/server"
)

type echo struct {
	Method, Path, Query, Host, Body string
	Header                          http.Header
}

func echoServer(t *testing.T, name string) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Backend", name)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(echo{r.Method, r.URL.Path, r.URL.RawQuery, r.Host, string(b), r.Header})
	}))
	t.Cleanup(s.Close)
	return s
}

func httpSpec(backendURL, subdomain string) agent.TunnelSpec {
	return agent.TunnelSpec{Proto: protocol.ProtoHTTP, LocalAddr: localAddr(backendURL), Subdomain: subdomain}
}

func registrationCode(err error) string {
	var re *agent.RegistrationError
	if errors.As(err, &re) {
		return re.Err.Code
	}
	return fmt.Sprintf("not a registration error: %v", err)
}

// Scenarios 1-5: local server, tunnel, public URL, request/response
// forwarding, random hostname.
func TestHTTPForwardingWithRandomHostname(t *testing.T) {
	e := newEnv(t, nil)
	backend := echoServer(t, "one")
	ag := e.startAgent(e.token("alice"), "", httpSpec(backend.URL, ""))
	tun := ag.waitOnline(t)[0].Registered

	if !regexp.MustCompile(`^[a-z]+-[a-z]+(-\d{4})?\.tunnel\.test$`).MatchString(tun.Hostname) {
		t.Fatalf("unexpected random hostname %q", tun.Hostname)
	}
	if tun.PublicURL != "http://"+tun.Hostname {
		t.Fatalf("public URL %q", tun.PublicURL)
	}

	resp, body := e.do("POST", tun.Hostname, "/api/items?id=42&q=a+b", strings.NewReader(`{"hello":"world"}`),
		map[string]string{"X-Test": "yes", "X-Forwarded-For": "198.51.100.7", "X-Forwarded-Proto": "https"})
	if resp.StatusCode != http.StatusCreated || resp.Header.Get("X-Backend") != "one" {
		t.Fatalf("status=%d headers=%v body=%s", resp.StatusCode, resp.Header, body)
	}
	var got echo
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("body %q: %v", body, err)
	}
	if got.Method != "POST" || got.Path != "/api/items" || got.Query != "id=42&q=a+b" || got.Body != `{"hello":"world"}` {
		t.Fatalf("request not forwarded faithfully: %+v", got)
	}
	if got.Host != tun.Hostname {
		t.Errorf("Host = %q, want public hostname", got.Host)
	}
	if got.Header.Get("X-Test") != "yes" {
		t.Errorf("custom header lost")
	}
	// The test client is on loopback, a trusted proxy range by default, so
	// its forwarded headers are honoured (this is the edge-proxy path).
	if got.Header.Get("X-Forwarded-For") != "198.51.100.7" || got.Header.Get("X-Forwarded-Proto") != "https" ||
		got.Header.Get("X-Forwarded-Host") != tun.Hostname {
		t.Errorf("forwarded headers: %v", got.Header)
	}
}

func TestClientIPHeadersCannotBeSpoofed(t *testing.T) {
	e := newEnv(t, nil)
	tun := e.startAgent(e.token("alice"), "", httpSpec(echoServer(t, "one").URL, "")).waitOnline(t)[0].Registered
	_, body := e.do("GET", tun.Hostname, "/", nil, map[string]string{"X-Real-IP": "6.6.6.6", "True-Client-IP": "6.6.6.6", "CF-Connecting-IP": "6.6.6.6"})
	var got echo
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Header.Get("X-Real-IP") != "127.0.0.1" || got.Header.Get("True-Client-IP") != "" || got.Header.Get("CF-Connecting-IP") != "" {
		t.Errorf("client IP headers reached the app: %v", got.Header)
	}
}

func TestForwardedHeadersFromUntrustedClientsAreIgnored(t *testing.T) {
	e := newEnv(t, map[string]string{"TRUSTED_PROXIES": "192.0.2.0/24"})
	backend := echoServer(t, "one")
	tun := e.startAgent(e.token("alice"), "", httpSpec(backend.URL, "")).waitOnline(t)[0].Registered
	_, body := e.do("GET", tun.Hostname, "/", nil, map[string]string{"X-Forwarded-For": "6.6.6.6", "X-Forwarded-Proto": "https"})
	var got echo
	json.Unmarshal(body, &got)
	if got.Header.Get("X-Forwarded-For") != "127.0.0.1" || got.Header.Get("X-Forwarded-Proto") != "http" {
		t.Fatalf("spoofed forwarded headers were trusted: %v", got.Header)
	}
}

// Scenarios 6-7: custom hostname, duplicate rejection.
func TestCustomSubdomainAndDuplicateRejection(t *testing.T) {
	e := newEnv(t, nil)
	backend := echoServer(t, "alice")
	alice, bob := e.token("alice"), e.token("bob")

	tun := e.startAgent(alice, "", httpSpec(backend.URL, "My-API")).waitOnline(t)[0].Registered
	if tun.Hostname != "my-api.tunnel.test" {
		t.Fatalf("hostname = %q", tun.Hostname)
	}
	if resp, _ := e.do("GET", "my-api.tunnel.test", "/", nil, nil); resp.Header.Get("X-Backend") != "alice" {
		t.Fatal("custom hostname does not route to alice")
	}

	if code := registrationCode(e.startAgent(bob, "", httpSpec(backend.URL, "my-api")).waitExit(t)); code != protocol.CodeHostnameTaken {
		t.Fatalf("other user: %s", code)
	}
	if code := registrationCode(e.startAgent(alice, "", httpSpec(backend.URL, "my-api")).waitExit(t)); code != protocol.CodeHostnameTaken {
		t.Fatalf("same user, second agent while active: %s", code)
	}
	for _, bad := range []string{"admin", "a", "bad_name", "xn--pple-43d"} {
		if code := registrationCode(e.startAgent(bob, "", httpSpec(backend.URL, bad)).waitExit(t)); code != protocol.CodeHostnameInvalid {
			t.Fatalf("subdomain %q: %s", bad, code)
		}
	}
}

// Scenario 13: cross-user isolation.
func TestCrossUserIsolation(t *testing.T) {
	e := newEnv(t, nil)
	aliceBackend, bobBackend := echoServer(t, "alice"), echoServer(t, "bob")
	alice, bob := e.token("alice"), e.token("bob")

	a := e.startAgent(alice, "", httpSpec(aliceBackend.URL, "alice-app"))
	a.waitOnline(t)
	b := e.startAgent(bob, "", httpSpec(bobBackend.URL, "bob-app"))
	b.waitOnline(t)

	for host, want := range map[string]string{"alice-app.tunnel.test": "alice", "bob-app.tunnel.test": "bob"} {
		if resp, _ := e.do("GET", host, "/", nil, nil); resp.Header.Get("X-Backend") != want {
			t.Fatalf("%s served by %q", host, resp.Header.Get("X-Backend"))
		}
	}

	// Alice disconnects. Her name stays reserved for her: Bob cannot take
	// it over and receive traffic meant for her.
	a.stopAndWait(t)
	eventually(t, "alice's tunnel to go offline", func() bool {
		resp, _ := e.do("GET", "alice-app.tunnel.test", "/", nil, nil)
		return resp.StatusCode == http.StatusNotFound
	})
	if code := registrationCode(e.startAgent(bob, "", httpSpec(bobBackend.URL, "alice-app")).waitExit(t)); code != protocol.CodeHostnameTaken {
		t.Fatalf("bob claimed alice's held hostname: %s", code)
	}
	a2 := e.startAgent(alice, "", httpSpec(aliceBackend.URL, "alice-app"))
	a2.waitOnline(t)
	a2.stopAndWait(t)
	e.waitReleased(t, "alice-app.tunnel.test", "alice", 24*time.Hour)

	// After the hold period the name is free for anyone.
	e.advanceClock(25 * time.Hour)
	tun := e.startAgent(bob, "", httpSpec(bobBackend.URL, "alice-app")).waitOnline(t)[0].Registered
	if tun.Hostname != "alice-app.tunnel.test" {
		t.Fatalf("hostname = %q", tun.Hostname)
	}
}

// Scenario 12: authentication.
func TestAuthentication(t *testing.T) {
	e := newEnv(t, nil)
	backend := echoServer(t, "x")

	bogus := "mc_" + strings.Repeat("0", 64)
	if err := e.startAgent(bogus, "", httpSpec(backend.URL, "")).waitExit(t); !errors.Is(err, agent.ErrUnauthorized) {
		t.Fatalf("unknown token: %v", err)
	}
	if err := e.startAgent("not-a-token", "", httpSpec(backend.URL, "")).waitExit(t); !errors.Is(err, agent.ErrUnauthorized) {
		t.Fatalf("malformed token: %v", err)
	}
	tok := e.token("alice")
	ag := e.startAgent(tok, "", httpSpec(backend.URL, ""))
	ag.waitOnline(t)
	ag.stopAndWait(t)
	e.auth.Revoke(tok)
	if err := e.startAgent(tok, "", httpSpec(backend.URL, "")).waitExit(t); !errors.Is(err, agent.ErrUnauthorized) {
		t.Fatalf("revoked token: %v", err)
	}

	// The connect endpoint refuses plain HTTP requests and missing tokens.
	if resp, _ := e.do("GET", baseDomain, protocol.ConnectPath, nil, nil); resp.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("plain GET: %d", resp.StatusCode)
	}
	resp, _ := e.do("GET", baseDomain, protocol.ConnectPath, nil, map[string]string{"Connection": "Upgrade", "Upgrade": protocol.UpgradeToken})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("upgrade without token: %d", resp.StatusCode)
	}
	// The agent endpoint is not reachable through a tunnel hostname.
	resp, _ = e.do("GET", "whatever.tunnel.test", protocol.ConnectPath, nil, map[string]string{"Connection": "Upgrade", "Upgrade": protocol.UpgradeToken})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("connect via tunnel host: %d", resp.StatusCode)
	}
}

// Scenario 8: reconnect after a network interruption, keeping the hostname.
func TestReconnectAfterNetworkInterruption(t *testing.T) {
	e := newEnv(t, nil)
	backend := echoServer(t, "one")
	proxy := newFlakyProxy(t, e.addr)
	ag := e.startAgent(e.token("alice"), proxy.ln.Addr().String(), httpSpec(backend.URL, ""), httpSpec(backend.URL, "sticky"))
	first := ag.waitOnline(t)

	for round := 0; round < 3; round++ {
		proxy.cut()
		again := ag.waitOnline(t)
		for i := range first {
			if again[i].Registered.Hostname != first[i].Registered.Hostname {
				t.Fatalf("round %d: hostname changed from %s to %s", round, first[i].Registered.Hostname, again[i].Registered.Hostname)
			}
			if again[i].Registered.TunnelID == first[i].Registered.TunnelID {
				t.Fatalf("round %d: tunnel was not re-registered", round)
			}
			if resp, _ := e.do("GET", again[i].Registered.Hostname, "/", nil, nil); resp.StatusCode != http.StatusCreated {
				t.Fatalf("round %d: request after reconnect: %d", round, resp.StatusCode)
			}
		}
	}
	if st := e.srv.Hub().Stats(); st.Sessions != 1 || st.Tunnels != 2 {
		t.Fatalf("stale sessions left behind: %+v", st)
	}
}

// Scenario 10: WebSocket-style upgrade (HTTP/1.1 Upgrade + bidirectional
// stream). The gateway treats the upgraded stream as opaque bytes, so this
// covers WebSocket without needing a WebSocket library.
func TestWebSocketUpgradeForwarding(t *testing.T) {
	checkWebSocket(t, newEnv(t, nil))
}

// The inspector, traffic statistics and request log all hook into the proxy
// path; WebSocket upgrades must keep working with every one of them on.
func TestWebSocketWithAllFeaturesOn(t *testing.T) {
	e := newEnvWith(t, map[string]string{"ENCRYPTION_KEY": strings.Repeat("ab", 32)}, func(d *server.Deps) {
		d.Captures = &captureStore{}
		d.Usage = &usageStore{}
	})
	checkWebSocket(t, e)
}

func checkWebSocket(t *testing.T, e *env) {
	t.Helper()
	type seen struct{ host, origin, fwdHost string }
	got := make(chan seen, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || r.Header.Get("Sec-WebSocket-Key") == "" {
			http.Error(w, "expected websocket upgrade", http.StatusBadRequest)
			return
		}
		got <- seen{r.Host, r.Header.Get("Origin"), r.Header.Get("X-Forwarded-Host")}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: test\r\n\r\n")
		brw.Flush()
		brw.WriteString("server-first\n") // server speaks first, like a push
		brw.Flush()
		for {
			line, err := brw.ReadString('\n')
			if err != nil {
				return
			}
			brw.WriteString(strings.ToUpper(line))
			brw.Flush()
		}
	}))
	t.Cleanup(backend.Close)
	tun := e.startAgent(e.token("alice"), "", httpSpec(backend.URL, "ws-app")).waitOnline(t)[0].Registered

	conn, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	origin := "https://" + tun.Hostname
	fmt.Fprintf(conn, "GET /_next/hmr?id=abc HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"+
		"Origin: %s\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", tun.Hostname, origin)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get("Sec-WebSocket-Accept") != "test" {
		t.Fatalf("upgrade response: %d %v", resp.StatusCode, resp.Header)
	}
	// Dev servers (Next.js allowedDevOrigins, Vite) check Host and Origin.
	if s := <-got; s.host != tun.Hostname || s.origin != origin || s.fwdHost != tun.Hostname {
		t.Errorf("the local app saw host=%q origin=%q x-forwarded-host=%q", s.host, s.origin, s.fwdHost)
	}
	if line, _ := br.ReadString('\n'); line != "server-first\n" {
		t.Fatalf("server push: %q", line)
	}
	for i := 0; i < 20; i++ {
		msg := fmt.Sprintf("message-%d\n", i)
		fmt.Fprint(conn, msg)
		line, err := br.ReadString('\n')
		if err != nil || line != strings.ToUpper(msg) {
			t.Fatalf("echo %d: %q %v", i, line, err)
		}
	}
}

// Scenario 11: TCP forwarding.
func TestTCPForwarding(t *testing.T) {
	e := newEnv(t, nil)
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
	ag := e.startAgent(e.token("alice"), "", agent.TunnelSpec{Proto: protocol.ProtoTCP, LocalAddr: ln.Addr().String()})
	tun := ag.waitOnline(t)[0].Registered
	if tun.Port < 39200 || tun.Port > 39260 || tun.PublicURL != fmt.Sprintf("tcp://tunnel.test:%d", tun.Port) {
		t.Fatalf("unexpected TCP tunnel: %+v", tun)
	}

	dial := func() (net.Conn, error) {
		return net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", tun.Port), 2*time.Second)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := dial()
			if err != nil {
				t.Errorf("dial: %v", err)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			payload := make([]byte, 256*1024)
			rand.Read(payload)
			go func() { c.Write(payload); c.(*net.TCPConn).CloseWrite() }()
			got, err := io.ReadAll(c)
			if err != nil || !bytes.Equal(got, payload) {
				t.Errorf("conn %d: echoed %d bytes, err=%v", i, len(got), err)
			}
		}(i)
	}
	wg.Wait()

	// The public port closes when the agent goes away.
	ag.stopAndWait(t)
	eventually(t, "TCP port to close", func() bool {
		c, err := dial()
		if err == nil {
			c.Close()
		}
		return err != nil
	})
}

func TestMultipleTunnelsPerAgentAndLimit(t *testing.T) {
	e := newEnv(t, map[string]string{"MAX_TUNNELS_PER_AGENT": "2"})
	one, two := echoServer(t, "one"), echoServer(t, "two")
	tok := e.token("alice")
	tunnels := e.startAgent(tok, "", httpSpec(one.URL, "first"), httpSpec(two.URL, "second")).waitOnline(t)
	for i, want := range []string{"one", "two"} {
		if resp, _ := e.do("GET", tunnels[i].Registered.Hostname, "/", nil, nil); resp.Header.Get("X-Backend") != want {
			t.Fatalf("tunnel %d routed to %q", i, resp.Header.Get("X-Backend"))
		}
	}
	err := e.startAgent(tok, "", httpSpec(one.URL, ""), httpSpec(one.URL, ""), httpSpec(one.URL, "")).waitExit(t)
	if code := registrationCode(err); code != protocol.CodeLimitExceeded {
		t.Fatalf("tunnel limit: %s", code)
	}
}

func TestUnavailableTunnelsAreHandledGracefully(t *testing.T) {
	e := newEnv(t, nil)
	resp, _ := e.do("GET", "nobody-home.tunnel.test", "/", nil, nil)
	if resp.StatusCode != http.StatusNotFound || resp.Header.Get("X-Mancar-Error") != "tunnel_not_found" {
		t.Fatalf("unknown tunnel: %d %v", resp.StatusCode, resp.Header)
	}
	resp, _ = e.do("GET", "evil.example.org", "/", nil, nil)
	if resp.StatusCode != http.StatusNotFound || resp.Header.Get("X-Mancar-Error") != "unknown_host" {
		t.Fatalf("foreign host: %d %v", resp.StatusCode, resp.Header)
	}
	if resp, _ := e.do("GET", baseDomain, "/api/v1/system/health", nil, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("health: %d", resp.StatusCode)
	}

	// Agent online but the local service is down.
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := dead.Addr().String()
	dead.Close()
	tun := e.startAgent(e.token("alice"), "", agent.TunnelSpec{Proto: protocol.ProtoHTTP, LocalAddr: addr}).waitOnline(t)[0].Registered
	resp, body := e.do("GET", tun.Hostname, "/", nil, nil)
	if resp.StatusCode != http.StatusBadGateway || resp.Header.Get("X-Mancar-Error") != "local_service_unreachable" {
		t.Fatalf("local service down: %d %v %s", resp.StatusCode, resp.Header, body)
	}
}

func TestRequestBodyLimit(t *testing.T) {
	e := newEnv(t, map[string]string{"MAX_REQUEST_BODY_BYTES": "1024"})
	backend := echoServer(t, "one")
	tun := e.startAgent(e.token("alice"), "", httpSpec(backend.URL, "")).waitOnline(t)[0].Registered
	big := strings.Repeat("x", 8192)
	if resp, _ := e.do("POST", tun.Hostname, "/", strings.NewReader(big), nil); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("declared length: %d", resp.StatusCode)
	}
	// Unknown length (chunked) must be caught while streaming.
	if resp, _ := e.do("POST", tun.Hostname, "/", io.MultiReader(strings.NewReader(big)), nil); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked: %d", resp.StatusCode)
	}
	if resp, _ := e.do("POST", tun.Hostname, "/", strings.NewReader("small"), nil); resp.StatusCode != http.StatusCreated {
		t.Fatalf("small body: %d", resp.StatusCode)
	}
}

func TestPerTunnelConnectionLimit(t *testing.T) {
	e := newEnv(t, map[string]string{"MAX_CONNECTIONS_PER_TUNNEL": "2"})
	release := make(chan struct{})
	var inflight sync.WaitGroup
	inflight.Add(2)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			inflight.Done()
			<-release
		}
		w.Write([]byte("done"))
	}))
	t.Cleanup(backend.Close)
	tun := e.startAgent(e.token("alice"), "", httpSpec(backend.URL, "")).waitOnline(t)[0].Registered

	results := make(chan int, 2)
	for i := 0; i < 2; i++ {
		go func() { resp, _ := e.do("GET", tun.Hostname, "/slow", nil, nil); results <- resp.StatusCode }()
	}
	inflight.Wait()
	resp, _ := e.do("GET", tun.Hostname, "/third", nil, nil)
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("X-Mancar-Error") != "tunnel_busy" {
		t.Fatalf("over-limit request: %d %v", resp.StatusCode, resp.Header)
	}
	close(release)
	for i := 0; i < 2; i++ {
		if code := <-results; code != http.StatusOK {
			t.Fatalf("in-flight request: %d", code)
		}
	}
	eventually(t, "capacity to be returned", func() bool {
		resp, _ := e.do("GET", tun.Hostname, "/after", nil, nil)
		return resp.StatusCode == http.StatusOK
	})
}

// Large bodies in both directions plus many concurrent requests: checks
// multiplexing, flow control and that nothing is corrupted or truncated.
func TestLargeBodiesAndConcurrency(t *testing.T) {
	e := newEnv(t, nil)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := sha256.New()
		n, _ := io.Copy(h, r.Body)
		w.Header().Set("X-Received", fmt.Sprint(n))
		w.Header().Set("X-Sum", hex.EncodeToString(h.Sum(nil)))
		if r.URL.Path == "/download" {
			io.Copy(w, io.LimitReader(zeroReader{}, 16<<20))
		}
	}))
	t.Cleanup(backend.Close)
	tun := e.startAgent(e.token("alice"), "", httpSpec(backend.URL, "")).waitOnline(t)[0].Registered

	payload := make([]byte, 16<<20)
	rand.Read(payload)
	sum := sha256.Sum256(payload)
	resp, _ := e.do("POST", tun.Hostname, "/upload", bytes.NewReader(payload), nil)
	if resp.Header.Get("X-Sum") != hex.EncodeToString(sum[:]) {
		t.Fatalf("upload corrupted: received %s bytes", resp.Header.Get("X-Received"))
	}
	if _, body := e.do("GET", tun.Hostname, "/download", nil, nil); len(body) != 16<<20 {
		t.Fatalf("download truncated: %d bytes", len(body))
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := strings.Repeat(fmt.Sprint(i), 1000)
			want := sha256.Sum256([]byte(body))
			resp, _ := e.do("POST", tun.Hostname, "/c", strings.NewReader(body), nil)
			if resp.Header.Get("X-Sum") != hex.EncodeToString(want[:]) {
				t.Errorf("request %d: body mixed up with another request", i)
			}
		}(i)
	}
	wg.Wait()
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// Scenario 15: graceful shutdown of agent and gateway.
func TestGracefulShutdown(t *testing.T) {
	e := newEnv(t, nil)
	backend := echoServer(t, "one")
	alice := e.token("alice")

	// Agent shutdown: the tunnel disappears promptly and frees its name.
	ag := e.startAgent(alice, "", httpSpec(backend.URL, "bye"))
	ag.waitOnline(t)
	ag.stopAndWait(t)
	eventually(t, "tunnel removal after agent shutdown", func() bool { return e.srv.Hub().Stats().Tunnels == 0 })
	if resp, _ := e.do("GET", "bye.tunnel.test", "/", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("tunnel still served after agent shutdown: %d", resp.StatusCode)
	}

	// Gateway shutdown: an in-flight request completes, sessions are
	// closed, hostnames are released, and Serve returns cleanly.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.Write([]byte("finished"))
	}))
	t.Cleanup(slow.Close)
	ag2 := e.startAgent(alice, "", httpSpec(slow.URL, "bye"))
	ag2.waitOnline(t)
	inflight := make(chan string, 1)
	go func() { _, b := e.do("GET", "bye.tunnel.test", "/", nil, nil); inflight <- string(b) }()
	time.Sleep(100 * time.Millisecond)

	if err := e.shutdown(); err != nil {
		t.Fatalf("gateway shutdown: %v", err)
	}
	if got := <-inflight; got != "finished" {
		t.Fatalf("in-flight request was cut off: %q", got)
	}
	if st := e.srv.Hub().Stats(); st.Sessions != 0 || st.Tunnels != 0 {
		t.Fatalf("sessions left after shutdown: %+v", st)
	}
	// The reservation is inactive again (claimable by its owner).
	if _, err := e.reg.Claim(context.Background(), domain.Claim{Hostname: "bye.tunnel.test", OwnerID: "alice", Kind: domain.KindCustom, TunnelID: "check"}); err != nil {
		t.Fatalf("hostname not released on shutdown: %v", err)
	}
}

// Private tunnels sign visitors in through the dashboard, so a gateway
// without accounts refuses them instead of serving them publicly.
func TestPrivateTunnelNeedsTheDashboard(t *testing.T) {
	e := newEnv(t, nil)
	spec := httpSpec(echoServer(t, "one").URL, "")
	spec.Private = true
	err := e.startAgent(e.token("alice"), "", spec).waitExit(t)
	if code := registrationCode(err); code != protocol.CodeUnsupported {
		t.Fatalf("registration code = %s", code)
	}
}

// One account cannot take the whole TCP port range.
func TestTCPTunnelsArePerAccount(t *testing.T) {
	e := newEnv(t, map[string]string{"MAX_TCP_TUNNELS_PER_USER": "2"})
	tcp := agent.TunnelSpec{Proto: protocol.ProtoTCP, LocalAddr: "127.0.0.1:1"}
	err := e.startAgent(e.token("alice"), "", tcp, tcp, tcp).waitExit(t)
	if code := registrationCode(err); code != protocol.CodeLimitExceeded {
		t.Fatalf("third TCP tunnel: %s", code)
	}
	// another account still gets ports
	e.startAgent(e.token("bob"), "", tcp).waitOnline(t)
}
