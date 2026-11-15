package integration_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tinoimammp/mancar/internal/agent"
	"github.com/tinoimammp/mancar/internal/protocol"
	"github.com/tinoimammp/mancar/internal/server"
	"github.com/tinoimammp/mancar/internal/usage"
)

func nextEvent(t *testing.T, ra *runningAgent) protocol.Event {
	t.Helper()
	select {
	case ev := <-ra.events:
		return ev
	case <-time.After(10 * time.Second):
		t.Fatal("no request-log event reached the agent")
		return protocol.Event{}
	}
}

func TestAgentReceivesHTTPRequestLog(t *testing.T) {
	e := newEnv(t, nil)
	backend := echoServer(t, "one")
	ra := e.startAgent(e.token("alice"), "", httpSpec(backend.URL, ""))
	tun := ra.waitOnline(t)[0].Registered

	resp, _ := e.do("POST", tun.Hostname, "/orders?secret=x", strings.NewReader("hello"), nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("request: %d", resp.StatusCode)
	}
	ev := nextEvent(t, ra)
	if ev.TunnelID != tun.TunnelID || ev.Method != "POST" || ev.Path != "/orders" || ev.Status != http.StatusCreated {
		t.Errorf("event: %+v", ev)
	}
	if ev.BytesIn != 5 || ev.BytesOut == 0 || ev.Time.IsZero() {
		t.Errorf("sizes/time: %+v", ev)
	}
	if strings.Contains(ev.Path, "secret") {
		t.Error("the query string reached the request log")
	}

	// Errors are reported too.
	resp, _ = e.do("GET", tun.Hostname, "/again", nil, nil)
	if ev := nextEvent(t, ra); ev.Path != "/again" || ev.Status != resp.StatusCode {
		t.Errorf("second event: %+v", ev)
	}
}

func TestAgentReceivesTCPConnectionLog(t *testing.T) {
	e := newEnv(t, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	ra := e.startAgent(e.token("alice"), "", agent.TunnelSpec{Proto: protocol.ProtoTCP, LocalAddr: ln.Addr().String()})
	tun := ra.waitOnline(t)[0].Registered

	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tun.Port))
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("ping"))
	buf := make([]byte, 4)
	io.ReadFull(c, buf)
	c.(*net.TCPConn).CloseWrite()
	io.Copy(io.Discard, c)
	c.Close()

	ev := nextEvent(t, ra)
	if ev.TunnelID != tun.TunnelID || ev.BytesIn != 4 || ev.BytesOut != 4 || ev.Remote == "" || ev.Method != "" {
		t.Errorf("tcp event: %+v", ev)
	}
}

type usageStore struct {
	mu   sync.Mutex
	rows []usage.Row
}

func (u *usageStore) AddUsage(_ context.Context, rows []usage.Row) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.rows = append(u.rows, rows...)
	return nil
}

func (u *usageStore) PurgeUsage(context.Context, time.Time) (int64, error) { return 0, nil }

func TestTrafficIsCountedPerHostname(t *testing.T) {
	st := &usageStore{}
	e := newEnvWith(t, nil, func(d *server.Deps) { d.Usage = st })
	backend := echoServer(t, "one")
	one := e.startAgent(e.token("alice"), "", httpSpec(backend.URL, "")).waitOnline(t)[0].Registered
	two := e.startAgent(e.token("bob"), "", httpSpec(backend.URL, "")).waitOnline(t)[0].Registered
	for i := 0; i < 3; i++ {
		e.do("POST", one.Hostname, "/", strings.NewReader("abc"), nil)
	}
	e.do("GET", two.Hostname, "/", nil, nil)
	e.do("GET", "nobody.tunnel.test", "/", nil, nil) // unknown hosts are not counted
	if err := e.shutdown(); err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	got := map[string]usage.Row{}
	for _, r := range st.rows {
		got[r.Hostname] = r
	}
	if r := got[one.Hostname]; r.Requests != 3 || r.BytesIn != 9 || r.BytesOut == 0 || r.UserID == "" {
		t.Errorf("%s: %+v", one.Hostname, r)
	}
	if r := got[two.Hostname]; r.Requests != 1 || r.UserID == got[one.Hostname].UserID {
		t.Errorf("%s: %+v", two.Hostname, r)
	}
	if len(got) != 2 {
		t.Errorf("unexpected hostnames counted: %v", got)
	}
}
