package cli

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tinoimammp/mancar/internal/agent"
	"github.com/tinoimammp/mancar/internal/protocol"
)

func TestRequestLogLines(t *testing.T) {
	var out bytes.Buffer
	r := &renderer{out: &out}
	r.onStatus(agent.Status{State: agent.StateOnline, Tunnels: []agent.TunnelStatus{{
		Spec:       agent.TunnelSpec{Proto: protocol.ProtoHTTP, LocalAddr: "127.0.0.1:3000"},
		Registered: protocol.Registered{TunnelID: "t1", Hostname: "api.example.com", PublicURL: "https://api.example.com"},
	}}})
	out.Reset()

	at := time.Date(2026, 1, 2, 14, 2, 11, 0, time.Local)
	http := agent.TunnelSpec{Proto: protocol.ProtoHTTP}
	r.onEvent(http, protocol.Event{TunnelID: "t1", Time: at, Method: "GET", Path: "/api/users", Status: 200, DurationMs: 12})
	r.onEvent(http, protocol.Event{TunnelID: "t1", Time: at, Method: "POST", Path: "/login", Status: 401, DurationMs: 1500})
	r.onEvent(agent.TunnelSpec{Proto: protocol.ProtoTCP}, protocol.Event{TunnelID: "t1", Time: at, Remote: "203.0.113.5:4000", BytesIn: 2048, BytesOut: 10, DurationMs: 61000})

	got := out.String()
	for _, want := range []string{
		"Requests\n--------\n",
		"14:02:11  GET    /api/users",
		"200 OK",
		"12 ms",
		"401 Unauthorized",
		"1.5s",
		"TCP   203.0.113.5:4000",
		"2.0 KB in / 10 B out",
		"1m1s",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Count(got, "Requests\n") != 1 {
		t.Errorf("header printed more than once:\n%s", got)
	}
	if strings.Contains(got, "api.example.com  ") {
		t.Errorf("a single tunnel should not get a hostname prefix:\n%s", got)
	}
}

// syncBuf lets the summary timer goroutine write while the test reads.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func pageLoad(r *renderer) {
	at := time.Date(2026, 1, 2, 14, 2, 11, 0, time.Local)
	sp := agent.TunnelSpec{Proto: protocol.ProtoHTTP}
	ev := func(method, p string, status int, out int64) {
		r.onEvent(sp, protocol.Event{TunnelID: "t1", Time: at, Method: method, Path: p, Status: status, BytesOut: out})
	}
	ev("GET", "/", 200, 100)
	ev("GET", "/assets/app.js", 200, 1024)
	ev("GET", "/assets/app.css", 304, 0)
	ev("GET", "/img/logo.PNG", 200, 1024)
	ev("GET", "/assets/missing.js", 404, 10)
	ev("POST", "/api/login", 401, 20)
}

func TestSmartLogSummarisesStaticFiles(t *testing.T) {
	out := &syncBuf{}
	r := &renderer{out: out, mode: logSmart}
	pageLoad(r)
	got := out.String()
	lines := strings.Split(strings.TrimSpace(got), "\n")
	want := []string{"Requests", "--------", "GET    /                ", "+ 3 static files (2.0 KB)", "/assets/missing.js", "/api/login"}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines, want %d:\n%s", len(lines), len(want), got)
	}
	for i, w := range want {
		if !strings.Contains(lines[i], strings.TrimSpace(w)) {
			t.Errorf("line %d = %q, want it to contain %q", i, lines[i], w)
		}
	}
	if strings.Contains(got, "app.js") || strings.Contains(got, "logo") {
		t.Errorf("successful static files listed individually:\n%s", got)
	}

	// A burst that nothing follows is summarised after a quiet second.
	r.onEvent(agent.TunnelSpec{Proto: protocol.ProtoHTTP}, protocol.Event{TunnelID: "t1", Path: "/font.woff2", Status: 200, BytesOut: 5})
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(out.String(), "+ 1 static file (5 B)") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(out.String(), "+ 1 static file (5 B)") {
		t.Errorf("trailing burst never summarised:\n%s", out.String())
	}
}

func TestAllAndErrorsLogModes(t *testing.T) {
	var all bytes.Buffer
	pageLoad(&renderer{out: &all, mode: logAll})
	for _, p := range []string{"/assets/app.js", "/assets/app.css", "/img/logo.PNG", "/api/login"} {
		if !strings.Contains(all.String(), p) {
			t.Errorf("--log all is missing %s:\n%s", p, all.String())
		}
	}
	if strings.Contains(all.String(), "static file") {
		t.Errorf("--log all summarised:\n%s", all.String())
	}

	var errs bytes.Buffer
	r := &renderer{out: &errs, mode: logErrors}
	pageLoad(r)
	r.onEvent(agent.TunnelSpec{Proto: protocol.ProtoTCP}, protocol.Event{TunnelID: "t1", Remote: "1.2.3.4:5"})
	got := errs.String()
	if !strings.Contains(got, "/assets/missing.js") || !strings.Contains(got, "/api/login") ||
		strings.Contains(got, "GET    /    ") || strings.Contains(got, "static file") || strings.Contains(got, "TCP") {
		t.Errorf("--log errors:\n%s", got)
	}
}

func TestLogModeFlag(t *testing.T) {
	for in, want := range map[string]string{"smart": logSmart, "ALL": logAll, " errors ": logErrors, "off": logOff} {
		if got, err := logMode(in, false); err != nil || got != want {
			t.Errorf("logMode(%q) = %q, %v", in, got, err)
		}
	}
	if got, _ := logMode("all", true); got != logOff {
		t.Errorf("--quiet should win: %q", got)
	}
	if _, err := logMode("verbose", false); err == nil {
		t.Error("unknown mode accepted")
	}
}
