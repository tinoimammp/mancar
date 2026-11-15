package cli

import (
	"bytes"
	"strings"
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
