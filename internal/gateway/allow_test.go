package gateway_test

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/tinoimammp/mancar/internal/agent"
	"github.com/tinoimammp/mancar/internal/auth"
	"github.com/tinoimammp/mancar/internal/domain"
	"github.com/tinoimammp/mancar/internal/gateway"
	"github.com/tinoimammp/mancar/internal/protocol"
)

// accounts resolves --allow like the server does: by username.
func accounts(_ context.Context, logins []string) (map[string]string, error) {
	known := map[string]string{"budi": "id-budi", "ana": "id-ana", "owner": "id-owner"}
	out := map[string]string{}
	for _, l := range logins {
		id, ok := known[l]
		if !ok {
			return nil, fmt.Errorf("%w: %s", gateway.ErrUnknownUser, l)
		}
		out[id] = l
	}
	return out, nil
}

// runAgent starts an agent with spec and returns what it registered, or
// the error it stopped with.
func runAgent(t *testing.T, spec agent.TunnelSpec) (*gateway.Hub, []agent.TunnelStatus, error) {
	t.Helper()
	a := auth.NewMemory()
	tok, _ := a.Issue("id-owner")
	svc := domain.NewService(domain.NewMemoryRegistry(), domain.ServiceOptions{BaseDomain: "example.com"})
	hub := gateway.NewHub(a, svc, gateway.Options{PrivateTunnels: true, ResolveLogins: accounts})
	srv := httptest.NewServer(hub)
	t.Cleanup(srv.Close)
	online := make(chan []agent.TunnelStatus, 1)
	ag, err := agent.New(agent.Options{ServerURL: srv.URL, Token: tok, Tunnels: []agent.TunnelSpec{spec},
		MinBackoff: 5 * time.Millisecond, MaxBackoff: 20 * time.Millisecond,
		OnStatus: func(s agent.Status) {
			if s.State == agent.StateOnline {
				select {
				case online <- s.Tunnels:
				default:
				}
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- ag.Run(ctx) }()
	select {
	case ts := <-online:
		return hub, ts, nil
	case err := <-done:
		return hub, nil, err
	case <-time.After(5 * time.Second):
		t.Fatal("agent neither came online nor stopped")
		return nil, nil, nil
	}
}

func TestPrivateTunnelSharedWithAccounts(t *testing.T) {
	hub, ts, err := runAgent(t, agent.TunnelSpec{Proto: protocol.ProtoHTTP, LocalAddr: "127.0.0.1:1",
		Private: true, Allow: []string{"budi", "ana", "owner"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := ts[0].Registered; !got.Private || !slices.Equal(got.Allow, []string{"ana", "budi", "owner"}) {
		t.Errorf("registered: %+v", got)
	}
	tun := hub.LookupHost(ts[0].Registered.Hostname)
	if !tun.MayOpen("id-owner") || !tun.MayOpen("id-budi") || tun.MayOpen("id-eve") || tun.MayOpen("") {
		t.Errorf("MayOpen: %+v", tun.Allow)
	}
	info := hub.Sessions()[0].Tunnels[0] // the owner is not listed as "shared with"
	if !slices.Equal(info.SharedWith, []string{"ana", "budi"}) || len(info.AllowIDs) != 2 {
		t.Errorf("shared with %v / %v", info.SharedWith, info.AllowIDs)
	}
}

func TestAllowWithAnUnknownAccountIsRefused(t *testing.T) {
	_, _, err := runAgent(t, agent.TunnelSpec{Proto: protocol.ProtoHTTP, LocalAddr: "127.0.0.1:1",
		Private: true, Allow: []string{"budi", "ghost"}})
	var re *agent.RegistrationError
	if !errors.As(err, &re) || re.Err.Code != protocol.CodeBadRequest || re.Err.Message != "no account: ghost" {
		t.Fatalf("err = %v", err)
	}
}
