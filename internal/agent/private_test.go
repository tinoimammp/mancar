package agent_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/yamux"

	"github.com/tinoimammp/mancar/internal/agent"
	"github.com/tinoimammp/mancar/internal/protocol"
)

// oldGateway accepts the agent and registers every tunnel, but (like a
// gateway from before private tunnels) ignores Register.Private.
func oldGateway(t *testing.T, got chan<- protocol.Register) *httptest.Server {
	return gatewayAnswering(t, got, false)
}

// gatewayAnswering is oldGateway that may honour Private (a v0.5.0 gateway:
// private tunnels, but no allow).
func gatewayAnswering(t *testing.T, got chan<- protocol.Register, private bool) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + protocol.UpgradeToken + "\r\n\r\n")
		rw.Flush()
		sess, err := yamux.Server(conn, protocol.YamuxConfig(0))
		if err != nil {
			return
		}
		defer sess.Close()
		ctrl, err := sess.Accept()
		if err != nil {
			return
		}
		br := protocol.NewControlReader(ctrl)
		m, err := protocol.ReadMessage(br)
		if err != nil || m.Register == nil {
			return
		}
		got <- *m.Register
		protocol.WriteJSONLine(ctrl, protocol.Message{Type: protocol.TypeRegistered, ReqID: m.ReqID, Registered: &protocol.Registered{
			TunnelID: "t1", Proto: "http", Hostname: "app.example.com", PublicURL: "https://app.example.com", Private: private && m.Register.Private,
		}})
		sess.AcceptStream() // wait until the agent hangs up
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPrivateTunnelIsNeverServedByAGatewayThatIgnoresIt(t *testing.T) {
	got := make(chan protocol.Register, 4)
	srv := oldGateway(t, got)
	o := baseOpts(srv.URL)
	o.Tunnels = []agent.TunnelSpec{{Proto: protocol.ProtoHTTP, LocalAddr: "127.0.0.1:3000", Private: true}}
	online := false
	o.OnStatus = func(s agent.Status) { online = online || s.State == agent.StateOnline }
	_, errc := start(t, o)
	err := waitErr(t, errc)
	var re *agent.RegistrationError
	if !errors.As(err, &re) || re.Err.Code != protocol.CodeUnsupported {
		t.Fatalf("Run = %v, want an unsupported registration error", err)
	}
	if reg := <-got; !reg.Private {
		t.Error("the agent did not ask for a private tunnel")
	}
	if online {
		t.Error("the agent reported the public tunnel as online")
	}
}

func TestAllowIsNotSilentlyDroppedByAnOlderGateway(t *testing.T) {
	got := make(chan protocol.Register, 4)
	srv := gatewayAnswering(t, got, true)
	o := baseOpts(srv.URL)
	o.Tunnels = []agent.TunnelSpec{{Proto: protocol.ProtoHTTP, LocalAddr: "127.0.0.1:3000", Private: true, Allow: []string{"budi"}}}
	_, errc := start(t, o)
	err := waitErr(t, errc)
	var re *agent.RegistrationError
	if !errors.As(err, &re) || re.Err.Code != protocol.CodeUnsupported {
		t.Fatalf("Run = %v, want an unsupported registration error", err)
	}
	if reg := <-got; len(reg.Allow) != 1 || reg.Allow[0] != "budi" {
		t.Errorf("register = %+v", reg)
	}
}
