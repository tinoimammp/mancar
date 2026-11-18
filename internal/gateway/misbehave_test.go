package gateway_test

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/tinoimammp/mancar/internal/auth"
	"github.com/tinoimammp/mancar/internal/domain"
	"github.com/tinoimammp/mancar/internal/gateway"
	"github.com/tinoimammp/mancar/internal/netutil"
	"github.com/tinoimammp/mancar/internal/protocol"
)

// rawAgent connects to the hub without the agent package, so a test can
// misbehave, and returns the yamux session plus the control stream.
func rawAgent(t *testing.T) (*yamux.Session, net.Conn) {
	t.Helper()
	a := auth.NewMemory()
	tok, _ := a.Issue("u1")
	svc := domain.NewService(domain.NewMemoryRegistry(), domain.ServiceOptions{BaseDomain: "example.com"})
	srv := httptest.NewServer(gateway.NewHub(a, svc, gateway.Options{}))
	t.Cleanup(srv.Close)
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	io.WriteString(conn, "GET "+protocol.ConnectPath+" HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: "+
		protocol.UpgradeToken+"\r\nAuthorization: Bearer "+tok+"\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	sess, err := yamux.Client(&netutil.BufferedConn{Conn: conn, R: br}, protocol.YamuxConfig(0))
	if err != nil {
		t.Fatal(err)
	}
	ctrl, err := sess.Open()
	if err != nil {
		t.Fatal(err)
	}
	return sess, ctrl
}

func TestExtraAgentStreamsAreClosed(t *testing.T) {
	sess, ctrl := rawAgent(t)
	protocol.WriteJSONLine(ctrl, protocol.Message{Type: protocol.TypeUnregister, ReqID: "1", Unregister: &protocol.Unregister{TunnelID: "x"}})
	if _, err := protocol.ReadMessage(protocol.NewControlReader(ctrl)); err != nil { // the control stream works
		t.Fatal(err)
	}
	extra, err := sess.Open()
	if err != nil {
		t.Fatal(err)
	}
	extra.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := extra.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("an extra stream should be closed by the gateway, got %v", err)
	}
}

func TestControlFloodDisconnects(t *testing.T) {
	_, ctrl := rawAgent(t)
	br := protocol.NewControlReader(ctrl)
	ctrl.SetDeadline(time.Now().Add(10 * time.Second))
	var last *protocol.Message
	for i := 0; i < 200; i++ {
		if err := protocol.WriteJSONLine(ctrl, protocol.Message{Type: protocol.TypeUnregister, ReqID: "x", Unregister: &protocol.Unregister{TunnelID: "x"}}); err != nil {
			break
		}
		m, err := protocol.ReadMessage(br)
		if err != nil {
			break
		}
		last = m
	}
	if last == nil || last.Error == nil || last.Error.Code != protocol.CodeLimitExceeded {
		t.Fatalf("last answer: %+v", last)
	}
	if _, err := protocol.ReadMessage(br); err == nil {
		t.Error("the session should be closed after the flood")
	}
}
