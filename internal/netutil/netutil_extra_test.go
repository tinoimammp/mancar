package netutil

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestParsePrefixes(t *testing.T) {
	t.Run("empty inputs yield nothing", func(t *testing.T) {
		for _, in := range []string{"", "   ", " , ,, "} {
			got, err := ParsePrefixes(in)
			if err != nil || len(got) != 0 {
				t.Errorf("ParsePrefixes(%q) = %v, %v; want empty, nil", in, got, err)
			}
		}
	})
	t.Run("valid lists", func(t *testing.T) {
		got, err := ParsePrefixes("10.0.0.0/8, 192.168.0.0/16 ,::1/128")
		if err != nil || len(got) != 3 {
			t.Fatalf("got %v, %v", got, err)
		}
		if got[0].String() != "10.0.0.0/8" || got[2].String() != "::1/128" {
			t.Errorf("unexpected prefixes: %v", got)
		}
	})
	t.Run("invalid entries are errors", func(t *testing.T) {
		for _, in := range []string{"10.0.0.1", "10.0.0.0/33", "garbage", "10.0.0.0/8,bad", "10.0.0.0/8;192.168.0.0/16"} {
			if _, err := ParsePrefixes(in); err == nil {
				t.Errorf("ParsePrefixes(%q) should fail", in)
			}
		}
	})
}

func newReq(remote string) *http.Request {
	r, _ := http.NewRequest("GET", "http://x/", nil)
	r.RemoteAddr = remote
	return r
}

func TestClientFromRequest_Edges(t *testing.T) {
	trusted, _ := ParsePrefixes("10.0.0.0/8, 127.0.0.0/8")

	t.Run("remote address without a port", func(t *testing.T) {
		r := newReq("10.0.0.2")
		r.Header.Set("X-Forwarded-For", "198.51.100.7")
		if got := ClientFromRequest(r, trusted); got.IP != "198.51.100.7" {
			t.Errorf("IP = %q", got.IP)
		}
	})
	t.Run("ipv4-mapped ipv6 peer is matched against ipv4 prefixes", func(t *testing.T) {
		r := newReq("[::ffff:10.0.0.2]:555")
		r.Header.Set("X-Forwarded-For", "198.51.100.7")
		if got := ClientFromRequest(r, trusted); got.IP != "198.51.100.7" {
			t.Errorf("IP = %q, trusted peer was not recognised", got.IP)
		}
	})
	t.Run("ipv4-mapped hop is reported as plain ipv4", func(t *testing.T) {
		r := newReq("10.0.0.2:555")
		r.Header.Set("X-Forwarded-For", "::ffff:198.51.100.7")
		if got := ClientFromRequest(r, trusted); got.IP != "198.51.100.7" {
			t.Errorf("IP = %q", got.IP)
		}
	})
	t.Run("ipv6 client address", func(t *testing.T) {
		r := newReq("[2001:db8::1]:555")
		if got := ClientFromRequest(r, trusted); got.IP != "2001:db8::1" {
			t.Errorf("IP = %q", got.IP)
		}
	})
	t.Run("garbage forwarded address is ignored", func(t *testing.T) {
		r := newReq("10.0.0.2:555")
		r.Header.Set("X-Forwarded-For", "not-an-ip")
		if got := ClientFromRequest(r, trusted); got.IP != "10.0.0.2" {
			t.Errorf("IP = %q, want the peer address", got.IP)
		}
	})
	t.Run("unparseable right-most hop falls back to the peer", func(t *testing.T) {
		r := newReq("10.0.0.2:555")
		r.Header.Set("X-Forwarded-For", "198.51.100.7, garbage")
		if got := ClientFromRequest(r, trusted); got.IP != "10.0.0.2" {
			t.Errorf("IP = %q", got.IP)
		}
	})
	t.Run("multiple header lines are combined, right-most wins", func(t *testing.T) {
		r := newReq("10.0.0.2:555")
		r.Header.Add("X-Forwarded-For", "6.6.6.6")
		r.Header.Add("X-Forwarded-For", "198.51.100.7")
		if got := ClientFromRequest(r, trusted); got.IP != "198.51.100.7" {
			t.Errorf("IP = %q", got.IP)
		}
	})
	t.Run("all hops trusted resolves to the left-most", func(t *testing.T) {
		r := newReq("10.0.0.2:555")
		r.Header.Set("X-Forwarded-For", "10.0.0.5, 10.0.0.9")
		if got := ClientFromRequest(r, trusted); got.IP != "10.0.0.5" {
			t.Errorf("IP = %q", got.IP)
		}
	})
	t.Run("no trusted proxies configured ignores every header", func(t *testing.T) {
		r := newReq("10.0.0.2:555")
		r.Header.Set("X-Forwarded-For", "198.51.100.7")
		r.Header.Set("X-Forwarded-Proto", "https")
		got := ClientFromRequest(r, nil)
		if got.IP != "10.0.0.2" || got.Proto != "http" {
			t.Errorf("got %+v", got)
		}
	})
}

func TestClientFromRequest_Proto(t *testing.T) {
	trusted, _ := ParsePrefixes("10.0.0.0/8")

	t.Run("direct TLS connection is https", func(t *testing.T) {
		r := newReq("203.0.113.9:555")
		r.TLS = &tls.ConnectionState{}
		if got := ClientFromRequest(r, trusted); got.Proto != "https" {
			t.Errorf("Proto = %q", got.Proto)
		}
	})
	t.Run("untrusted peer cannot downgrade a TLS connection", func(t *testing.T) {
		r := newReq("203.0.113.9:555")
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("X-Forwarded-Proto", "http")
		if got := ClientFromRequest(r, trusted); got.Proto != "https" {
			t.Errorf("Proto = %q", got.Proto)
		}
	})
	t.Run("trusted proxy value is case-insensitive", func(t *testing.T) {
		r := newReq("10.0.0.2:555")
		r.Header.Set("X-Forwarded-Proto", "HTTPS")
		if got := ClientFromRequest(r, trusted); got.Proto != "https" {
			t.Errorf("Proto = %q", got.Proto)
		}
	})
	t.Run("unknown protocol values are ignored", func(t *testing.T) {
		r := newReq("10.0.0.2:555")
		r.Header.Set("X-Forwarded-Proto", "ftp")
		if got := ClientFromRequest(r, trusted); got.Proto != "http" {
			t.Errorf("Proto = %q", got.Proto)
		}
	})
}

func TestNormalizeHost_Edges(t *testing.T) {
	for in, want := range map[string]string{
		"":                  "",
		"EXAMPLE.com.":      "example.com",
		"1.2.3.4:80":        "1.2.3.4",
		"[2001:DB8::1]:443": "2001:db8::1",
		"host:":             "host",
		"A.B.C":             "a.b.c",
	} {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBufferedConn_ReadsBufferedBytesFirst(t *testing.T) {
	br := bufio.NewReader(io.MultiReader(strings.NewReader("buffered-"), strings.NewReader("rest")))
	c := &BufferedConn{R: br}
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "buffered-rest" {
		t.Errorf("read %q, %v", got, err)
	}
}

// tcpPair returns both ends of a loopback TCP connection.
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		ch <- result{c, err}
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		client.Close()
		t.Fatal(r.err)
	}
	t.Cleanup(func() { client.Close(); r.c.Close() })
	return client, r.c
}

func waitDone(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestPipe_HalfClosePreservesReverseDirection(t *testing.T) {
	c1, s1 := tcpPair(t)
	c2, s2 := tcpPair(t)
	deadline := time.Now().Add(5 * time.Second)
	c1.SetDeadline(deadline)
	c2.SetDeadline(deadline)

	done := make(chan struct{})
	go func() { Pipe(s1, s2); close(done) }()

	// Request goes c1 -> c2, then c1 signals end-of-request.
	if _, err := c1.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := c1.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c2)
	if err != nil || string(got) != "request" {
		t.Fatalf("c2 received %q, %v", got, err)
	}

	// The response must still flow back after the half-close.
	if _, err := c2.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	c2.Close()
	got, err = io.ReadAll(c1)
	if err != nil || string(got) != "response" {
		t.Fatalf("c1 received %q, %v", got, err)
	}
	waitDone(t, done, "Pipe to return")
}

func TestPipe_LargeTransferIsIntact(t *testing.T) {
	c1, s1 := tcpPair(t)
	c2, s2 := tcpPair(t)
	deadline := time.Now().Add(10 * time.Second)
	c1.SetDeadline(deadline)
	c2.SetDeadline(deadline)

	done := make(chan struct{})
	go func() { Pipe(s1, s2); close(done) }()

	payload := make([]byte, 1<<20)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	go func() {
		c1.Write(payload)
		c1.(*net.TCPConn).CloseWrite()
	}()
	got, err := io.ReadAll(c2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload corrupted: got %d bytes, want %d", len(got), len(payload))
	}
	c2.Close()
	waitDone(t, done, "Pipe to return")
}

func TestPipe_ErrorTearsDownBothSides(t *testing.T) {
	c1, s1 := tcpPair(t)
	c2, s2 := tcpPair(t)
	c2.SetDeadline(time.Now().Add(5 * time.Second))

	done := make(chan struct{})
	go func() { Pipe(s1, s2); close(done) }()

	// A reset (not a clean FIN) must close the other side immediately.
	c1.(*net.TCPConn).SetLinger(0)
	c1.Close()

	buf := make([]byte, 1)
	if _, err := c2.Read(buf); err == nil {
		t.Error("c2 should observe the teardown (EOF or error)")
	}
	waitDone(t, done, "Pipe to return")
}

func TestInPrefixes(t *testing.T) {
	ps, _ := ParsePrefixes("10.0.0.0/8, 192.168.0.0/16, ::1/128, fc00::/7")
	for _, in := range []string{"10.1.2.3", "192.168.5.5", "::1", "fd12::1", "::ffff:10.1.2.3"} {
		if !InPrefixes(ps, in) {
			t.Errorf("%s should be inside", in)
		}
	}
	for _, out := range []string{"198.51.100.7", "11.0.0.1", "2001:db8::1", "", "garbage", "10.1.2", "10.1.2.3/8"} {
		if InPrefixes(ps, out) {
			t.Errorf("%q should not be inside", out)
		}
	}
	if InPrefixes(nil, "10.1.2.3") {
		t.Error("nothing is inside an empty list")
	}
}
