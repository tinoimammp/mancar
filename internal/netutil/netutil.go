// Package netutil contains small networking helpers shared by the gateway
// and the agent.
package netutil

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
)

// Pipe copies data in both directions until both sides are done, then closes
// both connections. A clean EOF in one direction is propagated as a
// half-close so request/response protocols finish properly; any error tears
// both connections down immediately. io.Copy uses a fixed 32 KiB buffer, and
// together with yamux flow control this gives end-to-end backpressure
// without unbounded buffering.
func Pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	var once sync.Once
	closeBoth := func() { once.Do(func() { a.Close(); b.Close() }) }
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		if _, err := io.Copy(dst, src); err != nil {
			closeBoth()
			return
		}
		closeWrite(dst)
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	closeBoth()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	// yamux streams: Close() is a half-close of the sending side.
	_ = c.Close()
}

// BufferedConn is a net.Conn whose reads first drain a bufio.Reader (bytes
// that were buffered while parsing an HTTP handshake).
type BufferedConn struct {
	net.Conn
	R *bufio.Reader
}

func (c *BufferedConn) Read(p []byte) (int, error) { return c.R.Read(p) }

// ParsePrefixes parses a comma separated CIDR list.
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// InPrefixes reports whether the textual address ip lies inside any of the
// prefixes. Unparseable input is never inside.
func InPrefixes(prefixes []netip.Prefix, ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && contains(prefixes, a)
}

func contains(prefixes []netip.Prefix, ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientInfo is what the gateway believes about the public client.
type ClientInfo struct {
	IP    string
	Proto string // "http" or "https"
}

// ClientFromRequest determines the real client address. X-Forwarded-* headers
// are only honoured when the direct peer is a trusted proxy (the bundled
// edge); otherwise they are ignored so clients cannot spoof their address.
func ClientFromRequest(r *http.Request, trusted []netip.Prefix) ClientInfo {
	info := ClientInfo{Proto: "http"}
	if r.TLS != nil {
		info.Proto = "https"
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	info.IP = host
	peer, err := netip.ParseAddr(host)
	if err != nil || !contains(trusted, peer) {
		return info
	}
	// Walk X-Forwarded-For from the right, skipping trusted hops.
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		for _, h := range strings.Split(v, ",") {
			if h = strings.TrimSpace(h); h != "" {
				hops = append(hops, h)
			}
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		ip, err := netip.ParseAddr(hops[i])
		if err != nil {
			break
		}
		info.IP = ip.Unmap().String()
		if !contains(trusted, ip) {
			break
		}
	}
	if p := strings.ToLower(r.Header.Get("X-Forwarded-Proto")); p == "http" || p == "https" {
		info.Proto = p
	}
	return info
}

// NormalizeHost lower-cases a Host header value and strips port and
// trailing dot.
func NormalizeHost(hostport string) string {
	h := hostport
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		h = host
	}
	return strings.TrimSuffix(strings.ToLower(h), ".")
}
