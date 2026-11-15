package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/tinoimammp/mancar/internal/agent"
	"github.com/tinoimammp/mancar/internal/auth"
	"github.com/tinoimammp/mancar/internal/domain"
	"github.com/tinoimammp/mancar/internal/protocol"
)

// fileConfig is the persisted configuration (config.json, mode 0600).
type fileConfig struct {
	Server  string        `json:"server,omitempty"`
	Token   string        `json:"token,omitempty"`
	Tunnels []savedTunnel `json:"tunnels,omitempty"`
}

type savedTunnel struct {
	Name      string `json:"name"`
	Proto     string `json:"proto"`
	Addr      string `json:"addr"`
	Subdomain string `json:"subdomain,omitempty"`
}

func (e Env) configPath() (string, error) {
	if e.ConfigDir == "" {
		return "", errors.New("cannot determine the configuration directory; set MANCAR_CONFIG_DIR")
	}
	return filepath.Join(e.ConfigDir, "config.json"), nil
}

// loadConfig reads the config file. A missing file is an empty config; a
// damaged one is an error (it is never silently overwritten).
func (e Env) loadConfig() (fileConfig, error) {
	var c fileConfig
	path, err := e.configPath()
	if err != nil {
		return c, nil // no place to read from: behave as unconfigured
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, fmt.Errorf("reading %s: %w", path, err)
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return fileConfig{}, fmt.Errorf("%s is not valid JSON (%v); fix or delete it", path, err)
	}
	return c, nil
}

// saveConfig writes the config atomically with owner-only permissions: it
// holds the agent token.
func (e Env) saveConfig(c fileConfig) error {
	path, err := e.configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(b, '\n'), 0o600)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(perm); err != nil && !errors.Is(err, fs.ErrPermission) {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func maskToken(t string) string {
	if t == "" {
		return "(not set)"
	}
	if len(t) <= 8 {
		return "********"
	}
	return t[:6] + "…" + strings.Repeat("*", 6)
}

// ---- resolved settings ------------------------------------------------------

type settings struct {
	server   string // normalised gateway URL
	token    string
	dialAddr string // optional: connect here, keep Host/SNI from server
}

// resolve combines flag, environment and config file (in that order of
// precedence) and validates the result.
func (e Env) resolve(serverFlag string, fc fileConfig) (settings, error) {
	var s settings
	s.server = firstNonEmpty(serverFlag, e.Getenv("MANCAR_SERVER"), fc.Server)
	s.token = firstNonEmpty(e.Getenv("MANCAR_TOKEN"), fc.Token)
	s.dialAddr = strings.TrimSpace(e.Getenv("MANCAR_DIAL_ADDR"))

	if s.server == "" {
		return s, errors.New("no server configured; run: mancar config set server https://tunnel.example.com")
	}
	norm, err := e.checkServerURL(s.server, s.dialAddr)
	if err != nil {
		return s, err
	}
	s.server = norm
	if s.token == "" {
		return s, errors.New("no agent token configured; set MANCAR_TOKEN or run: mancar config set token -  (ask your operator for one)")
	}
	if !auth.WellFormed(s.token) {
		return s, fmt.Errorf("the configured agent token is malformed (expected %q followed by 64 characters)", auth.TokenPrefix)
	}
	return s, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// checkServerURL validates and normalises a gateway URL. Plain http is only
// accepted for loopback hosts (or with MANCAR_ALLOW_INSECURE=1) because
// the agent token travels in the handshake.
func (e Env) checkServerURL(raw, dialAddr string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("server %q must look like https://tunnel.example.com", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("server %q must be a bare origin without credentials, path or query", raw)
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) && !isLoopbackDial(dialAddr) && e.Getenv("MANCAR_ALLOW_INSECURE") != "1" {
		return "", fmt.Errorf("refusing http://%s: the agent token would travel unencrypted; use https://", u.Host)
	}
	return u.Scheme + "://" + strings.ToLower(u.Host), nil
}

func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func isLoopbackDial(addr string) bool {
	if addr == "" {
		return false
	}
	h, _, err := net.SplitHostPort(addr)
	return err == nil && isLoopbackHost(h)
}

// ---- local addresses and tunnel specs --------------------------------------

// parseLocalAddr turns "3000", "host:3000" or "http://host:3000" into a
// host:port dial address.
func parseLocalAddr(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("missing local port or address")
	}
	if n, err := strconv.Atoi(s); err == nil {
		if n < 1 || n > 65535 {
			return "", fmt.Errorf("port %d is out of range (1-65535)", n)
		}
		return "localhost:" + s, nil
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return "", fmt.Errorf("%q is not a valid local address", s)
		}
		host, port := u.Hostname(), u.Port()
		if port == "" {
			switch u.Scheme {
			case "http":
				port = "80"
			case "https":
				port = "443"
			default:
				return "", fmt.Errorf("%q needs an explicit port", s)
			}
		}
		s = net.JoinHostPort(host, port)
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" || strings.ContainsAny(host, " \t/") {
		return "", fmt.Errorf("%q is not a valid local address; use a port (3000) or host:port", s)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("%q has an invalid port", s)
	}
	return net.JoinHostPort(host, port), nil
}

func checkSubdomain(s string) (string, error) {
	label := domain.NormalizeLabel(s)
	if err := domain.ValidateLabel(label); err != nil {
		return "", errors.New(strings.TrimPrefix(err.Error(), "domain: "))
	}
	return label, nil
}

func (t savedTunnel) spec() agent.TunnelSpec {
	return agent.TunnelSpec{Name: t.Name, Proto: t.Proto, LocalAddr: t.Addr, Subdomain: t.Subdomain}
}

var tunnelNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ---- the config command -----------------------------------------------------

func cmdConfig(e Env, args []string) int {
	fs := newFlagSet(e, "config")
	subdomain := fs.String("subdomain", "", "subdomain for an http tunnel (add-tunnel)")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return flagExit(err)
	}
	sub := "show"
	if len(pos) > 0 {
		sub, pos = pos[0], pos[1:]
	}

	if sub == "path" {
		p, err := e.configPath()
		if err != nil {
			return fail(e, 1, "%v", err)
		}
		fmt.Fprintln(e.Stdout, p)
		return 0
	}
	fc, err := e.loadConfig()
	if err != nil {
		return fail(e, 1, "%v", err)
	}

	save := func() int {
		if err := e.saveConfig(fc); err != nil {
			return fail(e, 1, "cannot save the configuration: %v", err)
		}
		return 0
	}

	switch sub {
	case "show":
		path, _ := e.configPath()
		fmt.Fprintf(e.Stdout, "Config file: %s\n", orNone(path))
		fmt.Fprintf(e.Stdout, "Server:      %s\n", orNone(firstNonEmpty(e.Getenv("MANCAR_SERVER"), fc.Server)))
		fmt.Fprintf(e.Stdout, "Token:       %s\n", maskToken(firstNonEmpty(e.Getenv("MANCAR_TOKEN"), fc.Token)))
		if len(fc.Tunnels) == 0 {
			fmt.Fprintln(e.Stdout, "Tunnels:     (none)")
		}
		for i, t := range fc.Tunnels {
			label := "Tunnels:    "
			if i > 0 {
				label = "            "
			}
			extra := ""
			if t.Subdomain != "" {
				extra = " subdomain=" + t.Subdomain
			}
			fmt.Fprintf(e.Stdout, "%s %s: %s %s%s\n", label, t.Name, t.Proto, t.Addr, extra)
		}
		return 0

	case "set":
		if len(pos) < 1 || (pos[0] != "server" && pos[0] != "token") {
			return fail(e, 2, "usage: mancar config set server URL | token TOKEN")
		}
		key := pos[0]
		var val string
		switch {
		case len(pos) == 2 && pos[1] == "-":
			b, err := io.ReadAll(io.LimitReader(e.Stdin, 4096))
			if err != nil {
				return fail(e, 1, "reading stdin: %v", err)
			}
			val = strings.TrimSpace(string(bytes.TrimSpace(b)))
		case len(pos) == 2:
			val = strings.TrimSpace(pos[1])
		default:
			return fail(e, 2, "usage: mancar config set %s VALUE", key)
		}
		if key == "server" {
			norm, err := e.checkServerURL(val, e.Getenv("MANCAR_DIAL_ADDR"))
			if err != nil {
				return fail(e, 2, "%v", err)
			}
			fc.Server = norm
		} else {
			if !auth.WellFormed(val) {
				return fail(e, 2, "that does not look like an agent token (expected %q followed by 64 characters)", auth.TokenPrefix)
			}
			fc.Token = val
		}
		if code := save(); code != 0 {
			return code
		}
		fmt.Fprintf(e.Stdout, "%s saved\n", key)
		return 0

	case "unset":
		if len(pos) != 1 || (pos[0] != "server" && pos[0] != "token") {
			return fail(e, 2, "usage: mancar config unset server|token")
		}
		if pos[0] == "server" {
			fc.Server = ""
		} else {
			fc.Token = ""
		}
		if code := save(); code != 0 {
			return code
		}
		fmt.Fprintf(e.Stdout, "%s removed\n", pos[0])
		return 0

	case "add-tunnel":
		if len(pos) != 3 {
			return fail(e, 2, "usage: mancar config add-tunnel NAME http|tcp ADDR [--subdomain NAME]")
		}
		name, proto := strings.ToLower(pos[0]), strings.ToLower(pos[1])
		if !tunnelNameRE.MatchString(name) {
			return fail(e, 2, "tunnel name %q must be 1-32 characters from a-z, 0-9, '_' and '-'", pos[0])
		}
		if proto != protocol.ProtoHTTP && proto != protocol.ProtoTCP {
			return fail(e, 2, "protocol must be http or tcp (got %q)", pos[1])
		}
		addr, err := parseLocalAddr(pos[2])
		if err != nil {
			return fail(e, 2, "%v", err)
		}
		t := savedTunnel{Name: name, Proto: proto, Addr: addr}
		if *subdomain != "" {
			if proto != protocol.ProtoHTTP {
				return fail(e, 2, "--subdomain only applies to http tunnels")
			}
			if t.Subdomain, err = checkSubdomain(*subdomain); err != nil {
				return fail(e, 2, "%v", err)
			}
		}
		for _, existing := range fc.Tunnels {
			if existing.Name == name {
				return fail(e, 2, "a tunnel named %q already exists; remove it first with: mancar config rm-tunnel %s", name, name)
			}
		}
		fc.Tunnels = append(fc.Tunnels, t)
		if code := save(); code != 0 {
			return code
		}
		fmt.Fprintf(e.Stdout, "tunnel %s saved; start it with: mancar start\n", name)
		return 0

	case "rm-tunnel":
		if len(pos) != 1 {
			return fail(e, 2, "usage: mancar config rm-tunnel NAME")
		}
		name := strings.ToLower(pos[0])
		kept := fc.Tunnels[:0:0]
		for _, t := range fc.Tunnels {
			if t.Name != name {
				kept = append(kept, t)
			}
		}
		if len(kept) == len(fc.Tunnels) {
			return fail(e, 1, "no tunnel named %q", name)
		}
		fc.Tunnels = kept
		if code := save(); code != 0 {
			return code
		}
		fmt.Fprintf(e.Stdout, "tunnel %s removed\n", name)
		return 0
	}
	return fail(e, 2, "unknown config command %q\n\n%s", sub, usageText)
}

func orNone(s string) string {
	if s == "" {
		return "(not set)"
	}
	return s
}
