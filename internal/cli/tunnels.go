package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/USERNAME/mancar/internal/agent"
	"github.com/USERNAME/mancar/internal/protocol"
)

// cmdTunnel implements "mancar http ..." and "mancar tcp ...".
func cmdTunnel(ctx context.Context, e Env, proto string, args []string) int {
	fs := newFlagSet(e, proto)
	server := fs.String("server", "", "gateway URL (overrides MANCAR_SERVER and the config file)")
	subdomain := fs.String("subdomain", "", "request this subdomain (http only)")
	random := fs.Bool("random", false, "use a random subdomain (http only)")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return flagExit(err)
	}
	if len(pos) != 1 {
		return fail(e, 2, "usage: mancar %s PORT|HOST:PORT%s", proto, map[bool]string{true: " [--subdomain NAME | --random]"}[proto == protocol.ProtoHTTP])
	}
	if proto == protocol.ProtoTCP && (*subdomain != "" || *random) {
		return fail(e, 2, "--subdomain and --random only apply to http tunnels")
	}
	if *subdomain != "" && *random {
		return fail(e, 2, "--subdomain and --random cannot be combined")
	}
	addr, err := parseLocalAddr(pos[0])
	if err != nil {
		return fail(e, 2, "%v", err)
	}

	label := ""
	if *subdomain != "" {
		if label, err = checkSubdomain(*subdomain); err != nil {
			return fail(e, 2, "invalid subdomain: %v", err)
		}
	}
	var p *prompter
	if e.Interactive {
		p = newPrompter(e)
	}
	if proto == protocol.ProtoHTTP && label == "" && !*random && p != nil {
		var ok bool
		if label, ok = chooseSubdomain(p); !ok {
			return fail(e, 1, "no input; aborting")
		}
	}

	fc, err := e.loadConfig()
	if err != nil {
		return fail(e, 1, "%v", err)
	}
	s, err := e.resolve(*server, fc)
	if err != nil {
		return fail(e, 2, "%v", err)
	}
	spec := agent.TunnelSpec{Proto: proto, LocalAddr: addr, Subdomain: label}
	if label != "" {
		fmt.Fprintln(e.Stdout, "Checking availability...")
	}
	return runTunnels(ctx, e, s, []agent.TunnelSpec{spec}, p)
}

// cmdStart implements "mancar start [NAME...]" for saved tunnels.
func cmdStart(ctx context.Context, e Env, args []string) int {
	fs := newFlagSet(e, "start")
	server := fs.String("server", "", "gateway URL (overrides MANCAR_SERVER and the config file)")
	names, err := parseFlags(fs, args)
	if err != nil {
		return flagExit(err)
	}
	fc, err := e.loadConfig()
	if err != nil {
		return fail(e, 1, "%v", err)
	}
	if len(fc.Tunnels) == 0 {
		return fail(e, 2, "no tunnels saved; add one with: mancar config add-tunnel NAME http 3000")
	}
	var specs []agent.TunnelSpec
	if len(names) == 0 {
		for _, t := range fc.Tunnels {
			specs = append(specs, t.spec())
		}
	} else {
		for _, n := range names {
			found := false
			for _, t := range fc.Tunnels {
				if t.Name == strings.ToLower(n) {
					specs, found = append(specs, t.spec()), true
				}
			}
			if !found {
				return fail(e, 2, "no saved tunnel named %q", n)
			}
		}
	}
	s, err := e.resolve(*server, fc)
	if err != nil {
		return fail(e, 2, "%v", err)
	}
	return runTunnels(ctx, e, s, specs, nil)
}

func chooseSubdomain(p *prompter) (string, bool) {
	fmt.Fprint(p.out, "Select your tunnel domain:\n\n  1) Random subdomain\n  2) Custom subdomain\n\n")
	for {
		ans, ok := p.ask("Choice [1]: ")
		if !ok {
			return "", false
		}
		switch ans {
		case "", "1":
			return "", true
		case "2":
			return askSubdomain(p)
		}
		fmt.Fprintln(p.out, "Please enter 1 or 2.")
	}
}

func askSubdomain(p *prompter) (string, bool) {
	for {
		ans, ok := p.ask("Enter subdomain: ")
		if !ok {
			return "", false
		}
		if ans == "" {
			fmt.Fprintln(p.out, "A subdomain is required.")
			continue
		}
		label, err := checkSubdomain(ans)
		if err != nil {
			fmt.Fprintf(p.out, "%v. Try again.\n", err)
			continue
		}
		fmt.Fprintln(p.out, "Checking availability...")
		return label, true
	}
}

// runTunnels connects, keeps the tunnels up and returns the exit code. When
// prompting is possible, a refused custom subdomain is asked for again.
func runTunnels(ctx context.Context, e Env, s settings, specs []agent.TunnelSpec, p *prompter) int {
	warnUnreachableLocals(e, specs)

	inst := newInstance(e, s.server, specs)
	defer inst.close()
	r := &renderer{out: e.Stdout, server: s.server}

	for {
		a, err := agent.New(agent.Options{
			ServerURL: s.server, DialAddr: s.dialAddr, Token: s.token, Tunnels: specs,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			OnStatus: func(st agent.Status) {
				inst.update(st)
				r.onStatus(st)
			},
		})
		if err != nil {
			return fail(e, 2, "%v", strings.TrimPrefix(err.Error(), "agent: "))
		}
		err = a.Run(ctx)
		if err == nil { // the context was cancelled: Ctrl+C or "mancar stop"
			fmt.Fprintln(e.Stdout, "\nShutting down.")
			return 0
		}

		var rerr *agent.RegistrationError
		if p != nil && len(specs) == 1 && specs[0].Proto == protocol.ProtoHTTP && errors.As(err, &rerr) &&
			(rerr.Err.Code == protocol.CodeHostnameTaken || rerr.Err.Code == protocol.CodeHostnameInvalid) {
			fmt.Fprintf(e.Stderr, "%s\n", describeRegistrationError(rerr))
			label, ok := askSubdomain(p)
			if !ok {
				return 1
			}
			specs[0].Subdomain = label
			r.reset()
			continue
		}
		return reportError(e, err)
	}
}

func describeRegistrationError(r *agent.RegistrationError) string {
	switch r.Err.Code {
	case protocol.CodeHostnameTaken:
		if r.Spec.Subdomain != "" {
			return fmt.Sprintf("%q is not available. Choose another name with --subdomain, or use --random.", r.Spec.Subdomain)
		}
		return "no hostname could be allocated; try again."
	case protocol.CodeHostnameInvalid:
		return "invalid subdomain: " + r.Err.Message
	case protocol.CodeLimitExceeded:
		return "limit reached: " + r.Err.Message
	case protocol.CodeUnsupported:
		return fmt.Sprintf("this gateway does not support %s tunnels: %s", r.Spec.Proto, r.Err.Message)
	}
	return r.Err.Message
}

func reportError(e Env, err error) int {
	var rerr *agent.RegistrationError
	switch {
	case errors.Is(err, agent.ErrUnauthorized):
		return fail(e, 1, "the gateway rejected the agent token; check it with: mancar config")
	case errors.As(err, &rerr):
		return fail(e, 1, "%s", describeRegistrationError(rerr))
	}
	return fail(e, 1, "%v", err)
}

// warnUnreachableLocals tells the user early when nothing listens on the
// local address; the tunnel still starts because the service may be started
// afterwards.
func warnUnreachableLocals(e Env, specs []agent.TunnelSpec) {
	for _, sp := range specs {
		c, err := net.DialTimeout("tcp", sp.LocalAddr, time.Second)
		if err != nil {
			fmt.Fprintf(e.Stderr, "warning: nothing is listening on %s yet; requests will fail until it starts\n", sp.LocalAddr)
			continue
		}
		c.Close()
	}
}

// ---- output -----------------------------------------------------------------

// renderer prints status changes.
type renderer struct {
	mu            sync.Mutex
	out           io.Writer
	server        string
	connecting    bool
	announced     []string
	lastReconnect string
}

func (r *renderer) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connecting, r.announced, r.lastReconnect = false, nil, ""
}

func (r *renderer) onStatus(s agent.Status) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch s.State {
	case agent.StateConnecting:
		if !r.connecting {
			r.connecting = true
			fmt.Fprintf(r.out, "Connecting to %s ...\n", r.server)
		}
	case agent.StateReconnecting:
		line := "Status: RECONNECTING"
		if s.Err != nil {
			line += " (" + oneLine(s.Err.Error()) + ")"
		}
		if line != r.lastReconnect {
			r.lastReconnect = line
			fmt.Fprintln(r.out, line)
		}
	case agent.StateOnline:
		urls := make([]string, len(s.Tunnels))
		for i, t := range s.Tunnels {
			urls[i] = t.Registered.PublicURL
		}
		first := r.announced == nil
		r.lastReconnect = ""
		if !first && equalStrings(urls, r.announced) {
			fmt.Fprintln(r.out, "Status: ONLINE (reconnected)")
			return
		}
		r.announced = urls
		printOnline(r.out, s.Tunnels, first)
	}
}

func printOnline(w io.Writer, ts []agent.TunnelStatus, first bool) {
	multi := len(ts) > 1
	if first {
		for _, t := range ts {
			if t.Spec.Proto == protocol.ProtoHTTP && t.Spec.Subdomain != "" && t.Registered.Hostname != "" {
				fmt.Fprintf(w, "SUCCESS: %s is available.\n\n", t.Registered.Hostname)
			}
		}
	}
	if multi {
		fmt.Fprint(w, "Tunnels established.\n\nForwarding:\n")
	} else {
		fmt.Fprint(w, "Tunnel established.\n\nForwarding:\n")
	}
	for _, t := range ts {
		fmt.Fprintf(w, "%s\n    -> %s://%s\n", t.Registered.PublicURL, t.Spec.Proto, t.Spec.LocalAddr)
		if multi {
			fmt.Fprintf(w, "    Protocol: %s   TLS: %s\n", strings.ToUpper(t.Spec.Proto), tlsLabel(t))
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "Status: ONLINE")
	if !multi {
		fmt.Fprintf(w, "Protocol: %s\nTLS: %s\n", strings.ToUpper(ts[0].Spec.Proto), tlsLabel(ts[0]))
	}
	fmt.Fprint(w, "\nPress Ctrl+C to stop.\n")
}

func tlsLabel(t agent.TunnelStatus) string {
	if strings.HasPrefix(t.Registered.PublicURL, "https://") {
		return "ENABLED"
	}
	return "DISABLED"
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 160 {
		s = s[:157] + "..."
	}
	return s
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
