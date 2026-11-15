package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tinoimammp/mancar/internal/agent"
	"github.com/tinoimammp/mancar/internal/protocol"
)

// cmdTunnel implements "mancar http ..." and "mancar tcp ...".
func cmdTunnel(ctx context.Context, e Env, proto string, args []string) int {
	fs := newFlagSet(e, proto)
	server := fs.String("server", "", "gateway URL (overrides MANCAR_SERVER and the config file)")
	subdomain := fs.String("subdomain", "", "request this subdomain (http only)")
	random := fs.Bool("random", false, "use a random subdomain (http only)")
	last := fs.Bool("last", false, "reuse the subdomain used most recently with this server (http only)")
	quiet := fs.Bool("quiet", false, "do not print the request log")
	logFlag := fs.String("log", logSmart, "request log: smart (summarise static files), all, errors")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return flagExit(err)
	}
	mode, err := logMode(*logFlag, *quiet)
	if err != nil {
		return fail(e, 2, "%v", err)
	}
	if len(pos) != 1 {
		return fail(e, 2, "usage: mancar %s PORT|HOST:PORT%s", proto, map[bool]string{true: " [--subdomain NAME | --random]"}[proto == protocol.ProtoHTTP])
	}
	if proto == protocol.ProtoTCP && (*subdomain != "" || *random || *last) {
		return fail(e, 2, "--subdomain, --random and --last only apply to http tunnels")
	}
	if n := btoi(*subdomain != "") + btoi(*random) + btoi(*last); n > 1 {
		return fail(e, 2, "--subdomain, --random and --last cannot be combined")
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
	fc, err := e.loadConfig()
	if err != nil {
		return fail(e, 1, "%v", err)
	}
	s, err := e.resolve(*server, fc)
	if err != nil {
		return fail(e, 2, "%v", err)
	}

	recent := e.recentSubdomains(s.server)
	if *last {
		if len(recent) == 0 {
			return fail(e, 2, "no subdomain has been used with %s yet; use --subdomain NAME or --random", s.server)
		}
		label = recent[0].Label
	}
	var p *prompter
	if e.Interactive {
		p = newPrompter(e)
	}
	if proto == protocol.ProtoHTTP && label == "" && !*random && p != nil {
		var ok bool
		if label, ok = chooseSubdomain(p, recent, e.Now()); !ok {
			return fail(e, 1, "no input; aborting")
		}
	}
	spec := agent.TunnelSpec{Proto: proto, LocalAddr: addr, Subdomain: label}
	if label != "" {
		fmt.Fprintln(e.Stdout, "Checking availability...")
	}
	return runTunnels(ctx, e, s, []agent.TunnelSpec{spec}, p, mode)
}

// cmdStart implements "mancar start [NAME...]" for saved tunnels.
func cmdStart(ctx context.Context, e Env, args []string) int {
	fs := newFlagSet(e, "start")
	server := fs.String("server", "", "gateway URL (overrides MANCAR_SERVER and the config file)")
	quiet := fs.Bool("quiet", false, "do not print the request log")
	logFlag := fs.String("log", logSmart, "request log: smart (summarise static files), all, errors")
	names, err := parseFlags(fs, args)
	if err != nil {
		return flagExit(err)
	}
	mode, err := logMode(*logFlag, *quiet)
	if err != nil {
		return fail(e, 2, "%v", err)
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
	return runTunnels(ctx, e, s, specs, nil, mode)
}

// chooseSubdomain asks for random, custom or one of the recently used
// subdomains (most recent first).
func chooseSubdomain(p *prompter, recent []recentSubdomain, now time.Time) (string, bool) {
	if len(recent) > recentShown {
		recent = recent[:recentShown]
	}
	fmt.Fprint(p.out, "Select your tunnel domain:\n\n  1) Random subdomain\n  2) Custom subdomain\n")
	if len(recent) > 0 {
		fmt.Fprintln(p.out, "\n  Recently used:")
	}
	for i, r := range recent {
		note := "used " + agoText(now, r.UsedAt)
		if r.Random {
			note = "random, " + note
		}
		fmt.Fprintf(p.out, "  %d) %-24s (%s)\n", i+3, r.Label, note)
	}
	fmt.Fprintln(p.out)
	max := 2 + len(recent)
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
		if n, err := strconv.Atoi(ans); err == nil && n >= 3 && n <= max {
			fmt.Fprintln(p.out, "Checking availability...")
			return recent[n-3].Label, true
		}
		if max == 2 {
			fmt.Fprintln(p.out, "Please enter 1 or 2.")
		} else {
			fmt.Fprintf(p.out, "Please enter a number from 1 to %d.\n", max)
		}
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
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
func runTunnels(ctx context.Context, e Env, s settings, specs []agent.TunnelSpec, p *prompter, mode string) int {
	warnUnreachableLocals(e, specs)
	// Main already showed a cached notice; only announce what is newer.
	go e.watchUpdates(ctx, e.cachedUpdate().Latest)

	inst := newInstance(e, s.server, specs)
	defer inst.close()
	r := &renderer{out: e.Stdout, server: s.server, mode: mode}

	for {
		opts := agent.Options{
			ServerURL: s.server, DialAddr: s.dialAddr, Token: s.token, Tunnels: specs,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			OnStatus: func(st agent.Status) {
				inst.update(st)
				r.onStatus(st)
				if st.State == agent.StateOnline {
					e.rememberTunnels(s.server, st.Tunnels)
				}
			},
		}
		if mode != logOff {
			opts.OnEvent = r.onEvent
		}
		a, err := agent.New(opts)
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
	// request log
	mode      string            // logSmart, logAll or logErrors
	labels    map[string]string // tunnel ID -> hostname or :port (several tunnels)
	logHeader bool
	// smart mode: successful static-file requests waiting to be summarised
	pendingFiles int
	pendingBytes int64
	flushTimer   *time.Timer
}

// Request log modes.
const (
	logSmart  = "smart"
	logAll    = "all"
	logErrors = "errors"
	logOff    = "off"
)

func logMode(flagValue string, quiet bool) (string, error) {
	if quiet {
		return logOff, nil
	}
	switch m := strings.ToLower(strings.TrimSpace(flagValue)); m {
	case logSmart, logAll, logErrors, logOff:
		return m, nil
	}
	return "", fmt.Errorf("--log must be smart, all, errors or off (got %q)", flagValue)
}

// summaryDelay is how long a burst of static files may stay quiet before its
// summary line is printed.
const summaryDelay = time.Second

var staticExt = map[string]bool{
	".js": true, ".mjs": true, ".css": true, ".map": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".webp": true, ".avif": true, ".ico": true, ".bmp": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".mp3": true, ".mp4": true, ".webm": true, ".ogg": true, ".wav": true,
}

// isStaticSuccess reports a successfully served static file: the requests a
// page load makes by the dozen and that smart mode summarises.
func isStaticSuccess(ev protocol.Event) bool {
	ok := (ev.Status >= 200 && ev.Status < 300) || ev.Status == http.StatusNotModified
	return ok && staticExt[strings.ToLower(path.Ext(ev.Path))]
}

func (r *renderer) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connecting, r.announced, r.lastReconnect = false, nil, ""
}

// onEvent prints one line of the request log, or in smart mode counts a
// static file towards the next summary line.
func (r *renderer) onEvent(spec agent.TunnelSpec, ev protocol.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	isTCP := spec.Proto == protocol.ProtoTCP
	switch r.mode {
	case logErrors:
		if isTCP || ev.Status < 400 {
			return
		}
	case logAll, logOff:
	default: // smart
		if !isTCP && isStaticSuccess(ev) {
			r.header()
			r.pendingFiles++
			r.pendingBytes += ev.BytesOut
			if r.flushTimer != nil {
				r.flushTimer.Stop()
			}
			r.flushTimer = time.AfterFunc(summaryDelay, func() {
				r.mu.Lock()
				defer r.mu.Unlock()
				r.flushSummary()
			})
			return
		}
	}
	r.header()
	r.flushSummary() // keep lines in order: the burst came first
	ts := ev.Time.Local().Format("15:04:05")
	prefix := ""
	if l := r.labels[ev.TunnelID]; l != "" && len(r.labels) > 1 {
		prefix = l + "  "
	}
	if spec.Proto == protocol.ProtoTCP {
		fmt.Fprintf(r.out, "%s  %sTCP   %-21s  %s in / %s out  %s\n", ts, prefix, ev.Remote,
			humanBytes(ev.BytesIn), humanBytes(ev.BytesOut), humanDuration(ev.DurationMs))
		return
	}
	status := strconv.Itoa(ev.Status)
	if txt := http.StatusText(ev.Status); txt != "" {
		status += " " + txt
	}
	fmt.Fprintf(r.out, "%s  %s%-6s %-40s %-24s %s\n", ts, prefix, ev.Method, clip(ev.Path, 40), status, humanDuration(ev.DurationMs))
}

func (r *renderer) header() {
	if !r.logHeader {
		r.logHeader = true
		fmt.Fprint(r.out, "\nRequests\n--------\n")
	}
}

// flushSummary prints the pending static-file summary. Caller holds r.mu.
func (r *renderer) flushSummary() {
	if r.pendingFiles == 0 {
		return
	}
	noun := "files"
	if r.pendingFiles == 1 {
		noun = "file"
	}
	fmt.Fprintf(r.out, "          + %d static %s (%s)\n", r.pendingFiles, noun, humanBytes(r.pendingBytes))
	r.pendingFiles, r.pendingBytes = 0, 0
	if r.flushTimer != nil {
		r.flushTimer.Stop()
		r.flushTimer = nil
	}
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func humanBytes(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1<<20:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	}
}

func humanDuration(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%d ms", ms)
	}
	return (time.Duration(ms) * time.Millisecond).Round(100 * time.Millisecond).String()
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
		r.labels = map[string]string{}
		for _, t := range s.Tunnels {
			l := t.Registered.Hostname
			if l == "" {
				l = ":" + strconv.Itoa(t.Registered.Port)
			}
			r.labels[t.Registered.TunnelID] = l
		}
		r.logHeader = false
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
