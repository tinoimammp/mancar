// Package cli implements the mancar command: the agent that exposes local
// services through a mancard gateway.
//
// Everything lives here, not in cmd/, so it can be tested end to end;
// cmd/mancar is a few lines that call Main.
//
// Exit codes: 0 success, 1 runtime failure, 2 usage or configuration error.
package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Env is everything the commands need from the outside world. Tests replace
// the process-related hooks so nothing ever signals the test process.
type Env struct {
	Getenv         func(string) string
	Stdin          io.Reader
	Stdout, Stderr io.Writer

	ConfigDir string // holds config.json
	StateDir  string // holds one agent-<pid>.json per running agent

	// Interactive reports whether Stdin is a terminal; prompts are only
	// shown then.
	Interactive bool

	PID       func() int
	PidAlive  func(pid int) bool
	Terminate func(pid int) error
	Now       func() time.Time
	// HeartbeatEvery is how often a running agent refreshes its state file.
	HeartbeatEvery time.Duration

	// Self-update ("mancar update"). An empty ReleasesURL disables update
	// checks entirely (tests never reach the network).
	ReleasesURL string
	HTTPClient  *http.Client
	Executable  func() (string, error) // path of the running binary
	GOOS        string                 // default runtime.GOOS
	GOARCH      string                 // default runtime.GOARCH

	// "mancar login": OpenBrowser opens the approval page (nil: print only);
	// LoginPoll overrides the server's polling interval (tests).
	OpenBrowser func(url string) error
	LoginPoll   time.Duration
}

// OSEnv returns an Env backed by the real process.
func OSEnv() Env {
	e := Env{Getenv: os.Getenv, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
	if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		e.Interactive = true
	}
	if d := os.Getenv("MANCAR_CONFIG_DIR"); d != "" {
		e.ConfigDir = d
	} else if d, err := os.UserConfigDir(); err == nil {
		e.ConfigDir = filepath.Join(d, "mancar")
	}
	e.OpenBrowser = openBrowser
	e.ReleasesURL = DefaultReleasesURL
	if u := os.Getenv("MANCAR_RELEASES_URL"); u != "" {
		e.ReleasesURL = u
	}
	if d := os.Getenv("MANCAR_STATE_DIR"); d != "" {
		e.StateDir = d
	} else if d, err := os.UserCacheDir(); err == nil {
		e.StateDir = filepath.Join(d, "mancar")
	}
	return e
}

func (e Env) withDefaults() Env {
	if e.Getenv == nil {
		e.Getenv = func(string) string { return "" }
	}
	if e.Stdin == nil {
		e.Stdin = strings.NewReader("")
	}
	if e.Stdout == nil {
		e.Stdout = io.Discard
	}
	if e.Stderr == nil {
		e.Stderr = io.Discard
	}
	if e.PID == nil {
		e.PID = os.Getpid
	}
	if e.PidAlive == nil {
		e.PidAlive = defaultPidAlive
	}
	if e.Terminate == nil {
		e.Terminate = defaultTerminate
	}
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.HeartbeatEvery <= 0 {
		e.HeartbeatEvery = 5 * time.Second
	}
	return e
}

const usageText = `mancar - expose local services through your own tunnel gateway

Usage:
  mancar login [SERVER] [--name NAME]  sign this computer in from the dashboard (saves a token)
  mancar http PORT|HOST:PORT [--subdomain NAME | --random | --last]
  mancar tcp  PORT|HOST:PORT
  mancar start [NAME...]            start the tunnels saved with "config add-tunnel"
  mancar status                     list running tunnels
  mancar stop [PID]                 stop running tunnels
  mancar config                     show the configuration
  mancar config set server URL      for example https://tunnel.example.com
  mancar config set token TOKEN     or "-" to read the token from stdin
  mancar config unset server|token
  mancar config add-tunnel NAME http|tcp ADDR [--subdomain NAME]
  mancar config rm-tunnel NAME
  mancar config path
  mancar update [--check]           install the latest release (verified with SHA256SUMS)
  mancar version

Tunnels print a request log. By default successful static files (.js, .css,
images, fonts) are summarised in one line per burst; --log all shows every
request, --log errors only 4xx/5xx, --quiet nothing.

Environment:
  MANCAR_SERVER            gateway URL (overrides the config file; --server overrides both)
  MANCAR_TOKEN             agent token (overrides the config file)
  MANCAR_NO_UPDATE_CHECK=1 do not look for or announce new releases

Easiest start: mancar login https://tunnel.example.com
Or ask your gateway operator for a token: mancard token create --user NAME
`

// Main runs one command and returns the process exit code.
func Main(ctx context.Context, args []string, e Env) int {
	e = e.withDefaults()
	if len(args) == 0 {
		fmt.Fprint(e.Stdout, usageText)
		return 0
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "update", "version", "--version", "-v", "help", "--help", "-h":
	default:
		e.noticeFromCache() // one line, from the cache: never slows a command down
	}
	switch cmd {
	case "login":
		return cmdLogin(ctx, e, rest)
	case "http", "tcp":
		return cmdTunnel(ctx, e, cmd, rest)
	case "start":
		return cmdStart(ctx, e, rest)
	case "status":
		return cmdStatus(e, rest)
	case "stop":
		return cmdStop(ctx, e, rest)
	case "config":
		return cmdConfig(e, rest)
	case "update":
		return cmdUpdate(ctx, e, rest)
	case "version", "--version", "-v":
		return cmdVersion(ctx, e)
	case "help", "--help", "-h":
		fmt.Fprint(e.Stdout, usageText)
		return 0
	default:
		fmt.Fprintf(e.Stderr, "mancar: unknown command %q\n\n%s", cmd, usageText)
		return 2
	}
}

// parseFlags parses flags that may appear before or after positional
// arguments ("mancar http 3000 --subdomain x"). It returns the positionals.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func newFlagSet(e Env, name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(e.Stderr)
	return fs
}

// flagExit maps a flag parsing error to an exit code.
func flagExit(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	return 2
}

func fail(e Env, code int, format string, args ...any) int {
	fmt.Fprintf(e.Stderr, "mancar: "+format+"\n", args...)
	return code
}

// prompter reads answers from stdin. It owns one buffered reader so no
// input is lost between questions.
type prompter struct {
	r   *bufio.Reader
	out io.Writer
}

func newPrompter(e Env) *prompter {
	return &prompter{r: bufio.NewReader(e.Stdin), out: e.Stdout}
}

// ask prints question and returns the trimmed answer; ok is false at EOF
// with no input.
func (p *prompter) ask(question string) (answer string, ok bool) {
	fmt.Fprint(p.out, question)
	line, err := p.r.ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(p.out)
		return "", false
	}
	return strings.TrimSpace(line), true
}
