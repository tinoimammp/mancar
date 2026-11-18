package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/tinoimammp/mancar/internal/auth"
)

// ---- mancar login ------------------------------------------------------------
//
// Signs this computer in without copying a token by hand: the gateway gives
// a short code, the person allows it in the dashboard (where they are signed
// in), and the gateway hands this command a new agent token for the account,
// named after the computer. The token is saved like "config set token".

func cmdLogin(ctx context.Context, e Env, args []string) int {
	fs := newFlagSet(e, "login")
	name := fs.String("name", "", "name of this device in the dashboard (default: the computer's name)")
	noBrowser := fs.Bool("no-browser", false, "print the link instead of opening a browser")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return flagExit(err)
	}
	if len(pos) > 1 {
		return fail(e, 2, "usage: mancar login [SERVER] [--name NAME] [--no-browser]")
	}
	fc, err := e.loadConfig()
	if err != nil {
		return fail(e, 1, "%v", err)
	}
	server := firstNonEmpty(append(pos, e.Getenv("MANCAR_SERVER"), fc.Server)...)
	if server == "" {
		return fail(e, 2, "which server? run: mancar login https://tunnel.example.com")
	}
	server, err = e.checkServerURL(server, e.Getenv("MANCAR_DIAL_ADDR"))
	if err != nil {
		return fail(e, 2, "%v", err)
	}
	device := strings.TrimSpace(*name)
	if device == "" {
		device, _ = os.Hostname()
		device = strings.TrimSuffix(device, ".local")
	}

	client := e.loginClient()
	var start struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
		URL        string `json:"verification_url"`
		Interval   int    `json:"interval"`
		ExpiresIn  int    `json:"expires_in"`
	}
	if code, err := postJSON(ctx, client, server+"/api/v1/auth/device", map[string]string{"name": device}, &start); err != nil {
		if code == http.StatusNotFound {
			return fail(e, 1, "%s does not support mancar login (update the gateway, or use: mancar config set token -)", server)
		}
		return fail(e, 1, "starting sign in: %v", err)
	}
	if start.DeviceCode == "" || start.UserCode == "" {
		return fail(e, 1, "the server gave an unexpected answer")
	}
	// The link is opened in a browser (on Windows through the shell): only
	// accept a web page on the server we asked, never a file, a UNC path or
	// a program a hostile server might name.
	if u, err := url.Parse(start.URL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host != hostOf(server) {
		return fail(e, 1, "the server sent an unexpected sign-in link: %q", printable(start.URL))
	}

	fmt.Fprintf(e.Stdout, "\n  Open this page, sign in, and allow %q:\n\n    %s\n\n  Check it shows this code:  %s\n\n", device, start.URL, start.UserCode)
	if !*noBrowser && e.OpenBrowser != nil {
		if err := e.OpenBrowser(start.URL); err == nil {
			fmt.Fprintln(e.Stdout, "  (opened in your browser)")
		}
	}
	fmt.Fprintln(e.Stdout, "  Waiting for approval... (Ctrl+C to cancel)")

	every := time.Duration(start.Interval) * time.Second
	if every <= 0 {
		every = 2 * time.Second
	}
	if e.LoginPoll > 0 {
		every = e.LoginPoll
	}
	deadline := e.Now().Add(time.Duration(max(start.ExpiresIn, 60)) * time.Second)
	for {
		select {
		case <-ctx.Done():
			return fail(e, 1, "cancelled")
		case <-time.After(every):
		}
		var got struct {
			Token    string `json:"token"`
			Username string `json:"username"`
			Name     string `json:"name"`
		}
		code, err := postJSON(ctx, client, server+"/api/v1/auth/device/token", map[string]string{"device_code": start.DeviceCode}, &got)
		switch {
		case err == nil:
			if !auth.WellFormed(got.Token) {
				return fail(e, 1, "the server sent a malformed token")
			}
			fc.Server, fc.Token = server, got.Token
			if err := e.saveConfig(fc); err != nil {
				return fail(e, 1, "saving the token: %v", err)
			}
			fmt.Fprintf(e.Stdout, "\n  Signed in as %s. This device's token (%q) is saved.\n  Next: mancar http 3000\n", got.Username, got.Name)
			return 0
		case code == http.StatusPreconditionRequired:
			if e.Now().After(deadline) {
				return fail(e, 1, "the code expired before it was allowed; run mancar login again")
			}
		case code == http.StatusForbidden:
			return fail(e, 1, "the sign in was denied in the dashboard")
		case code == http.StatusGone:
			return fail(e, 1, "the code expired; run mancar login again")
		case code == http.StatusTooManyRequests || code == 0 || code >= 500:
			// network hiccup or busy server: keep waiting until the deadline
			if e.Now().After(deadline) {
				return fail(e, 1, "giving up: %v", err)
			}
		default:
			return fail(e, 1, "%v", err)
		}
	}
}

// hostOf is the host[:port] of a server URL.
func hostOf(server string) string {
	u, err := url.Parse(server)
	if err != nil {
		return ""
	}
	return u.Host
}

// loginClient is an HTTP client that, like the agent, honours
// MANCAR_DIAL_ADDR (connect there, keep the server's name for TLS).
func (e Env) loginClient() *http.Client {
	if e.HTTPClient != nil {
		return e.HTTPClient
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if addr := strings.TrimSpace(e.Getenv("MANCAR_DIAL_ADDR")); addr != "" {
		var d net.Dialer
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		}
	}
	return &http.Client{Transport: tr, Timeout: 20 * time.Second}
}

// postJSON posts body and decodes a 2xx answer into out. On failure it
// returns the HTTP status (0 when there was no answer) and the server's
// message.
func postJSON(ctx context.Context, c *http.Client, url string, body, out any) (int, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error struct{ Message string } `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error.Message != "" {
			return resp.StatusCode, errors.New(e.Error.Message)
		}
		return resp.StatusCode, fmt.Errorf("server answered %s", resp.Status)
	}
	return resp.StatusCode, json.Unmarshal(data, out)
}

// openBrowser opens url in the default browser.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Stdout, cmd.Stderr = nil, nil
	return cmd.Start()
}
