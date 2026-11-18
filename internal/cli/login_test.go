package cli_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinoimammp/mancar/internal/cli"
)

// fakeDeviceServer answers "pending" twice, then approves (or denies).
func fakeDeviceServer(t *testing.T, deny bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var polls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/device", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		json.NewDecoder(r.Body).Decode(&in)
		if in["name"] != "test-box" {
			t.Errorf("device name sent: %q", in["name"])
		}
		json.NewEncoder(w).Encode(map[string]any{"device_code": "secret-dc", "user_code": "ACDE-FGHJ",
			"verification_url": "http://" + r.Host + "/dashboard/#device=ACDE-FGHJ", "interval": 1, "expires_in": 600})
	})
	mux.HandleFunc("POST /api/v1/auth/device/token", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		json.NewDecoder(r.Body).Decode(&in)
		if in["device_code"] != "secret-dc" {
			t.Errorf("device code sent: %q", in["device_code"])
		}
		if polls.Add(1) < 3 {
			w.WriteHeader(http.StatusPreconditionRequired)
			w.Write([]byte(`{"error":{"code":"authorization_pending","message":"waiting"}}`))
			return
		}
		if deny {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":{"code":"access_denied","message":"denied"}}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"token": devToken, "username": "tino", "name": "test-box"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &polls
}

func runLogin(t *testing.T, m *machine, args ...string) (result, []string) {
	t.Helper()
	e, out, errb := m.env("", false, 1)
	e.LoginPoll = 10 * time.Millisecond
	var opened []string
	e.OpenBrowser = func(u string) error { opened = append(opened, u); return nil }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	code := cli.Main(ctx, append([]string{"login"}, args...), e)
	return result{code, out.String(), errb.String()}, opened
}

func TestLoginSavesServerAndToken(t *testing.T) {
	srv, polls := fakeDeviceServer(t, false)
	m := newMachine(t, map[string]string{})
	r, opened := runLogin(t, m, srv.URL, "--name", "test-box")
	if r.code != 0 {
		t.Fatalf("login: %+v", r)
	}
	if !strings.Contains(r.stdout, "ACDE-FGHJ") || !strings.Contains(r.stdout, "Signed in as tino") {
		t.Errorf("output: %s", r.stdout)
	}
	if len(opened) != 1 || !strings.HasSuffix(opened[0], "#device=ACDE-FGHJ") {
		t.Errorf("browser: %v", opened)
	}
	if polls.Load() != 3 {
		t.Errorf("polls: %d", polls.Load())
	}
	cfg := m.run("config")
	if !strings.Contains(cfg.stdout, srv.URL) || strings.Contains(cfg.stdout, devToken) {
		t.Errorf("config after login (server saved, token masked): %s", cfg.stdout)
	}
}

func TestLoginDenied(t *testing.T) {
	srv, _ := fakeDeviceServer(t, true)
	m := newMachine(t, map[string]string{})
	r, _ := runLogin(t, m, srv.URL, "--name", "test-box", "--no-browser")
	if r.code != 1 || !strings.Contains(r.stderr, "denied") {
		t.Errorf("denied: %+v", r)
	}
	if cfg := m.run("config"); strings.Contains(cfg.stdout, srv.URL) {
		t.Errorf("a denied login saved something: %s", cfg.stdout)
	}
}

func TestLoginUsage(t *testing.T) {
	m := newMachine(t, map[string]string{})
	if r, _ := runLogin(t, m); r.code != 2 || !strings.Contains(r.stderr, "which server") {
		t.Errorf("no server: %+v", r)
	}
	if r, _ := runLogin(t, m, "http://tunnel.example.com"); r.code != 2 || !strings.Contains(r.stderr, "unencrypted") {
		t.Errorf("plain http to a public host: %+v", r)
	}
}

// A hostile server must not get mancar login to open a local file, a
// network share or another site in the browser.
func TestLoginRefusesForeignLinks(t *testing.T) {
	for _, link := range []string{"file:///etc/passwd", `\\evil\share\run.exe`, "https://evil.example.net/x", "calc.exe"} {
		mux := http.NewServeMux()
		mux.HandleFunc("POST /api/v1/auth/device", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"device_code": "dc", "user_code": "ACDE-FGHJ", "verification_url": link, "interval": 1, "expires_in": 600})
		})
		srv := httptest.NewServer(mux)
		m := newMachine(t, map[string]string{"MANCAR_DIAL_ADDR": ""})
		r, opened := runLogin(t, m, srv.URL, "--name", "test-box")
		srv.Close()
		if r.code == 0 || len(opened) != 0 || !strings.Contains(r.stderr, "unexpected sign-in link") {
			t.Errorf("%s: exit %d, opened %v, stderr %q", link, r.code, opened, r.stderr)
		}
	}
}
