package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinoimammp/mancar/internal/version"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		latest, current string
		want            bool
	}{
		{"v0.3.0", "v0.2.0", true},
		{"v0.2.1", "v0.2.0", true},
		{"v1.0.0", "v0.9.9", true},
		{"v0.10.0", "v0.9.0", true}, // numeric, not lexical
		{"v0.2.0", "v0.2.0", false},
		{"v0.1.0", "v0.2.0", false},
		{"v0.3.0", "v0.3.0-rc1", true},
		{"v0.3.0-rc1", "v0.3.0", false},
		{"v0.3.0", "dev", false},
		{"garbage", "v0.1.0", false},
	} {
		if got := newer(c.latest, c.current); got != c.want {
			t.Errorf("newer(%q, %q) = %v, want %v", c.latest, c.current, got, c.want)
		}
	}
}

type fakeReleases struct {
	srv      *httptest.Server
	hits     atomic.Int64
	tag      string
	binary   []byte
	sums     string // overrides the generated SHA256SUMS when set
	noSums   bool
	assetFor string // os-arch the release has a build for
}

func newFakeReleases(t *testing.T, tag string, binary []byte) *fakeReleases {
	f := &fakeReleases{tag: tag, binary: binary, assetFor: "linux-amd64"}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := fmt.Sprintf("mancar-%s-%s", f.tag, f.assetFor)
		switch r.URL.Path {
		case "/latest":
			f.hits.Add(1)
			assets := []map[string]string{{"name": name, "browser_download_url": f.srv.URL + "/bin"}}
			if !f.noSums {
				assets = append(assets, map[string]string{"name": "SHA256SUMS", "browser_download_url": f.srv.URL + "/sums"})
			}
			json.NewEncoder(w).Encode(map[string]any{"tag_name": f.tag, "assets": assets})
		case "/bin":
			w.Write(f.binary)
		case "/sums":
			if f.sums != "" {
				fmt.Fprint(w, f.sums)
				return
			}
			sum := sha256.Sum256(f.binary)
			fmt.Fprintf(w, "%s  mancar-%s-darwin-arm64\n%s  %s\n", strings.Repeat("0", 64), f.tag, hex.EncodeToString(sum[:]), name)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func setVersion(t *testing.T, v string) {
	old := version.Version
	version.Version = v
	t.Cleanup(func() { version.Version = old })
}

func updateEnv(t *testing.T, f *fakeReleases) (Env, string, *bytes.Buffer, *bytes.Buffer) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "mancar")
	if err := os.WriteFile(exe, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	e := Env{
		Stdout: &out, Stderr: &errb, StateDir: t.TempDir(), ConfigDir: t.TempDir(),
		ReleasesURL: f.srv.URL + "/latest", GOOS: "linux", GOARCH: "amd64",
		Executable: func() (string, error) { return exe, nil },
	}
	return e.withDefaults(), exe, &out, &errb
}

func TestUpdateInstallsVerifiedRelease(t *testing.T) {
	setVersion(t, "v0.2.0")
	f := newFakeReleases(t, "v0.3.0", []byte("new binary v0.3.0"))
	e, exe, out, errb := updateEnv(t, f)
	if code := Main(context.Background(), []string{"update"}, e); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	got, _ := os.ReadFile(exe)
	if string(got) != "new binary v0.3.0" {
		t.Errorf("binary not replaced: %q", got)
	}
	if fi, _ := os.Stat(exe); fi.Mode()&0o111 == 0 {
		t.Error("new binary is not executable")
	}
	if !strings.Contains(out.String(), "v0.2.0 -> v0.3.0") {
		t.Errorf("output: %s", out)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), ".mancar-update-*")); len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

func TestUpdateRefusesBadChecksumOrMissingSums(t *testing.T) {
	setVersion(t, "v0.2.0")
	for name, mutate := range map[string]func(*fakeReleases){
		"wrong checksum": func(f *fakeReleases) { f.sums = strings.Repeat("a", 64) + "  mancar-v0.3.0-linux-amd64\n" },
		"no entry":       func(f *fakeReleases) { f.sums = strings.Repeat("a", 64) + "  something-else\n" },
		"no SHA256SUMS":  func(f *fakeReleases) { f.noSums = true },
		"no build":       func(f *fakeReleases) { f.assetFor = "plan9-mips" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeReleases(t, "v0.3.0", []byte("tampered"))
			mutate(f)
			e, exe, _, errb := updateEnv(t, f)
			if code := Main(context.Background(), []string{"update"}, e); code != 1 {
				t.Fatalf("exit %d, want 1: %s", code, errb)
			}
			if got, _ := os.ReadFile(exe); string(got) != "old binary" {
				t.Errorf("binary replaced despite %s: %q", name, got)
			}
			if left, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), ".mancar-update-*")); len(left) != 0 {
				t.Errorf("temporary files left behind: %v", left)
			}
		})
	}
}

func TestUpdateCheckAndUpToDate(t *testing.T) {
	f := newFakeReleases(t, "v0.3.0", []byte("x"))
	for _, c := range []struct{ cur, want string }{
		{"v0.2.0", "A new version is available: v0.3.0"},
		{"v0.3.0", "is up to date"},
		{"dev", "development build"},
	} {
		setVersion(t, c.cur)
		e, exe, out, _ := updateEnv(t, f)
		if code := Main(context.Background(), []string{"update", "--check"}, e); code != 0 || !strings.Contains(out.String(), c.want) {
			t.Errorf("%s --check: exit %d, %q", c.cur, code, out)
		}
		if got, _ := os.ReadFile(exe); string(got) != "old binary" {
			t.Error("--check replaced the binary")
		}
	}
	// Without --check, an up-to-date release does nothing and a dev build needs --force.
	setVersion(t, "v0.3.0")
	e, _, out, _ := updateEnv(t, f)
	if code := Main(context.Background(), []string{"update"}, e); code != 0 || !strings.Contains(out.String(), "up to date") {
		t.Errorf("up to date: %d %q", code, out)
	}
	setVersion(t, "dev")
	e, _, _, errb := updateEnv(t, f)
	if code := Main(context.Background(), []string{"update"}, e); code != 1 || !strings.Contains(errb.String(), "--force") {
		t.Errorf("dev build: %d %q", code, errb)
	}
}

func TestEveryCommandShowsCachedNotice(t *testing.T) {
	setVersion(t, "v0.2.0")
	f := newFakeReleases(t, "v0.3.0", []byte("x"))
	e, _, _, errb := updateEnv(t, f)

	// Nothing cached yet: commands stay quiet and do not touch the network.
	Main(context.Background(), []string{"status"}, e)
	if errb.Len() != 0 || f.hits.Load() != 0 {
		t.Fatalf("notice without a cache: %q, hits=%d", errb, f.hits.Load())
	}
	// "mancar version" asks the server, says so, and fills the cache.
	var out bytes.Buffer
	e.Stdout = &out
	Main(context.Background(), []string{"version"}, e)
	if !strings.Contains(out.String(), "mancar v0.2.0") || !strings.Contains(out.String(), "Latest release: v0.3.0") || f.hits.Load() != 1 {
		t.Fatalf("version: %q hits=%d", out.String(), f.hits.Load())
	}
	// From now on every command shows the notice, still without network.
	Main(context.Background(), []string{"status"}, e)
	if !strings.Contains(errb.String(), "A new version of mancar is available: v0.3.0") || f.hits.Load() != 1 {
		t.Errorf("cached notice: %q hits=%d", errb, f.hits.Load())
	}
	errb.Reset()
	Main(context.Background(), []string{"update", "--check"}, e) // prints its own message, not the notice
	if strings.Contains(errb.String(), "A new version of mancar") {
		t.Errorf("update repeated the notice: %q", errb)
	}

	errb.Reset()
	e.Getenv = func(k string) string {
		if k == "MANCAR_NO_UPDATE_CHECK" {
			return "1"
		}
		return ""
	}
	Main(context.Background(), []string{"status"}, e)
	if errb.Len() != 0 {
		t.Errorf("MANCAR_NO_UPDATE_CHECK ignored: %q", errb)
	}
}

// lockedBuffer is a bytes.Buffer safe for a writer goroutine and a reader.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestWatchUpdatesRefreshesStaleCacheOnce(t *testing.T) {
	setVersion(t, "v0.2.0")
	f := newFakeReleases(t, "v0.3.0", []byte("x"))
	e, _, _, _ := updateEnv(t, f)
	errb := &lockedBuffer{}
	e.Stderr = errb
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.watchUpdates(ctx, ""); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(errb.String(), "v0.3.0") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if f.hits.Load() != 1 || strings.Count(errb.String(), "v0.3.0") != 1 {
		t.Errorf("hits=%d output=%q", f.hits.Load(), errb)
	}
	// A fresh cache is not re-fetched by the next tunnel.
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	e.watchUpdates(ctx, "v0.3.0")
	if f.hits.Load() != 1 {
		t.Errorf("fresh cache re-fetched: %d", f.hits.Load())
	}
}

func TestDevelopmentBuildIsNotNagged(t *testing.T) {
	setVersion(t, "dev")
	f := newFakeReleases(t, "v0.3.0", []byte("x"))
	e, _, out, errb := updateEnv(t, f)
	Main(context.Background(), []string{"version"}, e)
	Main(context.Background(), []string{"status"}, e)
	if f.hits.Load() != 0 || strings.Contains(out.String()+errb.String(), "v0.3.0") {
		t.Errorf("dev build checked or nagged: hits=%d %q %q", f.hits.Load(), out, errb)
	}
}
