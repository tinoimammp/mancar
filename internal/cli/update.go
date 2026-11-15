package cli

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/tinoimammp/mancar/internal/version"
)

// DefaultReleasesURL is where "mancar update" looks for the latest release.
const DefaultReleasesURL = "https://api.github.com/repos/tinoimammp/mancar/releases/latest"

// updateCheckEvery is how often a running tunnel looks for a new release.
const updateCheckEvery = 24 * time.Hour

// maxBinaryBytes bounds a downloaded binary.
const maxBinaryBytes = 200 << 20

type release struct {
	Tag    string            // e.g. v0.3.0
	Assets map[string]string // file name -> download URL
}

func (e Env) httpClient() *http.Client {
	if e.HTTPClient != nil {
		return e.HTTPClient
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (e Env) latestRelease(ctx context.Context) (*release, error) {
	if e.ReleasesURL == "" {
		return nil, errors.New("no release source configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.ReleasesURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "mancar/"+version.Version)
	resp, err := e.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("checking for updates: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checking for updates: the release server answered %s", resp.Status)
	}
	var body struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return nil, fmt.Errorf("checking for updates: unreadable answer: %w", err)
	}
	if _, ok := parseVersion(body.TagName); !ok {
		return nil, fmt.Errorf("checking for updates: unexpected release tag %q", body.TagName)
	}
	rel := &release{Tag: body.TagName, Assets: map[string]string{}}
	for _, a := range body.Assets {
		rel.Assets[a.Name] = a.URL
	}
	return rel, nil
}

// parseVersion reads "v1.2.3" (a "-suffix" marks a pre-release).
func parseVersion(v string) (semver [4]int, ok bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	core, pre, hasPre := strings.Cut(v, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return semver, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver, false
		}
		semver[i] = n
	}
	// A release sorts after its pre-releases.
	semver[3] = 1
	if hasPre && pre != "" {
		semver[3] = 0
	}
	return semver, true
}

// newer reports whether latest is a higher version than current. A current
// version that is not a release (a development build) is never "older".
func newer(latest, current string) bool {
	l, ok1 := parseVersion(latest)
	c, ok2 := parseVersion(current)
	if !ok1 || !ok2 {
		return false
	}
	for i := range l {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

func (e Env) goos() string {
	if e.GOOS != "" {
		return e.GOOS
	}
	return runtime.GOOS
}

func (e Env) goarch() string {
	if e.GOARCH != "" {
		return e.GOARCH
	}
	return runtime.GOARCH
}

func (e Env) assetName(tag string) string {
	ext := ""
	if e.goos() == "windows" {
		ext = ".exe"
	}
	return fmt.Sprintf("mancar-%s-%s-%s%s", tag, e.goos(), e.goarch(), ext)
}

// cmdUpdate implements "mancar update [--check] [--force]".
func cmdUpdate(ctx context.Context, e Env, args []string) int {
	fs := newFlagSet(e, "update")
	check := fs.Bool("check", false, "only report whether a new version is available")
	force := fs.Bool("force", false, "install the latest release even over a development build or the same version")
	if _, err := parseFlags(fs, args); err != nil {
		return flagExit(err)
	}
	rel, err := e.latestRelease(ctx)
	if err != nil {
		return fail(e, 1, "%v", err)
	}
	cur := version.Version
	_, isRelease := parseVersion(cur)
	switch {
	case *check && !isRelease:
		fmt.Fprintf(e.Stdout, "This is a development build (%s); the latest release is %s.\n", cur, rel.Tag)
		return 0
	case *check && newer(rel.Tag, cur):
		fmt.Fprintf(e.Stdout, "A new version is available: %s (you have %s). Run: mancar update\n", rel.Tag, cur)
		return 0
	case *check || (!*force && isRelease && !newer(rel.Tag, cur)):
		fmt.Fprintf(e.Stdout, "mancar %s is up to date (latest release: %s).\n", cur, rel.Tag)
		return 0
	case !*force && !isRelease:
		return fail(e, 1, "this is a development build (%s); use --force to replace it with release %s", cur, rel.Tag)
	}

	name := e.assetName(rel.Tag)
	binURL, sumsURL := rel.Assets[name], rel.Assets["SHA256SUMS"]
	if binURL == "" {
		return fail(e, 1, "release %s has no build for %s/%s (%s)", rel.Tag, e.goos(), e.goarch(), name)
	}
	if sumsURL == "" {
		return fail(e, 1, "release %s has no SHA256SUMS; refusing to install an unverified binary", rel.Tag)
	}
	want, err := e.expectedSum(ctx, sumsURL, name)
	if err != nil {
		return fail(e, 1, "%v", err)
	}

	exe, err := e.executable()
	if err != nil {
		return fail(e, 1, "cannot find the running mancar binary: %v", err)
	}
	fmt.Fprintf(e.Stdout, "Downloading mancar %s for %s/%s ...\n", rel.Tag, e.goos(), e.goarch())
	tmp, err := e.download(ctx, binURL, filepath.Dir(exe), want)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fail(e, 1, "no permission to write to %s; run: sudo mancar update", filepath.Dir(exe))
		}
		return fail(e, 1, "%v", err)
	}
	if err := replaceBinary(exe, tmp, e.goos()); err != nil {
		os.Remove(tmp)
		if errors.Is(err, os.ErrPermission) {
			return fail(e, 1, "no permission to replace %s; run: sudo mancar update", exe)
		}
		return fail(e, 1, "installing the update failed: %v", err)
	}
	fmt.Fprintf(e.Stdout, "Updated mancar %s -> %s (%s).\n", cur, rel.Tag, exe)
	if n := len(e.liveInstances()); n > 0 {
		fmt.Fprintf(e.Stdout, "%d running tunnel process(es) still use the old version; restart them to switch.\n", n)
	}
	return 0
}

func (e Env) executable() (string, error) {
	if e.Executable != nil {
		return e.Executable()
	}
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(p)
}

func (e Env) get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "mancar/"+version.Version)
	resp, err := e.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("download of %s failed: %s", url, resp.Status)
	}
	return resp, nil
}

// expectedSum finds name in a SHA256SUMS file ("<hex>  <name>" lines).
func (e Env) expectedSum(ctx context.Context, url, name string) (string, error) {
	resp, err := e.get(ctx, url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 1<<20))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("SHA256SUMS has no entry for %s; refusing to install an unverified binary", name)
}

// download writes url to a temporary file in dir and checks its SHA-256.
func (e Env) download(ctx context.Context, url, dir, wantSum string) (string, error) {
	resp, err := e.get(ctx, url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	f, err := os.CreateTemp(dir, ".mancar-update-*")
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxBinaryBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxBinaryBytes {
		err = errors.New("the download is larger than expected")
	}
	if err == nil {
		if got := hex.EncodeToString(h.Sum(nil)); got != wantSum {
			err = fmt.Errorf("checksum mismatch for the download (got %s, want %s); not installed", got, wantSum)
		}
	}
	if err == nil {
		err = os.Chmod(f.Name(), 0o755)
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// replaceBinary moves the verified download over exe. On Unix a rename over
// a running executable is safe. Windows does not allow that, but does allow
// renaming the running file, so the old one is moved aside first.
func replaceBinary(exe, tmp, goos string) error {
	if goos != "windows" {
		return os.Rename(tmp, exe)
	}
	old := exe + ".old"
	os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return err
	}
	if err := os.Rename(tmp, exe); err != nil {
		os.Rename(old, exe)
		return err
	}
	return nil
}

// ---- update notices ----------------------------------------------------------
//
// The latest release tag is cached in the state directory. Every command
// prints a one-line notice from that cache (no network, no delay); running
// tunnels refresh it in the background every updateCheckEvery, and
// "mancar version" asks the release server directly.
// MANCAR_NO_UPDATE_CHECK=1 turns all of it off.

type updateState struct {
	CheckedAt time.Time `json:"checked_at"`
	Latest    string    `json:"latest"`
}

func (e Env) updateChecksOn() bool {
	if e.ReleasesURL == "" || e.Getenv("MANCAR_NO_UPDATE_CHECK") != "" {
		return false
	}
	_, isRelease := parseVersion(version.Version)
	return isRelease // development builds are not nagged
}

func (e Env) updateStatePath() string {
	if e.StateDir == "" {
		return ""
	}
	return filepath.Join(e.StateDir, "update-check.json")
}

func (e Env) cachedUpdate() updateState {
	var st updateState
	if p := e.updateStatePath(); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			_ = json.Unmarshal(b, &st)
		}
	}
	return st
}

// refreshUpdate asks the release server and caches the answer.
func (e Env) refreshUpdate(ctx context.Context, timeout time.Duration) (updateState, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	rel, err := e.latestRelease(cctx)
	if err != nil {
		return updateState{}, err
	}
	st := updateState{CheckedAt: e.Now(), Latest: rel.Tag}
	if p := e.updateStatePath(); p != "" {
		if b, err := json.Marshal(st); err == nil {
			_ = os.MkdirAll(e.StateDir, 0o700)
			_ = os.WriteFile(p, b, 0o600)
		}
	}
	return st, nil
}

func (e Env) printUpdateNotice(latest string) bool {
	if !newer(latest, version.Version) {
		return false
	}
	fmt.Fprintf(e.Stderr, "A new version of mancar is available: %s (you have %s). Run: mancar update\n", latest, version.Version)
	return true
}

// noticeFromCache prints the notice when the cached latest release is newer.
func (e Env) noticeFromCache() {
	if e.updateChecksOn() {
		e.printUpdateNotice(e.cachedUpdate().Latest)
	}
}

// watchUpdates runs for the lifetime of a tunnel: it refreshes a stale cache
// right away and then every updateCheckEvery, announcing each newer release
// once. It never delays the tunnel and is silent on errors.
func (e Env) watchUpdates(ctx context.Context, announced string) {
	if !e.updateChecksOn() {
		return
	}
	for {
		st := e.cachedUpdate()
		if e.Now().Sub(st.CheckedAt) >= updateCheckEvery {
			if fresh, err := e.refreshUpdate(ctx, 10*time.Second); err == nil {
				st = fresh
			}
		}
		if ctx.Err() != nil {
			return
		}
		if st.Latest != announced && e.printUpdateNotice(st.Latest) {
			announced = st.Latest
		}
		wait := updateCheckEvery - e.Now().Sub(st.CheckedAt)
		if wait < time.Minute {
			wait = time.Minute
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// cmdVersion prints the version and, when the release server answers within
// a few seconds, whether it is the latest.
func cmdVersion(ctx context.Context, e Env) int {
	fmt.Fprintf(e.Stdout, "mancar %s\n", version.Version)
	if !e.updateChecksOn() {
		return 0
	}
	st, err := e.refreshUpdate(ctx, 3*time.Second)
	if err != nil {
		return 0
	}
	if newer(st.Latest, version.Version) {
		fmt.Fprintf(e.Stdout, "Latest release: %s. Run: mancar update\n", st.Latest)
	} else {
		fmt.Fprintln(e.Stdout, "This is the latest release.")
	}
	return 0
}
