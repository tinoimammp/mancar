package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tinoimammp/mancar/internal/agent"
	"github.com/tinoimammp/mancar/internal/protocol"
)

// Recently used subdomains, per gateway, so the interactive prompt can offer
// them again. Kept in the state directory (it is history, not configuration).

const (
	recentKept  = 10 // remembered per server
	recentShown = 3  // offered in the prompt
)

type recentSubdomain struct {
	Label  string    `json:"label"`
	UsedAt time.Time `json:"used_at"`
	Random bool      `json:"random,omitempty"` // assigned by the gateway, not chosen
}

func (e Env) recentPath() string {
	if e.StateDir == "" {
		return ""
	}
	return filepath.Join(e.StateDir, "recent-subdomains.json")
}

func (e Env) loadRecent() map[string][]recentSubdomain {
	m := map[string][]recentSubdomain{}
	if p := e.recentPath(); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			_ = json.Unmarshal(b, &m)
		}
	}
	return m
}

// recentSubdomains returns the subdomains used with server, newest first.
func (e Env) recentSubdomains(server string) []recentSubdomain {
	return e.loadRecent()[server]
}

// rememberTunnels records the HTTP hostnames of tunnels that came online.
// Errors are ignored: history is a convenience.
func (e Env) rememberTunnels(server string, ts []agent.TunnelStatus) {
	p := e.recentPath()
	if p == "" {
		return
	}
	m := e.loadRecent()
	list := m[server]
	changed := false
	for _, t := range ts {
		if t.Spec.Proto != protocol.ProtoHTTP || t.Registered.Hostname == "" {
			continue
		}
		label, _, _ := strings.Cut(t.Registered.Hostname, ".")
		kept := []recentSubdomain{{Label: label, UsedAt: e.Now(), Random: t.Spec.Subdomain == ""}}
		for _, r := range list {
			if r.Label != label {
				kept = append(kept, r)
			}
		}
		if len(kept) > recentKept {
			kept = kept[:recentKept]
		}
		list, changed = kept, true
	}
	if !changed {
		return
	}
	m[server] = list
	if b, err := json.MarshalIndent(m, "", "  "); err == nil {
		_ = os.MkdirAll(e.StateDir, 0o700)
		_ = writeFileAtomic(p, append(b, '\n'), 0o600)
	}
}

// agoText renders a short "used ... ago".
func agoText(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}
