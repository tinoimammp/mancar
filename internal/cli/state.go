package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/tinoimammp/mancar/internal/agent"
)

// Every running agent keeps agent-<pid>.json in the state directory, which
// is what "status" and "stop" read. The file is refreshed by a heartbeat so
// a crashed agent (which cannot delete its file) is recognised as stale.

type instanceTunnel struct {
	Proto     string `json:"proto"`
	PublicURL string `json:"public_url"`
	Local     string `json:"local"`
	Private   bool   `json:"private,omitempty"`
	Auth      bool   `json:"auth,omitempty"`
}

type instanceState struct {
	PID     int              `json:"pid"`
	Started time.Time        `json:"started"`
	Updated time.Time        `json:"updated"`
	Server  string           `json:"server"`
	State   string           `json:"state"`
	Error   string           `json:"error,omitempty"`
	Tunnels []instanceTunnel `json:"tunnels"`
}

type instance struct {
	e      Env
	mu     sync.Mutex
	st     instanceState
	path   string
	warned bool
	stop   chan struct{}
	done   chan struct{}
}

func (e Env) stateFile(pid int) string {
	return filepath.Join(e.StateDir, "agent-"+strconv.Itoa(pid)+".json")
}

func newInstance(e Env, server string, specs []agent.TunnelSpec) *instance {
	i := &instance{e: e, stop: make(chan struct{}), done: make(chan struct{})}
	i.st = instanceState{PID: e.PID(), Started: e.Now(), Server: server, State: string(agent.StateConnecting)}
	for _, sp := range specs {
		i.st.Tunnels = append(i.st.Tunnels, instanceTunnel{Proto: sp.Proto, Local: sp.LocalAddr})
	}
	if e.StateDir != "" {
		i.path = e.stateFile(i.st.PID)
		i.flush()
	}
	go i.heartbeat()
	return i
}

func (i *instance) heartbeat() {
	defer close(i.done)
	t := time.NewTicker(i.e.HeartbeatEvery)
	defer t.Stop()
	for {
		select {
		case <-i.stop:
			return
		case <-t.C:
			i.mu.Lock()
			i.flushLocked()
			i.mu.Unlock()
		}
	}
}

func (i *instance) update(s agent.Status) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.st.State = string(s.State)
	i.st.Error = ""
	if s.Err != nil {
		i.st.Error = oneLine(s.Err.Error())
	}
	if len(s.Tunnels) > 0 {
		i.st.Tunnels = i.st.Tunnels[:0]
		for _, t := range s.Tunnels {
			i.st.Tunnels = append(i.st.Tunnels, instanceTunnel{Proto: t.Spec.Proto, PublicURL: t.Registered.PublicURL, Local: t.Spec.LocalAddr, Private: t.Registered.Private, Auth: t.Registered.Auth})
		}
	}
	i.flushLocked()
}

func (i *instance) flush() { i.mu.Lock(); defer i.mu.Unlock(); i.flushLocked() }

func (i *instance) flushLocked() {
	if i.path == "" {
		return
	}
	i.st.Updated = i.e.Now()
	b, err := json.Marshal(i.st)
	if err == nil {
		if err = os.MkdirAll(i.e.StateDir, 0o700); err == nil {
			err = writeFileAtomic(i.path, b, 0o600)
		}
	}
	if err != nil && !i.warned {
		i.warned = true
		fmt.Fprintf(i.e.Stderr, "warning: cannot write %s: %v (mancar status/stop will not see this agent)\n", i.path, err)
	}
}

func (i *instance) close() {
	close(i.stop)
	<-i.done
	if i.path != "" {
		os.Remove(i.path)
	}
}

// liveInstances returns the running agents, oldest first, and deletes state
// files of agents that are gone.
func (e Env) liveInstances() []instanceState {
	if e.StateDir == "" {
		return nil
	}
	files, _ := filepath.Glob(filepath.Join(e.StateDir, "agent-*.json"))
	maxAge := 3*e.HeartbeatEvery + 2*time.Second
	var live []instanceState
	for _, f := range files {
		var st instanceState
		b, err := os.ReadFile(f)
		if err != nil || json.Unmarshal(b, &st) != nil || st.PID <= 0 {
			os.Remove(f)
			continue
		}
		if e.Now().Sub(st.Updated) > maxAge || !e.PidAlive(st.PID) {
			os.Remove(f)
			continue
		}
		live = append(live, st)
	}
	sort.Slice(live, func(a, b int) bool { return live[a].Started.Before(live[b].Started) })
	return live
}

func cmdStatus(e Env, args []string) int {
	fs := newFlagSet(e, "status")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return flagExit(err)
	}
	if len(pos) != 0 {
		return fail(e, 2, "usage: mancar status")
	}
	live := e.liveInstances()
	if len(live) == 0 {
		fmt.Fprintln(e.Stdout, "No tunnels are running.")
		return 0
	}
	tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "PID\tSTATE\tPROTOCOL\tPUBLIC URL\tLOCAL")
	for _, st := range live {
		if len(st.Tunnels) == 0 {
			fmt.Fprintf(tw, "%d\t%s\t-\t-\t-\n", st.PID, st.State)
		}
		for _, t := range st.Tunnels {
			url := t.PublicURL
			if url == "" {
				url = "-"
			}
			proto := t.Proto
			switch {
			case t.Private:
				proto += " (private)"
			case t.Auth:
				proto += " (password)"
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", st.PID, st.State, proto, url, t.Local)
		}
	}
	tw.Flush()
	return 0
}

func cmdStop(ctx context.Context, e Env, args []string) int {
	fs := newFlagSet(e, "stop")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return flagExit(err)
	}
	live := e.liveInstances()
	target := live
	if len(pos) > 1 {
		return fail(e, 2, "usage: mancar stop [PID]")
	}
	if len(pos) == 1 {
		pid, err := strconv.Atoi(pos[0])
		if err != nil || pid <= 0 {
			return fail(e, 2, "%q is not a process ID", pos[0])
		}
		target = nil
		for _, st := range live {
			if st.PID == pid {
				target = append(target, st)
			}
		}
		if len(target) == 0 {
			return fail(e, 1, "no running mancar agent with PID %d (see: mancar status)", pid)
		}
	}
	if len(target) == 0 {
		fmt.Fprintln(e.Stdout, "No tunnels are running.")
		return 0
	}

	code := 0
	for _, st := range target {
		if err := e.Terminate(st.PID); err != nil {
			fmt.Fprintf(e.Stderr, "mancar: cannot stop agent %d: %v\n", st.PID, err)
			code = 1
			continue
		}
		if waitGone(ctx, e, st.PID, 15*time.Second) {
			fmt.Fprintf(e.Stdout, "Stopped agent %d\n", st.PID)
		} else {
			fmt.Fprintf(e.Stderr, "mancar: agent %d did not exit within 15s\n", st.PID)
			code = 1
		}
	}
	return code
}

func waitGone(ctx context.Context, e Env, pid int, limit time.Duration) bool {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		_, err := os.Stat(e.stateFile(pid))
		if os.IsNotExist(err) || !e.PidAlive(pid) {
			os.Remove(e.stateFile(pid))
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(25 * time.Millisecond):
		}
	}
	return false
}
