package cli_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStatusAndStopWithSeveralAgents(t *testing.T) {
	gw := startGateway(t, "")
	m := newMachine(t, connected(gw))
	port := httpBackend(t, "app")

	a := m.start("http", port, "--subdomain", "agent-one")
	a.waitOut(t, "Status: ONLINE")
	b := m.start("http", port, "--subdomain", "agent-two")
	b.waitOut(t, "Status: ONLINE")

	st := m.run("status")
	if st.code != 0 || !strings.Contains(st.stdout, "agent-one.tunnel.test") || !strings.Contains(st.stdout, "agent-two.tunnel.test") {
		t.Fatalf("status: %+v", st)
	}
	if strings.Index(st.stdout, fmt.Sprint(a.pid)) > strings.Index(st.stdout, fmt.Sprint(b.pid)) {
		t.Errorf("agents should be listed oldest first:\n%s", st.stdout)
	}

	// stop one agent by PID: the other keeps running
	if r := m.run("stop", fmt.Sprint(a.pid)); r.code != 0 || !strings.Contains(r.stdout, fmt.Sprintf("Stopped agent %d", a.pid)) {
		t.Fatalf("stop one: %+v", r)
	}
	if code := a.waitExit(t); code != 0 {
		t.Errorf("stopped agent exited with %d", code)
	}
	if st := m.run("status"); strings.Contains(st.stdout, "agent-one") || !strings.Contains(st.stdout, "agent-two") {
		t.Errorf("status after stopping one:\n%s", st.stdout)
	}

	// stop everything
	if r := m.run("stop"); r.code != 0 || !strings.Contains(r.stdout, fmt.Sprintf("Stopped agent %d", b.pid)) {
		t.Fatalf("stop all: %+v", r)
	}
	b.waitExit(t)
	if r := m.run("stop"); r.code != 0 || !strings.Contains(r.stdout, "No tunnels are running.") {
		t.Errorf("stop with nothing running: %+v", r)
	}
}

func TestStopArgumentErrors(t *testing.T) {
	m := newMachine(t, nil)
	if r := m.run("stop", "banana"); r.code != 2 || !strings.Contains(r.stderr, "not a process ID") {
		t.Errorf("%+v", r)
	}
	if r := m.run("stop", "-5"); r.code != 2 {
		t.Errorf("%+v", r)
	}
	if r := m.run("stop", "1", "2"); r.code != 2 {
		t.Errorf("%+v", r)
	}
	if r := m.run("stop", "999999"); r.code != 1 || !strings.Contains(r.stderr, "no running mancar agent with PID 999999") {
		t.Errorf("%+v", r)
	}
	if r := m.run("status", "extra"); r.code != 2 {
		t.Errorf("%+v", r)
	}
}

func TestStaleAndCorruptStateFilesAreIgnoredAndCleaned(t *testing.T) {
	m := newMachine(t, nil)
	os.MkdirAll(m.stateDir, 0o700)
	write := func(name string, content []byte) string {
		p := filepath.Join(m.stateDir, name)
		if err := os.WriteFile(p, content, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	state := func(pid int, updated time.Time) []byte {
		b, _ := json.Marshal(map[string]any{"pid": pid, "started": updated, "updated": updated, "state": "online",
			"tunnels": []map[string]string{{"proto": "http", "public_url": "http://old.tunnel.test", "local": "localhost:1"}}})
		return b
	}
	files := []string{
		write("agent-1.json", state(41000, time.Now().Add(-time.Hour))), // crashed: no heartbeat
		write("agent-2.json", state(41001, time.Now())),                 // fresh heartbeat but the process is gone
		write("agent-3.json", []byte("{not json")),
		write("agent-4.json", []byte(`{"pid":0}`)),
	}
	st := m.run("status")
	if st.code != 0 || !strings.Contains(st.stdout, "No tunnels are running.") {
		t.Errorf("status: %+v", st)
	}
	for _, f := range files {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("%s was not cleaned up", filepath.Base(f))
		}
	}
}

func TestStateFilesArePrivate(t *testing.T) {
	gw := startGateway(t, "")
	m := newMachine(t, connected(gw))
	p := m.start("http", httpBackend(t, "app"), "--subdomain", "private-state")
	p.waitOut(t, "Status: ONLINE")
	files := m.stateFiles()
	if len(files) != 1 {
		t.Fatalf("state files: %v", files)
	}
	b, _ := os.ReadFile(files[0])
	if strings.Contains(string(b), devToken) {
		t.Error("the token is stored in the state file")
	}
	skipIfWindows(t)
	if mode := fileMode(t, files[0]); mode != 0o600 {
		t.Errorf("state file mode = %v, want 0600", mode)
	}
	if mode := fileMode(t, m.stateDir); mode != 0o700 {
		t.Errorf("state dir mode = %v, want 0700", mode)
	}
}

func TestHeartbeatKeepsTheStateFileFresh(t *testing.T) {
	gw := startGateway(t, "")
	m := newMachine(t, connected(gw))
	p := m.start("http", httpBackend(t, "app"), "--subdomain", "heartbeat-app")
	p.waitOut(t, "Status: ONLINE")

	read := func() time.Time {
		files := m.stateFiles()
		if len(files) != 1 {
			t.Fatalf("state files: %v", files)
		}
		var st struct{ Updated time.Time }
		b, _ := os.ReadFile(files[0])
		json.Unmarshal(b, &st)
		return st.Updated
	}
	first := read()
	eventually(t, "a heartbeat", func() bool { return read().After(first) })
}

func TestStatusMarksPrivateTunnels(t *testing.T) {
	m := newMachine(t, nil)
	const pid = 42000
	m.mu.Lock()
	m.procs[pid] = func() {} // a running agent, as far as status can tell
	m.mu.Unlock()
	os.MkdirAll(m.stateDir, 0o700)
	now := time.Now()
	b, _ := json.Marshal(map[string]any{"pid": pid, "started": now, "updated": now, "state": "online",
		"tunnels": []map[string]any{
			{"proto": "http", "public_url": "https://admin.tunnel.test", "local": "localhost:8080", "private": true},
			{"proto": "http", "public_url": "https://www.tunnel.test", "local": "localhost:3000"},
		}})
	os.WriteFile(filepath.Join(m.stateDir, fmt.Sprintf("agent-%d.json", pid)), b, 0o600)
	st := m.run("status")
	lines := strings.Split(st.stdout, "\n")
	if st.code != 0 || len(lines) < 3 || !strings.Contains(lines[1], "http (private)") || strings.Contains(lines[2], "private") {
		t.Errorf("status:\n%s", st.stdout)
	}
}
