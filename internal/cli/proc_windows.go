//go:build windows

package cli

import "os"

func defaultPidAlive(pid int) bool {
	p, err := os.FindProcess(pid) // fails when the process no longer exists
	if err != nil {
		return false
	}
	p.Release()
	return true
}

// defaultTerminate cannot request a graceful stop on Windows; the gateway
// notices the closed connection and frees the hostname.
func defaultTerminate(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	defer p.Release()
	return p.Kill()
}
