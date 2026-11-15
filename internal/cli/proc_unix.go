//go:build !windows

package cli

import (
	"errors"
	"syscall"
)

func defaultPidAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// defaultTerminate asks the agent to shut down gracefully.
func defaultTerminate(pid int) error { return syscall.Kill(pid, syscall.SIGTERM) }
