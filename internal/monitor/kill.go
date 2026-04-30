package monitor

import (
	"fmt"
	"syscall"
)

// killProcess sends SIGKILL to the specified PID.
func killProcess(pid int) error {
	if pid <= 1 {
		return fmt.Errorf("refusing to kill PID %d (system process)", pid)
	}
	return syscall.Kill(pid, syscall.SIGKILL)
}
