//go:build unix

package server

import (
	"os"
	"os/exec"
	"syscall"
)

func pluginSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func pluginTerminate(p *os.Process) {
	if err := syscall.Kill(-p.Pid, syscall.SIGTERM); err != nil {
		p.Signal(syscall.SIGTERM)
	}
}

func pluginKill(p *os.Process) {
	if err := syscall.Kill(-p.Pid, syscall.SIGKILL); err != nil {
		p.Kill()
	}
}
