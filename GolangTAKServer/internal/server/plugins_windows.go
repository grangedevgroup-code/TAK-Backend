//go:build windows

package server

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

func pluginSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x00000200}
}

func pluginTerminate(p *os.Process) {
	kill := exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(p.Pid))
	kill.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if kill.Run() != nil {
		p.Kill()
	}
}

func pluginKill(p *os.Process) {
	p.Kill()
}
