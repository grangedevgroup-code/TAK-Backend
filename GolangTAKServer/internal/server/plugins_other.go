//go:build !unix && !windows

package server

import (
	"os"
	"os/exec"
)

func pluginSysProcAttr(cmd *exec.Cmd) {}

func pluginTerminate(p *os.Process) {
	p.Kill()
}

func pluginKill(p *os.Process) {
	p.Kill()
}
