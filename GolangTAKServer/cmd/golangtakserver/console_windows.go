//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/service"
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
	procSetConsoleCP   = kernel32.NewProc("SetConsoleOutputCP")
	vtEnabled          bool
)

const enableVirtualTerminalProcessing = 0x0004

func enableConsole() {
	h := os.Stdout.Fd()
	var mode uint32
	if r, _, _ := procGetConsoleMode.Call(h, uintptr(unsafe.Pointer(&mode))); r == 0 {
		return
	}
	procSetConsoleCP.Call(65001)
	if r, _, _ := procSetConsoleMode.Call(h, uintptr(mode|enableVirtualTerminalProcessing)); r != 0 {
		vtEnabled = true
	}
}

func ansiOK() bool { return vtEnabled }

func isAdmin() bool { return service.IsAdmin() }

func elevate(argv []string) error {
	pause := true
	for _, a := range argv {
		if a == "--pause" {
			pause = false
		}
	}
	if pause {
		argv = append(argv, "--pause")
	}
	if err := service.RelaunchElevated(argv); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Administrator rights are required. Approve the Windows prompt; the command continues in a new window.")
	return nil
}

func addToPath(dir string) error { return service.AddToSystemPath(dir) }

func removeFromPath(dir string) { service.RemoveFromSystemPath(dir) }

func scheduleDelete(path string) {
	cmdExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	line := `"` + cmdExe + `" /C ping -n 3 127.0.0.1 >NUL & del /F /Q "` + path + `" & del /F /Q "` + path + `.old" & rmdir "` + filepath.Dir(path) + `"`
	cmd := exec.Command(cmdExe)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: line, HideWindow: true, CreationFlags: 0x00000008}
	cmd.Start()
}
