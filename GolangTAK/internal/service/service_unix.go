//go:build unix

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type manager string

const (
	mgrSystemd manager = "systemd"
	mgrOpenRC  manager = "openrc"
	mgrSysV    manager = "sysv"
	mgrLaunchd manager = "launchd"
	mgrRCD     manager = "rc.d"
	mgrCron    manager = "cron"
	mgrNone    manager = "none"
)

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func have(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t\n'\"\\$`;&|<>(){}*?!#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func commandLine(c Config) string {
	parts := []string{shellQuote(c.Executable)}
	for _, a := range c.Args {
		parts = append(parts, shellQuote(a))
	}
	return strings.Join(parts, " ")
}

func detect() manager {
	switch runtime.GOOS {
	case "darwin":
		return mgrLaunchd
	case "freebsd", "dragonfly":
		return mgrRCD
	}
	if exists("/run/systemd/system") && have("systemctl") {
		return mgrSystemd
	}
	if exists("/sbin/openrc-run") || exists("/usr/sbin/openrc-run") || have("rc-service") {
		return mgrOpenRC
	}
	if exists("/etc/init.d") && (have("update-rc.d") || have("chkconfig") || have("service")) {
		return mgrSysV
	}
	if have("crontab") {
		return mgrCron
	}
	return mgrNone
}

func Manager() string { return string(detect()) }

func IsAdmin() bool { return os.Geteuid() == 0 }

func Interactive() bool { return true }

func RunAsService(name string, fn func(stop <-chan struct{}) error) (bool, error) {
	return false, nil
}

func unitPath(c Config) string { return "/etc/systemd/system/" + c.Name + ".service" }

func plistLabel(c Config) string { return "io.github." + c.Name }

func plistPath(c Config) string { return "/Library/LaunchDaemons/" + plistLabel(c) + ".plist" }

func writeFile(path, content string, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), perm); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func systemdUnit(c Config) string {
	return `[Unit]
Description=` + c.Description + `
Documentation=https://github.com/grangedevgroup-code/TAK-Backend
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=` + commandLine(c) + `
Restart=always
RestartSec=3
LimitNOFILE=1048576
TimeoutStopSec=20
KillMode=mixed

[Install]
WantedBy=multi-user.target
`
}

func openrcScript(c Config) string {
	args := make([]string, len(c.Args))
	for i, a := range c.Args {
		args[i] = shellQuote(a)
	}
	return `#!/sbin/openrc-run
name="` + c.DisplayName + `"
description="` + c.Description + `"
command=` + shellQuote(c.Executable) + `
command_args="` + strings.ReplaceAll(strings.Join(args, " "), `"`, `\"`) + `"
supervisor=supervise-daemon
respawn_delay=3
respawn_max=0
output_log="/var/log/` + c.Name + `.log"
error_log="/var/log/` + c.Name + `.log"

depend() {
	need net
	after firewall
}
`
}

func sysvScript(c Config) string {
	sup := append([]string{"supervise"}, c.Args...)
	parts := []string{shellQuote(c.Executable)}
	for _, a := range sup {
		parts = append(parts, shellQuote(a))
	}
	return `#!/bin/sh
### BEGIN INIT INFO
# Provides:          ` + c.Name + `
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: ` + c.DisplayName + `
### END INIT INFO
PIDFILE=/var/run/` + c.Name + `.pid
start() {
	if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
		return 0
	fi
	nohup ` + strings.Join(parts, " ") + ` >>/var/log/` + c.Name + `.log 2>&1 &
	echo $! > "$PIDFILE"
}
stop() {
	if [ -f "$PIDFILE" ]; then
		kill "$(cat "$PIDFILE")" 2>/dev/null
		i=0
		while kill -0 "$(cat "$PIDFILE")" 2>/dev/null && [ $i -lt 40 ]; do sleep 0.5; i=$((i+1)); done
		rm -f "$PIDFILE"
	fi
}
status() {
	if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
		echo running
		return 0
	fi
	echo stopped
	return 3
}
case "$1" in
	start) start ;;
	stop) stop ;;
	restart) stop; start ;;
	status) status ;;
	*) echo "usage: $0 {start|stop|restart|status}"; exit 1 ;;
esac
`
}

func rcdScript(c Config) string {
	args := make([]string, len(c.Args))
	for i, a := range c.Args {
		args[i] = shellQuote(a)
	}
	return `#!/bin/sh
# PROVIDE: ` + c.Name + `
# REQUIRE: NETWORKING
# KEYWORD: shutdown
. /etc/rc.subr
name="` + c.Name + `"
rcvar="` + c.Name + `_enable"
pidfile="/var/run/` + c.Name + `.pid"
procname="/usr/sbin/daemon"
command="/usr/sbin/daemon"
command_args="-r -R 3 -P ${pidfile} -o /var/log/` + c.Name + `.log ` + shellQuote(c.Executable) + ` ` + strings.ReplaceAll(strings.Join(args, " "), `"`, `\"`) + `"
load_rc_config $name
: ${` + c.Name + `_enable:="NO"}
run_rc_command "$1"
`
}

func plist(c Config) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>` + plistLabel(c) + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + xmlEsc(c.Executable) + `</string>
`)
	for _, a := range c.Args {
		b.WriteString("\t\t<string>" + xmlEsc(a) + "</string>\n")
	}
	b.WriteString(`	</array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>ThrottleInterval</key><integer>3</integer>
	<key>SoftResourceLimits</key><dict><key>NumberOfFiles</key><integer>65536</integer></dict>
	<key>StandardOutPath</key><string>/var/log/` + c.Name + `.log</string>
	<key>StandardErrorPath</key><string>/var/log/` + c.Name + `.log</string>
</dict>
</plist>
`)
	return b.String()
}

func xmlEsc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

func cronLine(c Config) string {
	parts := []string{shellQuote(c.Executable), "supervise"}
	for _, a := range c.Args {
		parts = append(parts, shellQuote(a))
	}
	return "@reboot " + strings.Join(parts, " ") + " >/dev/null 2>&1 # " + c.Name
}

func Install(c Config) error {
	switch detect() {
	case mgrSystemd:
		if err := writeFile(unitPath(c), systemdUnit(c), 0o644); err != nil {
			return err
		}
		if out, err := run(30*time.Second, "systemctl", "daemon-reload"); err != nil {
			return fmt.Errorf("systemctl daemon-reload: %v %s", err, out)
		}
		if out, err := run(30*time.Second, "systemctl", "enable", c.Name); err != nil {
			return fmt.Errorf("systemctl enable: %v %s", err, out)
		}
	case mgrOpenRC:
		if err := writeFile("/etc/init.d/"+c.Name, openrcScript(c), 0o755); err != nil {
			return err
		}
		if out, err := run(30*time.Second, "rc-update", "add", c.Name, "default"); err != nil {
			return fmt.Errorf("rc-update: %v %s", err, out)
		}
	case mgrSysV:
		if err := writeFile("/etc/init.d/"+c.Name, sysvScript(c), 0o755); err != nil {
			return err
		}
		if have("update-rc.d") {
			run(30*time.Second, "update-rc.d", c.Name, "defaults")
		} else if have("chkconfig") {
			run(30*time.Second, "chkconfig", "--add", c.Name)
			run(30*time.Second, "chkconfig", c.Name, "on")
		}
	case mgrLaunchd:
		if err := writeFile(plistPath(c), plist(c), 0o644); err != nil {
			return err
		}
	case mgrRCD:
		if err := writeFile("/usr/local/etc/rc.d/"+c.Name, rcdScript(c), 0o755); err != nil {
			return err
		}
		if out, err := run(30*time.Second, "sysrc", c.Name+"_enable=YES"); err != nil {
			return fmt.Errorf("sysrc: %v %s", err, out)
		}
	case mgrCron:
		cur, _ := run(10*time.Second, "crontab", "-l")
		var lines []string
		for _, l := range strings.Split(cur, "\n") {
			if l != "" && !strings.HasSuffix(l, "# "+c.Name) && !strings.Contains(l, "no crontab for") {
				lines = append(lines, l)
			}
		}
		lines = append(lines, cronLine(c))
		f, err := os.CreateTemp("", "cron")
		if err != nil {
			return err
		}
		f.WriteString(strings.Join(lines, "\n") + "\n")
		f.Close()
		defer os.Remove(f.Name())
		if out, err := run(10*time.Second, "crontab", f.Name()); err != nil {
			return fmt.Errorf("crontab: %v %s", err, out)
		}
	default:
		return fmt.Errorf("no supported service manager found; run %q in the background", c.Executable+" supervise")
	}
	return nil
}

func Uninstall(c Config) error {
	Stop(c)
	switch detect() {
	case mgrSystemd:
		run(30*time.Second, "systemctl", "disable", c.Name)
		os.Remove(unitPath(c))
		run(30*time.Second, "systemctl", "daemon-reload")
	case mgrOpenRC:
		run(30*time.Second, "rc-update", "del", c.Name, "default")
		os.Remove("/etc/init.d/" + c.Name)
	case mgrSysV:
		if have("update-rc.d") {
			run(30*time.Second, "update-rc.d", "-f", c.Name, "remove")
		} else if have("chkconfig") {
			run(30*time.Second, "chkconfig", "--del", c.Name)
		}
		os.Remove("/etc/init.d/" + c.Name)
	case mgrLaunchd:
		os.Remove(plistPath(c))
	case mgrRCD:
		run(30*time.Second, "sysrc", "-x", c.Name+"_enable")
		os.Remove("/usr/local/etc/rc.d/" + c.Name)
	case mgrCron:
		cur, _ := run(10*time.Second, "crontab", "-l")
		var lines []string
		for _, l := range strings.Split(cur, "\n") {
			if l != "" && !strings.HasSuffix(l, "# "+c.Name) && !strings.Contains(l, "no crontab for") {
				lines = append(lines, l)
			}
		}
		f, err := os.CreateTemp("", "cron")
		if err == nil {
			f.WriteString(strings.Join(lines, "\n") + "\n")
			f.Close()
			run(10*time.Second, "crontab", f.Name())
			os.Remove(f.Name())
		}
	}
	return nil
}

func pidFile(c Config) string { return "/var/run/" + c.Name + ".pid" }

func supervisorRunning(c Config) bool {
	b, err := os.ReadFile(pidFile(c))
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

func Start(c Config) error {
	var out string
	var err error
	switch detect() {
	case mgrSystemd:
		out, err = run(60*time.Second, "systemctl", "start", c.Name)
	case mgrOpenRC:
		out, err = run(60*time.Second, "rc-service", c.Name, "start")
	case mgrSysV:
		out, err = run(60*time.Second, "/etc/init.d/"+c.Name, "start")
	case mgrLaunchd:
		run(30*time.Second, "launchctl", "bootout", "system/"+plistLabel(c))
		out, err = run(60*time.Second, "launchctl", "bootstrap", "system", plistPath(c))
		if err != nil {
			out, err = run(60*time.Second, "launchctl", "load", "-w", plistPath(c))
		}
	case mgrRCD:
		out, err = run(60*time.Second, "service", c.Name, "start")
	case mgrCron, mgrNone:
		if supervisorRunning(c) {
			return nil
		}
		return startDetached(c)
	}
	if err != nil {
		return fmt.Errorf("%v %s", err, out)
	}
	return nil
}

func Stop(c Config) error {
	var out string
	var err error
	switch detect() {
	case mgrSystemd:
		out, err = run(60*time.Second, "systemctl", "stop", c.Name)
	case mgrOpenRC:
		out, err = run(60*time.Second, "rc-service", c.Name, "stop")
	case mgrSysV:
		out, err = run(60*time.Second, "/etc/init.d/"+c.Name, "stop")
	case mgrLaunchd:
		out, err = run(60*time.Second, "launchctl", "bootout", "system/"+plistLabel(c))
		if err != nil {
			out, err = run(60*time.Second, "launchctl", "unload", plistPath(c))
		}
	case mgrRCD:
		out, err = run(60*time.Second, "service", c.Name, "stop")
	case mgrCron, mgrNone:
		b, rerr := os.ReadFile(pidFile(c))
		if rerr != nil {
			return nil
		}
		if pid, perr := strconv.Atoi(strings.TrimSpace(string(b))); perr == nil {
			if p, ferr := os.FindProcess(pid); ferr == nil {
				p.Signal(syscall.SIGTERM)
			}
		}
		os.Remove(pidFile(c))
		return nil
	}
	if err != nil {
		return fmt.Errorf("%v %s", err, out)
	}
	return nil
}

func Restart(c Config) error {
	if detect() == mgrSystemd {
		if out, err := run(60*time.Second, "systemctl", "restart", c.Name); err != nil {
			return fmt.Errorf("%v %s", err, out)
		}
		return nil
	}
	Stop(c)
	time.Sleep(time.Second)
	return Start(c)
}

func Status(c Config) (string, error) {
	switch detect() {
	case mgrSystemd:
		if !exists(unitPath(c)) {
			return StatusNotInstalled, nil
		}
		out, _ := run(10*time.Second, "systemctl", "is-active", c.Name)
		if strings.TrimSpace(out) == "active" {
			return StatusRunning, nil
		}
		return StatusStopped, nil
	case mgrOpenRC:
		if !exists("/etc/init.d/" + c.Name) {
			return StatusNotInstalled, nil
		}
		if _, err := run(10*time.Second, "rc-service", c.Name, "status"); err == nil {
			return StatusRunning, nil
		}
		return StatusStopped, nil
	case mgrSysV:
		if !exists("/etc/init.d/" + c.Name) {
			return StatusNotInstalled, nil
		}
		if _, err := run(10*time.Second, "/etc/init.d/"+c.Name, "status"); err == nil {
			return StatusRunning, nil
		}
		return StatusStopped, nil
	case mgrLaunchd:
		if !exists(plistPath(c)) {
			return StatusNotInstalled, nil
		}
		out, err := run(10*time.Second, "launchctl", "print", "system/"+plistLabel(c))
		if err == nil && strings.Contains(out, "state = running") {
			return StatusRunning, nil
		}
		return StatusStopped, nil
	case mgrRCD:
		if !exists("/usr/local/etc/rc.d/" + c.Name) {
			return StatusNotInstalled, nil
		}
		if _, err := run(10*time.Second, "service", c.Name, "status"); err == nil {
			return StatusRunning, nil
		}
		return StatusStopped, nil
	case mgrCron:
		cur, _ := run(10*time.Second, "crontab", "-l")
		if !strings.Contains(cur, "# "+c.Name) {
			return StatusNotInstalled, nil
		}
		if supervisorRunning(c) {
			return StatusRunning, nil
		}
		return StatusStopped, nil
	}
	if supervisorRunning(c) {
		return StatusRunning, nil
	}
	return StatusUnknown, nil
}

func startDetached(c Config) error {
	args := append([]string{"supervise"}, c.Args...)
	logf, err := os.OpenFile("/var/log/"+c.Name+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		logf, err = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
	}
	defer logf.Close()
	attr := &os.ProcAttr{Files: []*os.File{nil, logf, logf}, Sys: &syscall.SysProcAttr{Setsid: true}}
	p, err := os.StartProcess(c.Executable, append([]string{c.Executable}, args...), attr)
	if err != nil {
		return err
	}
	os.WriteFile(pidFile(c), []byte(strconv.Itoa(p.Pid)), 0o644)
	return p.Release()
}

func PIDFile(c Config) string { return pidFile(c) }

func LogHint(c Config) string {
	switch detect() {
	case mgrSystemd:
		return "journalctl -u " + c.Name + " -f"
	}
	return "tail -f /var/log/" + c.Name + ".log"
}
