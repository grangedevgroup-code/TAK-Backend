package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/server"
)

var version = "dev"

var invocation []string

var errUsage = errors.New("usage")

type args struct {
	pos   []string
	vals  map[string]string
	flags map[string]bool
}

func (a *args) val(k string) string { return a.vals[k] }

func (a *args) on(k string) bool { return a.flags[k] }

func (a *args) arg(i int) string {
	if i < len(a.pos) {
		return a.pos[i]
	}
	return ""
}

func (a *args) has(k string) bool {
	_, ok := a.vals[k]
	return ok
}

type command struct {
	name    string
	usage   string
	summary string
	values  []string
	bools   []string
	run     func(*args) error
	raw     bool
	hidden  bool
}

func commands() []command {
	return []command{
		{name: "run", usage: "run [--data DIR]", summary: "Run the server in this window (Ctrl+C stops it)", bools: []string{"service", "quiet"}, run: cmdRun},
		{name: "install", usage: "install [--address HOST] [--name NAME] [--admin-password PW] [--no-anonymous] [--no-firewall] [--no-start]", summary: "Install as a system service that starts at boot, open the firewall, create the admin account and test everything", values: []string{"address", "name", "admin-password"}, bools: []string{"no-anonymous", "no-firewall", "no-start", "yes"}, run: cmdInstall},
		{name: "uninstall", usage: "uninstall [--purge]", summary: "Remove the service, firewall rules and program (--purge also deletes all data)", bools: []string{"purge", "yes"}, run: cmdUninstall},
		{name: "start", usage: "start", summary: "Start the service", run: cmdStart},
		{name: "stop", usage: "stop", summary: "Stop the service", run: cmdStop},
		{name: "restart", usage: "restart", summary: "Restart the service", run: cmdRestart},
		{name: "status", usage: "status", summary: "Show service state, addresses and connected clients", run: cmdStatus},
		{name: "connect", usage: "connect [--host HOST] [--user NAME]", summary: "Show connection details and QR codes for TAK clients", values: []string{"host", "user"}, run: cmdConnect},
		{name: "qr", usage: "qr [USER] [--host HOST]", summary: "Print a QR code to connect a device (ATAK enrollment for USER, or iTAK quick connect)", values: []string{"host"}, run: cmdQR},
		{name: "user", usage: "user list | add NAME [--password PW] [--admin] [--groups G1,G2] [--callsign CS] | del NAME | passwd NAME [PW] | admin NAME on|off | disable NAME | enable NAME | groups NAME [--in G1,G2] [--out G1,G2] | revoke NAME | package NAME [--type cert|enroll|tcp] [--host HOST] [--out FILE]", summary: "Manage user accounts and connection packages", values: []string{"password", "groups", "callsign", "in", "out", "type", "host", "out-file", "team", "role"}, bools: []string{"admin"}, run: cmdUser},
		{name: "group", usage: "group list | add NAME [--description TEXT] | del NAME", summary: "Manage groups (channels)", values: []string{"description"}, run: cmdGroup},
		{name: "peer", usage: "peer list | invite NAME [--groups G1,G2] | join CODE [--name NAME] [--groups G1,G2] | add NAME URL [--groups G1,G2] [--user U --password PW] [--cert FILE.p12 --cert-password PW] [--trust FILE] [--insecure] [--direction both|in|out] [--no-presence] | del NAME | enable NAME | disable NAME", summary: "Link to other TAK servers and TAK-compatible software (invite and join link two GolangTAK servers with one code)", values: []string{"groups", "user", "password", "cert", "cert-password", "trust", "direction", "protocol", "name"}, bools: []string{"insecure", "no-presence"}, run: cmdPeer},
		{name: "plugin", usage: "plugin list | install FOLDER|ZIP|URL [--name NAME] | add NAME COMMAND [ARGS...] [--env K=V,K2=V2] [--dir DIR] [--admin] [--groups G1,G2] [--disabled] | settings NAME [KEY=VALUE...] | del NAME [--files] | uninstall NAME | enable NAME | disable NAME | restart NAME | logs NAME", summary: "Run your own programs alongside the server; they get an API token and are restarted if they stop (put -- before arguments that start with a dash)", values: []string{"env", "dir", "groups", "name"}, bools: []string{"admin", "disabled", "files"}, run: cmdPlugin},
		{name: "config", usage: "config show | get KEY | set KEY VALUE [KEY VALUE ...] | path", summary: "View or change settings (for example: config set ports.tls 8089)", run: cmdConfig},
		{name: "cert", usage: "cert info | renew | revoke SERIAL | import-ca CERT.pem KEY.pem [KEY-PASSWORD]", summary: "Certificate authority and server certificate tools", run: cmdCert},
		{name: "logs", usage: "logs [-f] [-n LINES]", summary: "Show the server log (-f follows new lines)", values: []string{"n"}, bools: []string{"f", "follow"}, run: cmdLogs},
		{name: "selftest", usage: "selftest", summary: "Check that the running server accepts TAK connections", run: cmdSelfTest},
		{name: "bench", usage: "bench [--host HOST] [--port PORT] [--clients N] [--every SECONDS] [--duration SECONDS] [--ramp SECONDS] [--tls --cert USER.p12 [--cert-password PW] [--trust CA.pem|TRUST.p12] [--insecure]]", summary: "Load test a TAK server with simulated clients and report throughput and delivery latency", values: []string{"host", "port", "clients", "every", "duration", "ramp", "cert", "cert-password", "trust", "trust-password"}, bools: []string{"tls", "insecure"}, run: cmdBench},
		{name: "backup", usage: "backup [FILE] [--files]", summary: "Save settings, users, certificates and missions to a zip file", bools: []string{"files"}, run: cmdBackup},
		{name: "version", usage: "version", summary: "Print the version", run: cmdVersion},
		{name: "help", usage: "help [COMMAND]", summary: "Show help", run: cmdHelp},
		{name: "service", usage: "service --data DIR", summary: "Entry point used by the Windows service manager", run: cmdService, hidden: true},
		{name: "supervise", usage: "supervise COMMAND...", summary: "Keep a command running, restarting it if it stops", run: cmdSupervise, raw: true, hidden: true},
	}
}

func findCommand(name string) *command {
	for _, c := range commands() {
		if c.name == name {
			return &c
		}
	}
	switch name {
	case "users":
		return findCommand("user")
	case "groups":
		return findCommand("group")
	case "peers":
		return findCommand("peer")
	case "plugins":
		return findCommand("plugin")
	case "serve", "server", "foreground":
		return findCommand("run")
	case "setup":
		return findCommand("install")
	case "remove":
		return findCommand("uninstall")
	case "log":
		return findCommand("logs")
	case "benchmark", "loadtest", "load-test":
		return findCommand("bench")
	case "test", "self-test", "check":
		return findCommand("selftest")
	case "certs", "certificate", "ca":
		return findCommand("cert")
	case "settings":
		return findCommand("config")
	}
	return nil
}

func isNumber(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

func parseArgs(in []string, values, bools []string) (*args, error) {
	a := &args{vals: map[string]string{}, flags: map[string]bool{}}
	isVal := map[string]bool{"data": true}
	for _, v := range values {
		isVal[v] = true
	}
	isBool := map[string]bool{"help": true, "h": true, "pause": true}
	for _, b := range bools {
		isBool[b] = true
	}
	for i := 0; i < len(in); i++ {
		s := in[i]
		if s == "--" {
			a.pos = append(a.pos, in[i+1:]...)
			break
		}
		if len(s) < 2 || s[0] != '-' || isNumber(s) {
			a.pos = append(a.pos, s)
			continue
		}
		name := strings.TrimLeft(s, "-")
		val, hasVal := "", false
		if k, v, ok := strings.Cut(name, "="); ok {
			name, val, hasVal = k, v, true
		}
		switch {
		case isVal[name]:
			if !hasVal {
				if i+1 >= len(in) {
					return nil, fmt.Errorf("--%s needs a value", name)
				}
				i++
				val = in[i]
			}
			a.vals[name] = val
		case isBool[name]:
			if hasVal {
				b, err := strconv.ParseBool(val)
				if err != nil {
					return nil, fmt.Errorf("--%s expects true or false", name)
				}
				a.flags[name] = b
			} else {
				a.flags[name] = true
			}
		default:
			return nil, fmt.Errorf("unknown option %s", s)
		}
	}
	return a, nil
}

func main() {
	if version == "dev" {
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			version = strings.TrimPrefix(bi.Main.Version, "v")
		}
	}
	os.Exit(realMain(os.Args[1:]))
}

func realMain(argv []string) int {
	invocation = argv
	enableConsole()
	name, rest := "run", argv
	if len(argv) > 0 {
		switch argv[0] {
		case "-h", "--help", "-help", "/?":
			printHelp(os.Stdout)
			return 0
		case "-v", "--version", "-version":
			name, rest = "version", argv[1:]
		default:
			if !strings.HasPrefix(argv[0], "-") {
				name, rest = strings.ToLower(argv[0]), argv[1:]
			}
		}
	}
	cmd := findCommand(name)
	if cmd == nil {
		fmt.Fprintf(os.Stderr, "golangtak: unknown command %q\n\n", name)
		printHelp(os.Stderr)
		return 2
	}
	var a *args
	if cmd.raw {
		a = &args{pos: rest, vals: map[string]string{}, flags: map[string]bool{}}
	} else {
		var err error
		if a, err = parseArgs(rest, cmd.values, cmd.bools); err != nil {
			fmt.Fprintf(os.Stderr, "golangtak %s: %v\nusage: golangtak %s\n", cmd.name, err, cmd.usage)
			return 2
		}
	}
	if a.on("help") || a.on("h") {
		fmt.Printf("usage: golangtak %s\n\n%s\n", cmd.usage, cmd.summary)
		return 0
	}
	err := cmd.run(a)
	code := 0
	if err != nil {
		code = 1
		if errors.Is(err, errUsage) {
			fmt.Fprintf(os.Stderr, "usage: golangtak %s\n", cmd.usage)
			code = 2
		} else {
			fmt.Fprintln(os.Stderr, "golangtak: "+friendlyError(err))
		}
	}
	if a.on("pause") {
		fmt.Print("\nPress Enter to close this window.")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}
	return code
}

func friendlyError(err error) string {
	msg := err.Error()
	if errors.Is(err, fs.ErrPermission) || strings.Contains(strings.ToLower(msg), "access is denied") {
		if runtime.GOOS == "windows" {
			return msg + "\n  Run this command from an administrator terminal."
		}
		return msg + "\n  Run this command with sudo, for example: sudo golangtak " + strings.Join(invocation, " ")
	}
	return msg
}

func printHelp(w io.Writer) {
	fmt.Fprintf(w, "GolangTAK %s - open source server for TAK clients (ATAK, WinTAK, iTAK, TAK Aware and compatible software)\n\n", version)
	fmt.Fprintln(w, "usage: golangtak [COMMAND] [OPTIONS]")
	fmt.Fprintln(w, "\ncommands:")
	for _, c := range commands() {
		if c.hidden {
			continue
		}
		fmt.Fprintf(w, "  %-10s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(w, "\nWith no command, golangtak runs the server in this window.")
	fmt.Fprintln(w, "Every command accepts --data DIR to use a different data directory (default: "+server.DefaultDataDir()+").")
	fmt.Fprintln(w, "Run 'golangtak help COMMAND' for the options of one command.")
}

func cmdHelp(a *args) error {
	if a.arg(0) != "" {
		c := findCommand(a.arg(0))
		if c == nil {
			return fmt.Errorf("unknown command %q", a.arg(0))
		}
		fmt.Printf("usage: golangtak %s\n\n%s\n", c.usage, c.summary)
		return nil
	}
	printHelp(os.Stdout)
	return nil
}

func cmdVersion(a *args) error {
	fmt.Printf("GolangTAK %s (%s %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return nil
}

func dataDir(a *args) string {
	d := a.val("data")
	if d == "" {
		d = server.DefaultDataDir()
	}
	if abs, err := filepath.Abs(d); err == nil {
		d = abs
	}
	return d
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
