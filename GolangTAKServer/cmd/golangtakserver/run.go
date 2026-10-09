package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/firewall"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/flock"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/qr"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/server"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/service"
)

func stopSignals() <-chan struct{} {
	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		close(stop)
		<-sig
		os.Exit(1)
	}()
	return stop
}

func underJournal() bool {
	return os.Getenv("INVOCATION_ID") != "" || os.Getenv("JOURNAL_STREAM") != ""
}

func cmdRun(a *args) error {
	dir := dataDir(a)
	if err := applyRunSettings(a, dir); err != nil {
		return err
	}
	if a.on("service") {
		var console io.Writer
		if underJournal() && !a.on("quiet") {
			console = os.Stderr
		}
		return serve(dir, console, stopSignals(), false, 90*time.Second)
	}
	var console io.Writer = os.Stderr
	if a.on("quiet") {
		console = nil
	}
	return serve(dir, console, stopSignals(), true, 0)
}

func cmdService(a *args) error {
	dir := dataDir(a)
	ran, err := service.RunAsService(serviceName(), func(stop <-chan struct{}) error {
		return serve(dir, nil, stop, false, 90*time.Second)
	})
	if ran {
		return err
	}
	return serve(dir, os.Stderr, stopSignals(), true, 0)
}

func openServer(dir string, console io.Writer, stop <-chan struct{}, wait time.Duration) (*server.Server, error) {
	deadline := time.Now().Add(wait)
	for {
		s, err := server.New(dir, server.Options{Console: console, Version: version})
		if err == nil {
			return s, nil
		}
		if !errors.Is(err, server.ErrRunning) || time.Now().After(deadline) {
			if errors.Is(err, server.ErrRunning) {
				pid := flock.Owner(server.LockPath(dir))
				return nil, fmt.Errorf("GolangTAKServer is already running with data directory %s (process %d); see 'golangtakserver status'", dir, pid)
			}
			return nil, err
		}
		select {
		case <-stop:
			return nil, nil
		case <-time.After(time.Second):
		}
	}
}

func logStartupError(dir string, err error) {
	path := filepath.Join(dir, "logs", "golangtakserver.log")
	os.MkdirAll(filepath.Dir(path), 0o700)
	f, ferr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if ferr != nil {
		return
	}
	fmt.Fprintf(f, "%s ERROR could not start: %v\n", time.Now().Format("2006-01-02 15:04:05"), err)
	f.Close()
}

func serve(dir string, console io.Writer, stop <-chan struct{}, banner bool, wait time.Duration) error {
	first := true
	for {
		s, err := openServer(dir, console, stop, wait)
		if err != nil {
			if !banner {
				logStartupError(dir, err)
			}
			return err
		}
		if s == nil {
			return nil
		}
		reapplyFirewall(dir)
		user, pw, created, err := s.EnsureAdmin(runAdminPassword)
		if err != nil {
			s.Log().Error("could not create the administrator account", "err", err)
		}
		if err := s.Start(context.Background()); err != nil {
			s.Log().Error("could not start", "err", err)
			s.Stop()
			return err
		}
		if banner && first {
			printBanner(s, user, pw, created)
		}
		first = false
		select {
		case <-stop:
			s.Stop()
			return nil
		case <-s.RestartRequested():
			s.Log().Info("restarting")
			s.Stop()
			wait = 30 * time.Second
		case <-s.UpdateExit():
			s.Stop()
			return errUpdated
		}
	}
}

func printBanner(s *server.Server, user, pw string, created bool) {
	cfg := s.Config()
	if !created {
		if u, p, err := server.ReadInitialPassword(s.DataDir); err == nil && strings.EqualFold(u, user) {
			pw = p
		}
	}
	w := os.Stdout
	fmt.Fprintf(w, "\nGolangTAKServer %s is running. Press Ctrl+C to stop.\n\n", version)
	printConnection(w, cfg, user, pw, s.DataDir)
	fmt.Fprintf(w, "\n  iTAK quick connect (scan with iTAK, then sign in):\n\n")
	printQR(w, s.ITAKString(cfg.Address, false))
	fmt.Fprintln(w)
}

func printConnection(w io.Writer, cfg server.Config, user, pw, dir string) {
	host := server.HostForURL(cfg.Address)
	row := func(k, v string) { fmt.Fprintf(w, "  %-12s %s\n", k, v) }
	row("Address", cfg.Address)
	if cfg.Ports.Enroll > 0 {
		dash := fmt.Sprintf("https://%s:%d", host, cfg.Ports.Enroll)
		if cfg.Ports.HTTP > 0 {
			dash += fmt.Sprintf("   (or http://%s:%d on a trusted network)", host, cfg.Ports.HTTP)
		}
		row("Dashboard", dash)
	} else if cfg.Ports.HTTP > 0 {
		row("Dashboard", fmt.Sprintf("http://%s:%d", host, cfg.Ports.HTTP))
	}
	if user != "" {
		row("Username", user)
	}
	if pw != "" {
		row("Password", pw+"   (saved in "+server.InitialPasswordPath(dir)+" until you change it)")
	}
	if cfg.Ports.TLS > 0 {
		row("TAK (SSL)", fmt.Sprintf("%s:%d  - ATAK, WinTAK, iTAK: sign in with a user name and password, or scan a QR code from the dashboard", cfg.Address, cfg.Ports.TLS))
	}
	if cfg.Ports.TCP > 0 && cfg.AllowAnonymous {
		row("TAK (TCP)", fmt.Sprintf("%s:%d  - unencrypted, for trusted networks and simple clients", cfg.Address, cfg.Ports.TCP))
	}
	row("Data", dir)
}

func printQR(w io.Writer, text string) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		fmt.Fprintln(w, "  (QR code unavailable: "+err.Error()+")")
		return
	}
	if ansiOK() {
		fmt.Fprint(w, c.TerminalANSI(2, "    "))
	} else {
		fmt.Fprint(w, c.Terminal(2, "    "))
	}
	fmt.Fprintf(w, "    %s\n", text)
}

type firewallRecord struct {
	Method string   `json:"method"`
	Rules  []string `json:"rules"`
}

func firewallPath(dir string) string { return filepath.Join(dir, "firewall.json") }

func parseRules(list []string) []firewall.Rule {
	var out []firewall.Rule
	for _, r := range list {
		p, proto, ok := strings.Cut(r, "/")
		if !ok {
			continue
		}
		var port, end int
		lo, hi, isRange := strings.Cut(p, "-")
		fmt.Sscan(lo, &port)
		if isRange {
			fmt.Sscan(hi, &end)
		}
		out = append(out, firewall.Rule{Port: port, End: end, Proto: proto})
	}
	return out
}

func reapplyFirewall(dir string) {
	if runtime.GOOS != "linux" || !isAdmin() {
		return
	}
	b, err := os.ReadFile(firewallPath(dir))
	if err != nil {
		return
	}
	var rec firewallRecord
	if json.Unmarshal(b, &rec) != nil || !strings.Contains(rec.Method, "iptables") {
		return
	}
	firewall.Reapply(parseRules(rec.Rules))
}

func cmdSupervise(a *args) error {
	if len(a.pos) == 0 {
		return errUsage
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	stop := stopSignals()
	backoff := time.Second
	for {
		cmd := exec.Command(exe, a.pos...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		started := time.Now()
		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "%s supervise: cannot start: %v\n", time.Now().Format(time.RFC3339), err)
		} else {
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case <-stop:
				if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
					cmd.Process.Kill()
				}
				select {
				case <-done:
				case <-time.After(25 * time.Second):
					cmd.Process.Kill()
					<-done
				}
				return nil
			case err := <-done:
				if time.Since(started) > time.Minute {
					backoff = time.Second
				}
				fmt.Fprintf(os.Stderr, "%s supervise: server exited (%v); restarting in %s\n", time.Now().Format(time.RFC3339), err, backoff)
			}
		}
		select {
		case <-stop:
			return nil
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

var runAdminPassword string

func applyRunSettings(a *args, dir string) error {
	runAdminPassword = firstNonEmpty(a.val("admin-password"), os.Getenv("GOLANGTAKSERVER_ADMIN_PASSWORD"))
	addr := strings.TrimSpace(firstNonEmpty(a.val("address"), os.Getenv("GOLANGTAKSERVER_ADDRESS")))
	name := strings.TrimSpace(firstNonEmpty(a.val("name"), os.Getenv("GOLANGTAKSERVER_NAME")))
	if addr == "" && name == "" {
		return nil
	}
	cfg, err := server.LoadConfig(dir)
	if err != nil {
		return err
	}
	if (addr == "" || cfg.Address == addr) && (name == "" || cfg.Name == name) {
		return nil
	}
	if addr != "" {
		cfg.Address = addr
	}
	if name != "" {
		cfg.Name = name
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return server.SaveConfig(dir, cfg)
}
