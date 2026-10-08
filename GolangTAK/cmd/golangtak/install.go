package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/firewall"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/flock"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/server"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/service"
)

func serviceName() string {
	if runtime.GOOS == "windows" {
		return "GolangTAK"
	}
	return "golangtak"
}

func installDir() string {
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramFiles")
		if base == "" {
			base = `C:\Program Files`
		}
		return filepath.Join(base, "GolangTAK")
	}
	return "/usr/local/bin"
}

func installPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(installDir(), "golangtak.exe")
	}
	return filepath.Join(installDir(), "golangtak")
}

func serviceConfig(exe, dir string) service.Config {
	args := []string{"run", "--service", "--data", dir}
	if runtime.GOOS == "windows" {
		args = []string{"service", "--data", dir}
	}
	return service.Config{Name: serviceName(), DisplayName: "GolangTAK", Description: "GolangTAK server for TAK clients", Executable: exe, Args: args, DataDir: dir}
}

func installedService(dir string) service.Config {
	return serviceConfig(installPath(), dir)
}

func step(format string, v ...any) {
	fmt.Printf("  - "+format+"\n", v...)
}

func warn(format string, v ...any) {
	fmt.Printf("  ! "+format+"\n", v...)
}

func sameFile(a, b string) bool {
	sa, err1 := os.Stat(a)
	sb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(sa, sb)
}

func copyBinary(src, dest string) error {
	if sameFile(src, dest) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dest + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	out.Close()
	os.Chmod(tmp, 0o755)
	if err := os.Rename(tmp, dest); err != nil {
		old := dest + ".old"
		os.Remove(old)
		if rerr := os.Rename(dest, old); rerr != nil {
			os.Remove(tmp)
			return err
		}
		if err := os.Rename(tmp, dest); err != nil {
			os.Rename(old, dest)
			os.Remove(tmp)
			return err
		}
	}
	return nil
}

func linkCommand(dest string) {
	if runtime.GOOS != "linux" {
		return
	}
	link := "/usr/bin/golangtak"
	if cur, err := os.Readlink(link); err == nil {
		if cur == dest {
			return
		}
		os.Remove(link)
	} else if _, err := os.Lstat(link); err == nil {
		return
	}
	os.Symlink(dest, link)
}

func unlinkCommand(dest string) {
	if runtime.GOOS != "linux" {
		return
	}
	if cur, err := os.Readlink("/usr/bin/golangtak"); err == nil && cur == dest {
		os.Remove("/usr/bin/golangtak")
	}
}

func secureDataDir(dir string) {
	if runtime.GOOS == "windows" {
		icacls := filepath.Join(os.Getenv("SystemRoot"), "System32", "icacls.exe")
		if err := exec.Command(icacls, dir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/Q").Run(); err != nil {
			warn("could not restrict access to %s: %v", dir, err)
			return
		}
		exec.Command(icacls, filepath.Join(dir, "*"), "/reset", "/T", "/C", "/Q").Run()
		return
	}
	os.Chmod(dir, 0o700)
}

func firewallRules(cfg server.Config) []firewall.Rule {
	p := cfg.Ports
	var rules []firewall.Rule
	for _, port := range []int{p.TCP, p.TCPAlt, p.TLS, p.HTTP, p.HTTPS, p.Enroll, p.WebSocket, p.API} {
		rules = append(rules, firewall.Rule{Port: port, Proto: "tcp"})
	}
	if cfg.Federation.Enabled {
		rules = append(rules, firewall.Rule{Port: p.Federation, Proto: "tcp"}, firewall.Rule{Port: p.FederationV2, Proto: "tcp"})
	}
	if v := cfg.Video; v.Enabled {
		rules = append(rules, firewall.Rule{Port: v.RTSPPort, Proto: "tcp"}, firewall.Rule{Port: v.RTSPSPort, Proto: "tcp"}, firewall.Rule{Port: v.RTMPPort, Proto: "tcp"})
		if v.RTPPort > 0 {
			rules = append(rules, firewall.Rule{Port: v.RTPPort, Proto: "udp"}, firewall.Rule{Port: v.RTPPort + 1, Proto: "udp"})
		}
	}
	if cfg.ACME.Enabled {
		port := cfg.ACME.ChallengePort
		if port == 0 {
			port = 80
		}
		rules = append(rules, firewall.Rule{Port: port, Proto: "tcp"})
	}
	if cfg.Voice.Enabled && cfg.Voice.Port > 0 {
		rules = append(rules, firewall.Rule{Port: cfg.Voice.Port, Proto: "tcp"}, firewall.Rule{Port: cfg.Voice.Port, Proto: "udp"})
	}
	for _, f := range cfg.DataFeeds {
		if !f.Enabled || f.Protocol == "sbs" || f.Protocol == "dump1090" || f.Protocol == "traccar" || (f.Protocol == "ais" && f.Address != "") {
			continue
		}
		proto := "tcp"
		if f.Protocol == "udp" || f.Protocol == "mcast" || f.Protocol == "ais" {
			proto = "udp"
		}
		port := f.Port
		if port == 0 && f.Protocol == "ais" {
			port = 10110
		} else if port == 0 && f.Protocol == "osmand" {
			port = 5055
		}
		rules = append(rules, firewall.Rule{Port: port, Proto: proto})
	}
	if cfg.Meshtastic.Enabled && cfg.Meshtastic.BrokerPort > 0 {
		rules = append(rules, firewall.Rule{Port: cfg.Meshtastic.BrokerPort, Proto: "tcp"})
	}
	rules = append(rules, firewall.Rule{Port: p.UDP, Proto: "udp"})
	if cfg.Mesh.Enabled {
		for _, g := range cfg.Mesh.Groups {
			if _, port, err := net.SplitHostPort(g); err == nil {
				n, _ := strconv.Atoi(port)
				rules = append(rules, firewall.Rule{Port: n, Proto: "udp"})
			}
		}
	}
	return firewall.Normalize(rules)
}

func ruleStrings(rules []firewall.Rule) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.String()
	}
	return out
}

func prepareData(a *args, dir string) (server.Config, string, string, bool, error) {
	var s *server.Server
	var err error
	deadline := time.Now().Add(45 * time.Second)
	for {
		s, err = server.New(dir, server.Options{Version: version})
		if err == nil {
			break
		}
		if !errors.Is(err, server.ErrRunning) {
			return server.Config{}, "", "", false, err
		}
		if time.Now().After(deadline) {
			return server.Config{}, "", "", false, fmt.Errorf("another GolangTAK (process %d) is using %s; stop it and run install again", flock.Owner(server.LockPath(dir)), dir)
		}
		time.Sleep(time.Second)
	}
	defer s.Stop()
	_, err = s.UpdateConfig(func(c *server.Config) error {
		if v := strings.TrimSpace(a.val("address")); v != "" {
			c.Address = v
		}
		if v := strings.TrimSpace(a.val("name")); v != "" {
			c.Name = v
		}
		if a.on("no-anonymous") {
			c.AllowAnonymous = false
		}
		return nil
	})
	if err != nil {
		return server.Config{}, "", "", false, err
	}
	if err := s.PKI().EnsureServer(s.Config()); err != nil {
		return server.Config{}, "", "", false, err
	}
	if _, err := s.PKI().SelfTestCert(); err != nil {
		return server.Config{}, "", "", false, err
	}
	user, pw, created, err := s.EnsureAdmin(a.val("admin-password"))
	if err != nil {
		return server.Config{}, "", "", false, err
	}
	if pw == "" {
		if u, p, err := server.ReadInitialPassword(dir); err == nil && strings.EqualFold(u, user) {
			pw = p
		}
	}
	if v := a.val("admin-password"); v != "" && !created {
		if err := s.Directory().SetPassword(user, v); err != nil {
			return server.Config{}, "", "", false, err
		}
		pw = v
	}
	return s.Config(), user, pw, created, nil
}

func waitRunning(dir string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if l, err := flock.Acquire(server.LockPath(dir)); err == nil {
			l.Release()
		} else if _, err := os.Stat(server.ControlTokenPath(dir)); err == nil {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func tailFile(path string, n int) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

func cmdInstall(a *args) error {
	if !isAdmin() {
		return elevate(invocation)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	dir := dataDir(a)
	if !a.has("data") && os.Getenv("GOLANGTAK_DATA") == "" && server.SystemDataDir() != "" {
		dir = server.SystemDataDir()
	}
	dest := installPath()
	svc := serviceConfig(dest, dir)
	fmt.Printf("Installing GolangTAK %s\n\n", version)

	if st, _ := service.Status(svc); st == service.StatusRunning {
		step("Stopping the running GolangTAK service")
		if err := service.Stop(svc); err != nil {
			warn("could not stop the service: %v", err)
		}
		service.WaitFor(svc, service.StatusStopped, 30*time.Second)
	}

	step("Installing the program to %s", dest)
	if err := copyBinary(exe, dest); err != nil {
		return fmt.Errorf("could not install the program to %s: %w", dest, err)
	}
	linkCommand(dest)
	if runtime.GOOS == "windows" {
		if err := addToPath(installDir()); err != nil {
			warn("could not add %s to PATH: %v", installDir(), err)
		}
	}

	step("Preparing data, certificates and the administrator account in %s", dir)
	if _, err := os.Stat(dir); err == nil {
		secureDataDir(dir)
	}
	cfg, user, pw, created, err := prepareData(a, dir)
	if err != nil {
		return err
	}
	secureDataDir(dir)

	step("Registering the %s service (starts at boot, restarts automatically)", service.Manager())
	if err := service.Install(svc); err != nil {
		return fmt.Errorf("could not register the service: %w", err)
	}

	if !a.on("no-firewall") {
		rules := firewallRules(cfg)
		firewall.Program = dest
		method, err := firewall.Open(rules)
		switch {
		case err != nil:
			warn("firewall: %v", err)
		case method != "":
			step("Opened ports in %s: %s", method, strings.Join(ruleStrings(rules), " "))
		default:
			step("No active firewall found; ports needed: %s", strings.Join(ruleStrings(rules), " "))
		}
		rec, _ := json.MarshalIndent(firewallRecord{Method: method, Rules: ruleStrings(rules)}, "", "  ")
		os.WriteFile(firewallPath(dir), rec, 0o600)
	}

	if a.on("no-start") {
		fmt.Println("\nInstalled. Start it with: golangtak start")
		return nil
	}

	step("Starting GolangTAK")
	if err := service.Start(svc); err != nil {
		return fmt.Errorf("the service did not start: %w", err)
	}
	if !waitRunning(dir, 60*time.Second) {
		fmt.Println()
		for _, l := range tailFile(filepath.Join(dir, "logs", "golangtak.log"), 15) {
			fmt.Println("    " + l)
		}
		return fmt.Errorf("GolangTAK did not come up within 60 seconds; check '%s'", service.LogHint(svc))
	}

	step("Testing connections")
	failed := 0
	for _, r := range selfTest(dir, cfg) {
		if r.err != nil {
			failed++
			warn("%-32s FAILED: %v", r.name, r.err)
		} else {
			fmt.Printf("      %-32s ok\n", r.name)
		}
	}

	fmt.Printf("\nGolangTAK %s is installed and running", version)
	if failed > 0 {
		fmt.Printf(" (%d self-test check(s) failed, see above)", failed)
	}
	fmt.Print(".\n\n")
	if !created && pw == "" {
		user = ""
	}
	printConnection(os.Stdout, cfg, user, pw, dir)
	fmt.Printf("\n  iTAK quick connect (scan with iTAK, then sign in):\n\n")
	printQR(os.Stdout, server.ITAKConnectString(cfg, cfg.Address, false))
	fmt.Println("\n  It starts automatically at boot and restarts itself if it stops.")
	fmt.Println("  Cloud servers: also allow the ports above in your provider's firewall or security group.")
	fmt.Println("  Manage it with: golangtak status | golangtak user add NAME | golangtak qr NAME | golangtak logs -f")
	return nil
}

func cmdUninstall(a *args) error {
	if !isAdmin() {
		return elevate(invocation)
	}
	dir := dataDir(a)
	if !a.has("data") && os.Getenv("GOLANGTAK_DATA") == "" && server.SystemDataDir() != "" {
		dir = server.SystemDataDir()
	}
	svc := installedService(dir)
	fmt.Println("Removing GolangTAK")
	step("Stopping and removing the service")
	if err := service.Uninstall(svc); err != nil {
		warn("%v", err)
	}
	var rules []firewall.Rule
	if b, err := os.ReadFile(firewallPath(dir)); err == nil {
		var rec firewallRecord
		if json.Unmarshal(b, &rec) == nil {
			rules = parseRules(rec.Rules)
		}
	}
	if len(rules) == 0 {
		cfg, _ := server.LoadConfig(dir)
		rules = firewallRules(cfg)
	}
	step("Removing firewall rules")
	firewall.Program = installPath()
	firewall.Close(rules)
	if a.on("purge") {
		step("Deleting all data in %s", dir)
		if l, err := flock.Acquire(server.LockPath(dir)); err == nil {
			l.Release()
			if err := os.RemoveAll(dir); err != nil {
				warn("could not delete %s: %v", dir, err)
			}
		} else {
			warn("data directory is still in use; delete %s manually", dir)
		}
	} else {
		step("Keeping data in %s (use --purge to delete it)", dir)
	}
	step("Removing the program")
	unlinkCommand(installPath())
	if runtime.GOOS == "windows" {
		removeFromPath(installDir())
	}
	removeProgram(installPath())
	fmt.Println("\nGolangTAK has been removed.")
	return nil
}

func removeProgram(path string) {
	self, _ := os.Executable()
	if runtime.GOOS == "windows" && sameFile(self, path) {
		scheduleDelete(path)
		return
	}
	os.Remove(path)
	os.Remove(path + ".old")
	if runtime.GOOS == "windows" {
		os.Remove(filepath.Dir(path))
	}
}

func requireService(svc service.Config) error {
	st, err := service.Status(svc)
	if err != nil {
		return err
	}
	if st == service.StatusNotInstalled {
		return errors.New("GolangTAK is not installed as a service; run 'golangtak install' (or 'golangtak run' to run it in this window)")
	}
	return nil
}

func cmdStart(a *args) error {
	if !isAdmin() {
		return elevate(invocation)
	}
	dir := dataDir(a)
	svc := installedService(dir)
	if err := requireService(svc); err != nil {
		return err
	}
	if err := service.Start(svc); err != nil {
		return err
	}
	if !waitRunning(dir, 60*time.Second) {
		return fmt.Errorf("GolangTAK did not come up; check '%s'", service.LogHint(svc))
	}
	fmt.Println("GolangTAK is running.")
	return nil
}

func cmdStop(a *args) error {
	if !isAdmin() {
		return elevate(invocation)
	}
	svc := installedService(dataDir(a))
	if err := requireService(svc); err != nil {
		return err
	}
	if err := service.Stop(svc); err != nil {
		return err
	}
	fmt.Println("GolangTAK is stopped. It will start again at the next boot; use 'golangtak uninstall' to remove it.")
	return nil
}

func cmdRestart(a *args) error {
	if !isAdmin() {
		return elevate(invocation)
	}
	dir := dataDir(a)
	svc := installedService(dir)
	if err := requireService(svc); err != nil {
		return err
	}
	if err := service.Restart(svc); err != nil {
		return err
	}
	if !waitRunning(dir, 60*time.Second) {
		return fmt.Errorf("GolangTAK did not come up; check '%s'", service.LogHint(svc))
	}
	fmt.Println("GolangTAK restarted.")
	return nil
}

func cmdStatus(a *args) error {
	dir := dataDir(a)
	svc := installedService(dir)
	st, _ := service.Status(svc)
	running := false
	if l, err := flock.Acquire(server.LockPath(dir)); err == nil {
		l.Release()
	} else if errors.Is(err, flock.ErrLocked) {
		running = true
	}
	fmt.Printf("  %-12s %s (%s)\n", "Service", st, service.Manager())
	if !running {
		fmt.Printf("  %-12s not running\n", "Server")
		fmt.Printf("  %-12s %s\n", "Data", dir)
		return nil
	}
	c, err := openClient(dir)
	if err != nil {
		fmt.Printf("  %-12s running (process %d)\n", "Server", flock.Owner(server.LockPath(dir)))
		return err
	}
	defer c.close()
	var s struct {
		Name          string         `json:"name"`
		Version       string         `json:"version"`
		Address       string         `json:"address"`
		Uptime        int64          `json:"uptimeSeconds"`
		Clients       int            `json:"clients"`
		ClientsByKind map[string]int `json:"clientsByKind"`
		Users         int            `json:"users"`
		Devices       int            `json:"devices"`
		Missions      int            `json:"missions"`
		Files         int            `json:"files"`
		Events        int64          `json:"events"`
		Memory        uint64         `json:"memoryBytes"`
		CertExpires   time.Time      `json:"serverCertExpires"`
		CAExpires     time.Time      `json:"caExpires"`
		Ports         server.Ports   `json:"ports"`
	}
	if err := c.call("GET", "/api/status", nil, &s); err != nil {
		return err
	}
	kinds := []string{}
	for k, v := range s.ClientsByKind {
		kinds = append(kinds, fmt.Sprintf("%s %d", k, v))
	}
	row := func(k, v string) { fmt.Printf("  %-12s %s\n", k, v) }
	row("Server", fmt.Sprintf("running %s, up %s", s.Version, (time.Duration(s.Uptime)*time.Second).String()))
	row("Name", s.Name)
	row("Address", s.Address)
	row("Clients", fmt.Sprintf("%d %s", s.Clients, strings.Join(kinds, ", ")))
	row("Users", strconv.Itoa(s.Users))
	row("Devices", strconv.Itoa(s.Devices))
	row("Missions", strconv.Itoa(s.Missions))
	row("Files", strconv.Itoa(s.Files))
	row("Events", strconv.FormatInt(s.Events, 10))
	row("Memory", fmt.Sprintf("%.1f MB", float64(s.Memory)/(1<<20)))
	row("Ports", fmt.Sprintf("tcp %d  ssl %d  http %d  https %d  enroll %d  websocket %d  udp %d", s.Ports.TCP, s.Ports.TLS, s.Ports.HTTP, s.Ports.HTTPS, s.Ports.Enroll, s.Ports.WebSocket, s.Ports.UDP))
	row("Server cert", "valid until "+s.CertExpires.Format("2006-01-02"))
	row("CA", "valid until "+s.CAExpires.Format("2006-01-02"))
	row("Data", dir)
	return nil
}
