package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/server"
)

type tsStatus struct {
	BackendState string `json:"BackendState"`
	AuthURL      string `json:"AuthURL"`
	Self         struct {
		HostName     string   `json:"HostName"`
		DNSName      string   `json:"DNSName"`
		TailscaleIPs []string `json:"TailscaleIPs"`
	} `json:"Self"`
	CurrentTailnet *struct {
		Name string `json:"Name"`
	} `json:"CurrentTailnet"`
}

func tailscaleCLI() (string, bool) {
	if runtime.GOOS == "windows" {
		for _, base := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")} {
			if base == "" {
				continue
			}
			p := filepath.Join(base, "Tailscale", "tailscale.exe")
			if _, err := os.Stat(p); err == nil {
				return p, true
			}
		}
	}
	if p, err := exec.LookPath("tailscale"); err == nil {
		return p, true
	}
	for _, p := range []string{"/usr/bin/tailscale", "/usr/local/bin/tailscale", "/opt/homebrew/bin/tailscale", "/Applications/Tailscale.app/Contents/MacOS/Tailscale"} {
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	return "", false
}

func tsRun(args ...string) ([]byte, error) {
	cli, ok := tailscaleCLI()
	if !ok {
		return nil, errors.New("tailscale is not installed")
	}
	out, err := exec.Command(cli, args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("tailscale %s: %v: %s", tsShown(args), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func tsShown(args []string) string {
	shown := make([]string, len(args))
	for i, a := range args {
		if strings.HasPrefix(a, "--authkey=") {
			a = "--authkey=..."
		}
		shown[i] = a
	}
	return strings.Join(shown, " ")
}

func installTailscale() error {
	switch runtime.GOOS {
	case "linux":
		script := filepath.Join(os.TempDir(), "tailscale-install.sh")
		defer os.Remove(script)
		if err := fetchTo("https://tailscale.com/install.sh", script); err != nil {
			return err
		}
		return runShown("sh", script)
	case "freebsd":
		if err := runShown("pkg", "install", "-y", "tailscale"); err != nil {
			return err
		}
		runShown("sysrc", "tailscaled_enable=YES")
		return runShown("service", "tailscaled", "start")
	case "openbsd":
		if err := runShown("pkg_add", "tailscale"); err != nil {
			return err
		}
		runShown("rcctl", "enable", "tailscaled")
		return runShown("rcctl", "start", "tailscaled")
	case "darwin":
		if brew, err := exec.LookPath("brew"); err == nil {
			if user := os.Getenv("SUDO_USER"); user != "" && os.Geteuid() == 0 {
				if err := runShown("sudo", "-u", user, brew, "install", "tailscale"); err != nil {
					return err
				}
			} else if err := runShown(brew, "install", "tailscale"); err != nil {
				return err
			}
			cli, ok := tailscaleCLI()
			if !ok {
				return errors.New("tailscale was installed with Homebrew but the command was not found")
			}
			return runShown(cli, "install-system-daemon")
		}
		return errors.New("install Homebrew (https://brew.sh) or the Tailscale app from the App Store, then run this again")
	case "windows":
		if _, err := exec.LookPath("winget"); err == nil {
			if runShown("winget", "install", "--id", "Tailscale.Tailscale", "-e", "--silent", "--accept-package-agreements", "--accept-source-agreements") == nil {
				return nil
			}
		}
		arch := "amd64"
		switch runtime.GOARCH {
		case "arm64":
			arch = "arm64"
		case "386":
			arch = "x86"
		}
		msi := filepath.Join(os.TempDir(), "tailscale-setup.msi")
		defer os.Remove(msi)
		if err := fetchTo("https://pkgs.tailscale.com/stable/tailscale-setup-latest-"+arch+".msi", msi); err != nil {
			return err
		}
		return runShown("msiexec", "/i", msi, "/qn", "/norestart")
	}
	return fmt.Errorf("install Tailscale for %s (see https://tailscale.com/download) and run this again", runtime.GOOS)
}

func ensureTailscale() error {
	if _, ok := tailscaleCLI(); ok {
		return nil
	}
	step("Installing Tailscale")
	if err := installTailscale(); err != nil {
		return fmt.Errorf("could not install Tailscale: %w", err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := tailscaleCLI(); ok {
			if _, err := tsStatusRead(); err == nil {
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return errors.New("tailscale was installed but its service did not start")
}

func tsStatusRead() (tsStatus, error) {
	var st tsStatus
	out, err := tsRun("status", "--json")
	if err != nil && len(out) == 0 {
		return st, err
	}
	if jerr := json.Unmarshal(out, &st); jerr != nil {
		if err != nil {
			return st, err
		}
		return st, fmt.Errorf("unexpected tailscale output: %s", strings.TrimSpace(string(out)))
	}
	return st, nil
}

func tsNames(st tsStatus) []string {
	var out []string
	for _, a := range st.Self.TailscaleIPs {
		if ip := net.ParseIP(a); ip != nil {
			out = append(out, ip.String())
		}
	}
	if dns := strings.TrimSuffix(st.Self.DNSName, "."); dns != "" {
		out = append(out, dns)
	}
	return out
}

func tailscaleUp(dir, key, hostname string, wait time.Duration) ([]string, error) {
	if err := ensureTailscale(); err != nil {
		return nil, err
	}
	args := []string{"up", "--timeout=" + wait.String()}
	if key != "" && key != "login" {
		args = append(args, "--authkey="+key)
	}
	if hostname != "" {
		args = append(args, "--hostname="+hostname)
	}
	if key == "" || key == "login" {
		step("Sign in to Tailscale with the link below to add this server to your tailnet")
		cli, _ := tailscaleCLI()
		if err := runShown(cli, args...); err != nil {
			return nil, fmt.Errorf("tailscale up: %w", err)
		}
	} else if _, err := tsRun(args...); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		st, err := tsStatusRead()
		if err == nil && st.BackendState == "Running" && len(st.Self.TailscaleIPs) > 0 {
			names := tsNames(st)
			addCertNames(dir, names, "Tailscale")
			return names, nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("tailscale is %s; check the auth key or run 'golangtakserver tailscale up'", firstNonEmpty(st.BackendState, "not connected"))
		}
		time.Sleep(2 * time.Second)
	}
}

func cmdTailscale(a *args) error {
	sub := strings.ToLower(a.arg(0))
	if sub == "" {
		sub = "status"
	}
	if sub != "status" && !isAdmin() {
		return elevate(invocation)
	}
	dir := dataDir(a)
	if !a.has("data") && server.DataEnv() == "" && server.SystemDataDir() != "" {
		if _, err := os.Stat(server.ConfigPath(server.SystemDataDir())); err == nil {
			dir = server.SystemDataDir()
		}
	}
	switch sub {
	case "up", "join":
		key := firstNonEmpty(a.val("auth-key"), a.arg(1), os.Getenv("TS_AUTHKEY"))
		names, err := tailscaleUp(dir, key, a.val("hostname"), 2*time.Minute)
		if err != nil {
			return err
		}
		fmt.Printf("Devices on your tailnet can connect to %s. It was added to the server certificate.\n", strings.Join(names, ", "))
		return nil
	case "down", "leave":
		if _, err := tsRun("down"); err != nil {
			return err
		}
		fmt.Println("Disconnected from the tailnet.")
		return nil
	case "status":
		if _, ok := tailscaleCLI(); !ok {
			fmt.Println("Tailscale is not installed. Connect with: golangtakserver tailscale up [AUTH_KEY]")
			return nil
		}
		st, err := tsStatusRead()
		if err != nil {
			return err
		}
		tailnet := ""
		if st.CurrentTailnet != nil {
			tailnet = st.CurrentTailnet.Name
		}
		fmt.Printf("Tailscale %s\n", firstNonEmpty(st.BackendState, "unknown"))
		if tailnet != "" {
			fmt.Printf("  Tailnet   %s\n", tailnet)
		}
		if st.Self.HostName != "" {
			fmt.Printf("  Machine   %s\n", st.Self.HostName)
		}
		if names := tsNames(st); len(names) > 0 {
			fmt.Printf("  Addresses %s\n", strings.Join(names, ", "))
		}
		if st.AuthURL != "" {
			fmt.Printf("  Sign in   %s\n", st.AuthURL)
		}
		return nil
	}
	return errUsage
}
