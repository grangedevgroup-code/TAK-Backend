package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/server"
)

var ztNetworkID = regexp.MustCompile(`^[0-9a-fA-F]{16}$`)

type ztNetwork struct {
	ID        string   `json:"nwid"`
	Name      string   `json:"name"`
	Status    string   `json:"status"`
	Addresses []string `json:"assignedAddresses"`
}

func zerotierCLI() (string, []string, bool) {
	if runtime.GOOS == "windows" {
		for _, p := range []string{
			filepath.Join(os.Getenv("ProgramData"), "ZeroTier", "One", "zerotier-one_x64.exe"),
			filepath.Join(os.Getenv("ProgramData"), "ZeroTier", "One", "zerotier-one_x86.exe"),
		} {
			if _, err := os.Stat(p); err == nil {
				return p, []string{"-q"}, true
			}
		}
		for _, p := range []string{
			filepath.Join(os.Getenv("ProgramFiles(x86)"), "ZeroTier", "One", "zerotier-cli.bat"),
			filepath.Join(os.Getenv("ProgramFiles"), "ZeroTier", "One", "zerotier-cli.bat"),
		} {
			if _, err := os.Stat(p); err == nil {
				return p, nil, true
			}
		}
		return "", nil, false
	}
	if p, err := exec.LookPath("zerotier-cli"); err == nil {
		return p, nil, true
	}
	for _, p := range []string{"/usr/sbin/zerotier-cli", "/usr/local/sbin/zerotier-cli", "/usr/local/bin/zerotier-cli", "/Library/Application Support/ZeroTier/One/zerotier-cli"} {
		if _, err := os.Stat(p); err == nil {
			return p, nil, true
		}
	}
	return "", nil, false
}

func ztRun(args ...string) ([]byte, error) {
	cli, pre, ok := zerotierCLI()
	if !ok {
		return nil, errors.New("ZeroTier is not installed")
	}
	out, err := exec.Command(cli, append(pre, args...)...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("zerotier-cli %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func runShown(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func fetchTo(url, path string) error {
	hc := &http.Client{Timeout: 5 * time.Minute}
	resp, err := hc.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func installZeroTier() error {
	switch runtime.GOOS {
	case "linux":
		script := filepath.Join(os.TempDir(), "zerotier-install.sh")
		defer os.Remove(script)
		if err := fetchTo("https://install.zerotier.com", script); err != nil {
			return err
		}
		return runShown("bash", script)
	case "freebsd":
		if err := runShown("pkg", "install", "-y", "zerotier"); err != nil {
			return err
		}
		runShown("sysrc", "zerotier_enable=YES")
		return runShown("service", "zerotier", "start")
	case "darwin":
		pkg := filepath.Join(os.TempDir(), "ZeroTierOne.pkg")
		defer os.Remove(pkg)
		if err := fetchTo("https://download.zerotier.com/dist/ZeroTier%20One.pkg", pkg); err != nil {
			return err
		}
		return runShown("installer", "-pkg", pkg, "-target", "/")
	case "windows":
		if _, err := exec.LookPath("winget"); err == nil {
			if runShown("winget", "install", "--id", "ZeroTier.ZeroTierOne", "-e", "--silent", "--accept-package-agreements", "--accept-source-agreements") == nil {
				return nil
			}
		}
		msi := filepath.Join(os.TempDir(), "ZeroTierOne.msi")
		defer os.Remove(msi)
		if err := fetchTo("https://download.zerotier.com/dist/ZeroTier%20One.msi", msi); err != nil {
			return err
		}
		return runShown("msiexec", "/i", msi, "/qn", "/norestart")
	}
	return fmt.Errorf("install ZeroTier for %s from https://www.zerotier.com/download/ and run this again", runtime.GOOS)
}

func ensureZeroTier() error {
	if _, _, ok := zerotierCLI(); ok {
		return nil
	}
	step("Installing ZeroTier")
	if err := installZeroTier(); err != nil {
		return fmt.Errorf("could not install ZeroTier: %w", err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, ok := zerotierCLI(); ok {
			if _, err := ztRun("info"); err == nil {
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return errors.New("ZeroTier was installed but its service did not start")
}

func ztNodeID() string {
	out, err := ztRun("-j", "info")
	if err != nil {
		return ""
	}
	var info struct {
		Address string `json:"address"`
	}
	json.Unmarshal(out, &info)
	return info.Address
}

func ztNetworks() ([]ztNetwork, error) {
	out, err := ztRun("-j", "listnetworks")
	if err != nil {
		return nil, err
	}
	var nets []ztNetwork
	if err := json.Unmarshal(out, &nets); err != nil {
		return nil, fmt.Errorf("unexpected zerotier-cli output: %s", strings.TrimSpace(string(out)))
	}
	return nets, nil
}

func ztIPs(n ztNetwork) []string {
	var out []string
	for _, a := range n.Addresses {
		if ip, _, err := net.ParseCIDR(a); err == nil {
			out = append(out, ip.String())
		}
	}
	return out
}

func zerotierJoin(dir, id string, wait time.Duration) ([]string, error) {
	if !ztNetworkID.MatchString(id) {
		return nil, fmt.Errorf("%q is not a ZeroTier network ID (16 hexadecimal characters)", id)
	}
	id = strings.ToLower(id)
	if err := ensureZeroTier(); err != nil {
		return nil, err
	}
	if _, err := ztRun("join", id); err != nil {
		return nil, err
	}
	node := ztNodeID()
	step("Joined ZeroTier network %s as node %s", id, node)
	deadline := time.Now().Add(wait)
	told := false
	for {
		nets, err := ztNetworks()
		if err != nil {
			return nil, err
		}
		for _, n := range nets {
			if !strings.EqualFold(n.ID, id) {
				continue
			}
			if ips := ztIPs(n); len(ips) > 0 && n.Status == "OK" {
				addZeroTierNames(dir, ips)
				return ips, nil
			}
			if n.Status == "ACCESS_DENIED" && !told {
				fmt.Printf("      Authorize node %s in the network's members list at https://my.zerotier.com/network/%s\n", node, id)
				told = true
			}
		}
		if time.Now().After(deadline) {
			if !told {
				fmt.Printf("      If the network is private, authorize node %s at https://my.zerotier.com/network/%s\n", node, id)
			}
			return nil, nil
		}
		time.Sleep(3 * time.Second)
	}
}

func addZeroTierNames(dir string, ips []string) {
	c, err := openClient(dir)
	if err != nil {
		return
	}
	defer c.close()
	cfg, err := getSettings(c)
	if err != nil {
		return
	}
	var names []string
	if v, ok := cfg["extraNames"].([]any); ok {
		for _, x := range v {
			if s, ok := x.(string); ok {
				names = append(names, s)
			}
		}
	}
	addr, _ := cfg["address"].(string)
	changed := false
	for _, ip := range ips {
		if ip != addr && !slices.Contains(names, ip) {
			names = append(names, ip)
			changed = true
		}
	}
	if changed {
		if err := putSettings(c, map[string]any{"extraNames": names}); err != nil {
			warn("could not add the ZeroTier address to the server certificate: %v", err)
		}
	}
}

func cmdZeroTier(a *args) error {
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
	case "join":
		if a.arg(1) == "" {
			return errUsage
		}
		ips, err := zerotierJoin(dir, a.arg(1), 90*time.Second)
		if err != nil {
			return err
		}
		if len(ips) == 0 {
			fmt.Println("Joined, but no address has been assigned yet. Run 'golangtakserver zerotier status' after authorizing this node.")
			return nil
		}
		fmt.Printf("Devices on the ZeroTier network can connect to %s. It was added to the server certificate.\n", strings.Join(ips, ", "))
		return nil
	case "leave":
		if a.arg(1) == "" {
			return errUsage
		}
		_, err := ztRun("leave", strings.ToLower(a.arg(1)))
		if err == nil {
			fmt.Println("Left the network.")
		}
		return err
	case "status":
		if _, _, ok := zerotierCLI(); !ok {
			fmt.Println("ZeroTier is not installed. Join a network with: golangtakserver zerotier join NETWORK_ID")
			return nil
		}
		nets, err := ztNetworks()
		if err != nil {
			return err
		}
		fmt.Printf("ZeroTier node %s\n", ztNodeID())
		if len(nets) == 0 {
			fmt.Println("Not a member of any network.")
		}
		for _, n := range nets {
			ips := ztIPs(n)
			fmt.Printf("  %s  %-20s %-14s %s\n", n.ID, n.Name, n.Status, strings.Join(ips, ", "))
		}
		return nil
	}
	return errUsage
}
