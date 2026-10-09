package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/firewall"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/server"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/service"
)

func legacyServiceName() string {
	if runtime.GOOS == "windows" {
		return "GolangTAK"
	}
	return "golangtak"
}

func legacyInstallDir() string {
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramFiles")
		if base == "" {
			base = `C:\Program Files`
		}
		return filepath.Join(base, "GolangTAK")
	}
	return "/usr/local/bin"
}

func legacyInstallPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(legacyInstallDir(), "golangtak.exe")
	}
	return filepath.Join(legacyInstallDir(), "golangtak")
}

func migrateLegacyInstall(newDir string) {
	oldDir := server.LegacySystemDataDir()
	old := service.Config{Name: legacyServiceName(), DisplayName: "GolangTAK", Executable: legacyInstallPath(), DataDir: oldDir}
	st, _ := service.Status(old)
	_, binErr := os.Stat(legacyInstallPath())
	if st == service.StatusNotInstalled && binErr != nil {
		migrateLegacyData(oldDir, newDir)
		return
	}
	step("Replacing the old GolangTAK installation")
	if st != service.StatusNotInstalled {
		service.Stop(old)
		service.WaitFor(old, service.StatusStopped, 30*time.Second)
		if err := service.Uninstall(old); err != nil {
			warn("could not remove the old GolangTAK service: %v", err)
		}
	}
	var rules []firewall.Rule
	if b, err := os.ReadFile(firewallPath(oldDir)); err == nil {
		var rec firewallRecord
		if json.Unmarshal(b, &rec) == nil {
			rules = parseRules(rec.Rules)
		}
	}
	prev := firewall.Program
	firewall.Program = legacyInstallPath()
	firewall.CloseLegacy(rules)
	firewall.Program = prev
	if runtime.GOOS == "linux" {
		if cur, err := os.Readlink("/usr/bin/golangtak"); err == nil && cur == legacyInstallPath() {
			os.Remove("/usr/bin/golangtak")
		}
	}
	if runtime.GOOS == "windows" {
		removeFromPath(legacyInstallDir())
	}
	removeProgram(legacyInstallPath())
	migrateLegacyData(oldDir, newDir)
}

func migrateLegacyData(oldDir, newDir string) {
	moved, err := server.MigrateLegacyData(oldDir, newDir)
	switch {
	case err != nil:
		warn("could not move the old data from %s to %s: %v; move it by hand or install with --data %s", oldDir, newDir, err, oldDir)
	case moved:
		step("Moved the existing data from %s to %s", oldDir, newDir)
	}
}
