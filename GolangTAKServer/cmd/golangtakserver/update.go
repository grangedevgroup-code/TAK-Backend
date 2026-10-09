package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/server"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/service"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/update"
)

var errUpdated = errors.New("updated to a new version; it restarts automatically when installed as a service, otherwise start it again")

func cmdUpdate(a *args) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	hc := &http.Client{Timeout: 10 * time.Minute}
	rel, err := update.Latest(ctx, hc)
	if err != nil {
		return err
	}
	fmt.Printf("Installed version: %s\nNewest release:    %s  (%s)\n", version, rel.Version, rel.URL)
	if !update.Newer(rel.Version, version) && !a.on("force") {
		fmt.Println("Already up to date.")
		return nil
	}
	if a.on("check") {
		if update.Newer(rel.Version, version) {
			fmt.Println("An update is available. Install it with: golangtakserver update")
		}
		return nil
	}
	if update.InContainer() {
		return errors.New("running in a container: pull the new image and recreate the container instead")
	}
	dir := dataDir(a)
	if !a.has("data") && server.DataEnv() == "" && server.SystemDataDir() != "" {
		dir = server.SystemDataDir()
	}
	svc := installedService(dir)
	st, _ := service.Status(svc)
	target := installPath()
	if st == service.StatusNotInstalled {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if r, err := filepath.EvalSymlinks(exe); err == nil {
			exe = r
		}
		target = exe
	} else if !isAdmin() {
		return elevate(invocation)
	}
	step("Downloading %s and checking it against SHA256SUMS", update.AssetName())
	if err := rel.Install(ctx, hc, target); err != nil {
		return err
	}
	step("Installed version %s to %s", rel.Version, target)
	if st == service.StatusNotInstalled {
		return nil
	}
	step("Restarting the service")
	if err := service.Restart(svc); err != nil {
		return err
	}
	if !service.WaitFor(svc, service.StatusRunning, 60*time.Second) {
		return fmt.Errorf("the service did not come back; check '%s'", service.LogHint(svc))
	}
	fmt.Printf("GolangTAKServer %s is running.\n", rel.Version)
	return nil
}
