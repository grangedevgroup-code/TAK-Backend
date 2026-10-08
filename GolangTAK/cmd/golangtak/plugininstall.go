package main

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/server"
)

const (
	maxPluginDownload = 512 << 20
	maxPluginFiles    = 10000
)

func downloadPlugin(src, dst string) error {
	u, err := url.Parse(src)
	if err != nil || u.Scheme != "https" {
		return errors.New("plugins can only be downloaded over https")
	}
	hc := &http.Client{Timeout: 10 * time.Minute}
	resp, err := hc.Get(src)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxPluginDownload+1))
	f.Close()
	if err != nil {
		return err
	}
	if n > maxPluginDownload {
		return errors.New("the plugin download is larger than 512 MB")
	}
	return nil
}

func extractPlugin(zipPath, dst string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("not a zip file: %w", err)
	}
	defer zr.Close()
	if len(zr.File) > maxPluginFiles {
		return errors.New("the plugin has too many files")
	}
	var total uint64
	for _, f := range zr.File {
		name := filepath.FromSlash(f.Name)
		if !filepath.IsLocal(name) {
			return fmt.Errorf("the zip contains an unsafe path %q", f.Name)
		}
		target := filepath.Join(dst, name)
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if f.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("the zip contains a link %q, which is not allowed", f.Name)
		}
		total += f.UncompressedSize64
		if total > 2<<30 {
			return errors.New("the plugin unpacks to more than 2 GB")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if f.Mode()&0o111 != 0 {
			mode = 0o755
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, io.LimitReader(rc, int64(f.UncompressedSize64)+1))
		rc.Close()
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func copyTree(src, dst string) error {
	count := 0
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return os.MkdirAll(target, 0o755)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		count++
		if count > maxPluginFiles {
			return errors.New("the plugin folder has too many files")
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm()|0o600)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, in)
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		return err
	})
}

func findManifestDir(root string) (string, error) {
	if _, err := os.Stat(filepath.Join(root, "plugin.json")); err == nil {
		return root, nil
	}
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		if e.IsDir() {
			if _, err := os.Stat(filepath.Join(root, e.Name(), "plugin.json")); err == nil {
				return filepath.Join(root, e.Name()), nil
			}
		}
	}
	return "", errors.New("no plugin.json found; a plugin needs a plugin.json describing it")
}

func installPlugin(a *args, c *client, src string) error {
	stage, err := os.MkdirTemp(filepath.Join(dataDir(a)), ".plugin-install-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	unpack := filepath.Join(stage, "files")
	switch {
	case strings.HasPrefix(src, "https://") || strings.HasPrefix(src, "http://"):
		zipPath := filepath.Join(stage, "plugin.zip")
		fmt.Println("Downloading", src)
		if err := downloadPlugin(src, zipPath); err != nil {
			return err
		}
		if err := extractPlugin(zipPath, unpack); err != nil {
			return err
		}
	default:
		info, err := os.Stat(src)
		if err != nil {
			return err
		}
		if info.IsDir() {
			if err := copyTree(src, unpack); err != nil {
				return err
			}
		} else if err := extractPlugin(src, unpack); err != nil {
			return err
		}
	}
	root, err := findManifestDir(unpack)
	if err != nil {
		return err
	}
	m, err := server.ReadPluginManifest(root)
	if err != nil {
		return err
	}
	name := firstNonEmpty(a.val("name"), m.Name)
	command := m.CommandFor(runtime.GOOS)
	if command == "" {
		return fmt.Errorf("plugin.json has no command for %s", runtime.GOOS)
	}
	dest := filepath.Join(dataDir(a), "plugin-apps", name)
	p := server.PluginConfig{Name: name, Command: command, Args: m.Args, Admin: m.Admin, Groups: m.Groups, Enabled: !a.on("disabled")}
	var existing []server.PluginStatus
	if err := c.call("GET", "/api/server-plugins", nil, &existing); err == nil {
		for _, e := range existing {
			if strings.EqualFold(e.Name, name) && e.Dir != "" {
				fmt.Printf("Upgrading %s.\n", name)
			}
		}
	}
	var cur server.Config
	if err := c.call("GET", "/api/settings", nil, &cur); err == nil {
		for _, e := range cur.Plugins {
			if strings.EqualFold(e.Name, name) {
				p.Settings = e.Settings
				p.Env = e.Env
			}
		}
	}
	if err := validateName(name); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	old := dest + ".old"
	os.RemoveAll(old)
	if _, err := os.Stat(dest); err == nil {
		if err := os.Rename(dest, old); err != nil {
			return fmt.Errorf("could not replace the installed plugin (stop it first with golangtak plugin disable %s): %w", name, err)
		}
	}
	if err := os.Rename(root, dest); err != nil {
		os.Rename(old, dest)
		return err
	}
	os.RemoveAll(old)
	p.Dir = dest
	if !filepath.IsAbs(command) {
		p.Command = filepath.Join(dest, filepath.FromSlash(command))
		if _, err := os.Stat(p.Command); err != nil {
			p.Command = command
		} else if runtime.GOOS != "windows" {
			os.Chmod(p.Command, 0o755)
		}
	}
	if err := c.call("PUT", "/api/server-plugins/"+url.PathEscape(name), p, nil); err != nil {
		return err
	}
	ver := ""
	if m.Version != "" {
		ver = " " + m.Version
	}
	fmt.Printf("Installed %s%s in %s.\n", name, ver, dest)
	if len(m.Settings) > 0 {
		fmt.Println("Change its settings in the dashboard under Plugins and profiles, or with: golangtak plugin settings " + name + " KEY=VALUE")
	}
	return nil
}

func validateName(name string) error {
	return server.ValidatePluginName(name)
}
