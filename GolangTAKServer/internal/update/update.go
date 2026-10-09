package update

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

const (
	TagPrefix  = "golangtakserver-v"
	DefaultAPI = "https://api.github.com/repos/grangedevgroup-code/TAK-Backend/releases?per_page=50"
)

type Release struct {
	Tag       string    `json:"tag"`
	Version   string    `json:"version"`
	URL       string    `json:"url"`
	Published time.Time `json:"published"`
	Notes     string    `json:"notes,omitempty"`
	assets    map[string]string
}

func APIURL() string {
	if v := os.Getenv("GOLANGTAKSERVER_UPDATE_API"); v != "" {
		return v
	}
	return DefaultAPI
}

func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

func Valid(v string) bool {
	_, ok := parseVersion(v)
	return ok
}

func Newer(candidate, current string) bool {
	a, ok1 := parseVersion(candidate)
	b, ok2 := parseVersion(current)
	if !ok1 || !ok2 {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

func AssetName() string {
	arch := runtime.GOARCH
	if arch == "arm" {
		goarm := "7"
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				if s.Key == "GOARM" && s.Value != "" {
					goarm = strings.TrimSuffix(s.Value, ",softfloat")
				}
			}
		}
		arch = "armv" + goarm
	}
	name := "golangtakserver-" + runtime.GOOS + "-" + arch
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

func get(ctx context.Context, hc *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "GolangTAKServer-updater")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return resp, nil
}

func Latest(ctx context.Context, hc *http.Client) (Release, error) {
	resp, err := get(ctx, hc, APIURL())
	if err != nil {
		return Release{}, err
	}
	defer resp.Body.Close()
	var list []struct {
		Tag        string    `json:"tag_name"`
		Draft      bool      `json:"draft"`
		Prerelease bool      `json:"prerelease"`
		HTMLURL    string    `json:"html_url"`
		Published  time.Time `json:"published_at"`
		Body       string    `json:"body"`
		Assets     []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&list); err != nil {
		return Release{}, fmt.Errorf("reading the release list: %w", err)
	}
	var best Release
	for _, r := range list {
		if r.Draft || r.Prerelease || !strings.HasPrefix(r.Tag, TagPrefix) {
			continue
		}
		v := strings.TrimPrefix(r.Tag, TagPrefix)
		if !Valid(v) || (best.Version != "" && !Newer(v, best.Version)) {
			continue
		}
		rel := Release{Tag: r.Tag, Version: v, URL: r.HTMLURL, Published: r.Published, Notes: r.Body, assets: map[string]string{}}
		for _, a := range r.Assets {
			rel.assets[a.Name] = a.URL
		}
		best = rel
	}
	if best.Version == "" {
		return Release{}, errors.New("no GolangTAKServer release found")
	}
	return best, nil
}

func (r Release) checksum(ctx context.Context, hc *http.Client, asset string) (string, error) {
	u, ok := r.assets["SHA256SUMS"]
	if !ok {
		return "", errors.New("the release has no SHA256SUMS")
	}
	resp, err := get(ctx, hc, u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 1<<20))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == asset {
			return strings.ToLower(f[0]), nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("no checksum published for %s", asset)
}

func (r Release) Install(ctx context.Context, hc *http.Client, target string) error {
	asset := AssetName()
	u, ok := r.assets[asset]
	if !ok {
		return fmt.Errorf("release %s has no build for this system (%s)", r.Version, asset)
	}
	want, err := r.checksum(ctx, hc, asset)
	if err != nil {
		return err
	}
	resp, err := get(ctx, hc, u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	tmp, err := os.CreateTemp(filepath.Dir(target), ".update-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, 512<<20))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(name)
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		os.Remove(name)
		return fmt.Errorf("checksum mismatch for %s", asset)
	}
	if err := os.Chmod(name, 0o755); err != nil {
		os.Remove(name)
		return err
	}
	return Replace(name, target)
}

func Replace(src, target string) error {
	if err := os.Rename(src, target); err == nil {
		return nil
	}
	old := target + ".old"
	os.Remove(old)
	if err := os.Rename(target, old); err != nil {
		os.Remove(src)
		return err
	}
	if err := os.Rename(src, target); err != nil {
		os.Rename(old, target)
		os.Remove(src)
		return err
	}
	return nil
}

func InContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}
	return os.Getenv("container") != ""
}
