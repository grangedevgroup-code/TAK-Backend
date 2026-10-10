package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/flock"
)

const (
	legacyName           = "GolangTAK"
	legacyDataEnv        = "GOLANGTAK_DATA"
	legacyLinkCodePrefix = "golangtak-link:"
	legacyOAuthAudience  = "golangtak"
	legacySelfTestUser   = "golangtak-selftest"
)

func DataEnv() string {
	if v := os.Getenv("GOLANGTAKSERVER_DATA"); v != "" {
		return v
	}
	return os.Getenv(legacyDataEnv)
}

func LegacySystemDataDir() string {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, legacyName)
	case "darwin":
		return "/Library/Application Support/" + legacyName
	case "android", "ios", "plan9", "js", "wasip1":
		return ""
	}
	return "/var/lib/golangtak"
}

func legacyUserDataDir() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return filepath.Join(h, ".golangtak")
	}
	return "golangtak-data"
}

func isSelfTest(name string) bool { return name == SelfTestUser || name == legacySelfTestUser }

var ErrLegacyInUse = errors.New("the old GolangTAK data directory is still in use")

func MigrateLegacyData(oldDir, newDir string) (bool, error) {
	if oldDir == "" || newDir == "" || oldDir == newDir {
		return false, nil
	}
	if _, err := os.Stat(ConfigPath(oldDir)); err != nil {
		return false, nil
	}
	if _, err := os.Stat(newDir); err == nil {
		return false, nil
	}
	oldLock := filepath.Join(oldDir, "golangtak.lock")
	l, err := flock.Acquire(oldLock)
	if err != nil {
		return false, ErrLegacyInUse
	}
	l.Release()
	os.Remove(oldLock)
	if err := os.MkdirAll(filepath.Dir(newDir), 0o755); err != nil {
		return false, err
	}
	if err := os.Rename(oldDir, newDir); err != nil {
		return false, err
	}
	os.Rename(filepath.Join(newDir, "logs", "golangtak.log"), filepath.Join(newDir, "logs", "golangtakserver.log"))
	rewriteDataPaths(newDir, oldDir, newDir)
	return true, nil
}

func MigrateLegacyUserData() {
	if os.Getenv("GOLANGTAKSERVER_DATA") != "" || os.Getenv(legacyDataEnv) != "" {
		return
	}
	MigrateLegacyData(legacyUserDataDir(), userDataDir())
}

func rewriteDataPaths(root, oldDir, newDir string) {
	esc := func(s string) []byte {
		b, _ := json.Marshal(s)
		return b[1 : len(b)-1]
	}
	oldEsc, newEsc := esc(oldDir), esc(newDir)
	sepEsc := esc(string(filepath.Separator))
	slashEsc := esc("/")
	pairs := [][2][]byte{
		{append(append([]byte{}, oldEsc...), sepEsc...), append(append([]byte{}, newEsc...), sepEsc...)},
		{append(append([]byte{}, oldEsc...), slashEsc...), append(append([]byte{}, newEsc...), slashEsc...)},
		{append(append([]byte{}, oldEsc...), '"'), append(append([]byte{}, newEsc...), '"')},
	}
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case "blobs", "recordings", "logs", "video", "media":
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".json" && ext != ".jsonl" {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 64<<20 {
			return nil
		}
		b, err := os.ReadFile(p) // #nosec G122 -- walks the server's own data directory during the rename migration
		if err != nil || !bytes.Contains(b, oldEsc) {
			return nil
		}
		out := b
		for _, pr := range pairs {
			out = bytes.ReplaceAll(out, pr[0], pr[1])
		}
		if !bytes.Equal(out, b) {
			writeFileAtomic(p, out, info.Mode().Perm())
		}
		return nil
	})
}

func withLegacyEnv(env []string) []string {
	out := env
	for _, kv := range env {
		if rest, ok := strings.CutPrefix(kv, "GOLANGTAKSERVER_"); ok {
			out = append(out, "GOLANGTAK_"+rest)
		}
	}
	return out
}

func trimLinkPrefix(code string) (string, bool) {
	if rest, ok := strings.CutPrefix(code, linkCodePrefix); ok {
		return rest, true
	}
	return strings.CutPrefix(code, legacyLinkCodePrefix)
}
