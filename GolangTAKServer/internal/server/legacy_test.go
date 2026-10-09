package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrateLegacyData(t *testing.T) {
	base := t.TempDir()
	oldDir := filepath.Join(base, "GolangTAK")
	newDir := filepath.Join(base, "GolangTAKServer")
	os.MkdirAll(filepath.Join(oldDir, "links"), 0o700)
	os.MkdirAll(filepath.Join(oldDir, "logs"), 0o700)
	cert := filepath.Join(oldDir, "links", "peer.pem")
	os.WriteFile(cert, []byte("x"), 0o600)
	os.WriteFile(filepath.Join(oldDir, "logs", "golangtak.log"), []byte("log"), 0o600)
	os.WriteFile(filepath.Join(oldDir, "golangtak.lock"), nil, 0o600)
	cfg, _ := json.Marshal(map[string]any{"peers": []map[string]string{{"name": "peer", "certFile": cert, "trustFile": oldDir + "/links/ca.pem"}}, "data": oldDir, "other": oldDir + "Extra"})
	os.WriteFile(ConfigPath(oldDir), cfg, 0o600)

	moved, err := MigrateLegacyData(oldDir, newDir)
	if err != nil || !moved {
		t.Fatalf("moved=%v err=%v", moved, err)
	}
	if _, err := os.Stat(oldDir); !os.IsNotExist(err) {
		t.Fatalf("old directory still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(newDir, "logs", "golangtakserver.log")); err != nil {
		t.Fatalf("log not renamed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(newDir, "golangtak.lock")); !os.IsNotExist(err) {
		t.Fatal("old lock file kept")
	}
	b, _ := os.ReadFile(ConfigPath(newDir))
	var got struct {
		Peers []map[string]string `json:"peers"`
		Data  string              `json:"data"`
		Other string              `json:"other"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Peers[0]["certFile"] != filepath.Join(newDir, "links", "peer.pem") || got.Peers[0]["trustFile"] != newDir+"/links/ca.pem" || got.Data != newDir {
		t.Fatalf("paths not rewritten: %s", b)
	}
	if got.Other != oldDir+"Extra" {
		t.Fatalf("unrelated path changed: %s", got.Other)
	}

	if moved, _ := MigrateLegacyData(oldDir, newDir); moved {
		t.Fatal("migrated twice")
	}
	os.MkdirAll(oldDir, 0o700)
	os.WriteFile(ConfigPath(oldDir), []byte("{}"), 0o600)
	if moved, _ := MigrateLegacyData(oldDir, newDir); moved {
		t.Fatal("overwrote an existing data directory")
	}
}

func TestLegacyCompat(t *testing.T) {
	if rest, ok := trimLinkPrefix("golangtak-link:abc"); !ok || rest != "abc" {
		t.Fatal("old link code prefix rejected")
	}
	if rest, ok := trimLinkPrefix(linkCodePrefix + "abc"); !ok || rest != "abc" {
		t.Fatal("link code prefix rejected")
	}
	if _, ok := trimLinkPrefix("other:abc"); ok {
		t.Fatal("unknown prefix accepted")
	}
	env := withLegacyEnv([]string{"GOLANGTAKSERVER_TOKEN=t", "PATH=x"})
	if !strings.Contains(strings.Join(env, " "), "GOLANGTAK_TOKEN=t") || len(env) != 3 {
		t.Fatalf("legacy env: %v", env)
	}
	if !isSelfTest("golangtak-selftest") || !isSelfTest(SelfTestUser) || isSelfTest("alice") {
		t.Fatal("self-test user check")
	}
}
