package main

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/server"
)

func TestTailscaleStatusNames(t *testing.T) {
	raw := `{"BackendState":"Running","Self":{"HostName":"tak","DNSName":"tak.example-tailnet.ts.net.","TailscaleIPs":["100.101.102.103","fd7a:115c:a1e0::1","bad"]},"CurrentTailnet":{"Name":"example"}}`
	var st tsStatus
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		t.Fatal(err)
	}
	got := tsNames(st)
	want := []string{"100.101.102.103", "fd7a:115c:a1e0::1", "tak.example-tailnet.ts.net"}
	if !slices.Equal(got, want) {
		t.Fatalf("names %v, want %v", got, want)
	}
	if s := tsShown([]string{"up", "--authkey=tskey-auth-secret"}); strings.Contains(s, "secret") {
		t.Fatalf("auth key shown: %s", s)
	}
}

func TestRunSettingsFromEnvironment(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	t.Setenv("GOLANGTAKSERVER_ADDRESS", "tak.example.org")
	t.Setenv("GOLANGTAKSERVER_NAME", "Field")
	t.Setenv("GOLANGTAKSERVER_ADMIN_PASSWORD", "container-password")
	if err := applyRunSettings(&args{}, dir); err != nil {
		t.Fatal(err)
	}
	cfg, err := server.LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Address != "tak.example.org" || cfg.Name != "Field" || runAdminPassword != "container-password" {
		t.Fatalf("address %q name %q password %q", cfg.Address, cfg.Name, runAdminPassword)
	}
}
