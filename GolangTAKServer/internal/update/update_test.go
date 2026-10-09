package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.6.0", "1.5.0", true}, {"1.5.1", "1.5.0", true}, {"2.0.0", "1.19.19", true},
		{"1.5.0", "1.5.0", false}, {"1.4.9", "1.5.0", false}, {"1.10.0", "1.9.0", true},
		{"1.6.0", "dev", false}, {"x", "1.0.0", false},
	}
	for _, c := range cases {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func fakeReleases(t *testing.T, binary []byte, badSum bool) *httptest.Server {
	asset := AssetName()
	sum := sha256.Sum256(binary)
	sumHex := hex.EncodeToString(sum[:])
	if badSum {
		sumHex = hex.EncodeToString(make([]byte, 32))
	}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/releases":
			list := []map[string]any{
				{"tag_name": "rusttak-v9.0.0", "assets": []any{}},
				{"tag_name": "golangtakserver-v1.7.0", "prerelease": true, "assets": []any{}},
				{"tag_name": "golangtakserver-v1.6.0", "html_url": "https://example.org/1.6.0", "assets": []map[string]string{
					{"name": asset, "browser_download_url": srv.URL + "/bin"},
					{"name": "SHA256SUMS", "browser_download_url": srv.URL + "/sums"},
				}},
				{"tag_name": "golangtakserver-v1.5.0", "assets": []any{}},
			}
			json.NewEncoder(w).Encode(list)
		case "/bin":
			w.Write(binary)
		case "/sums":
			fmt.Fprintf(w, "%s  golangtakserver-other\n%s  %s\n", hex.EncodeToString(make([]byte, 32)), sumHex, asset)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("GOLANGTAKSERVER_UPDATE_API", srv.URL+"/releases")
	return srv
}

func TestLatestAndInstall(t *testing.T) {
	binary := []byte("new program build")
	fakeReleases(t, binary, false)
	rel, err := Latest(context.Background(), http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	if rel.Version != "1.6.0" || rel.URL != "https://example.org/1.6.0" {
		t.Fatalf("picked %+v", rel)
	}
	target := filepath.Join(t.TempDir(), "golangtakserver")
	os.WriteFile(target, []byte("old program"), 0o755)
	if err := rel.Install(context.Background(), http.DefaultClient, target); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != string(binary) {
		t.Fatalf("installed %q", got)
	}
}

func TestInstallRejectsBadChecksum(t *testing.T) {
	fakeReleases(t, []byte("tampered"), true)
	rel, err := Latest(context.Background(), http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "golangtakserver")
	os.WriteFile(target, []byte("old program"), 0o755)
	if err := rel.Install(context.Background(), http.DefaultClient, target); err == nil {
		t.Fatal("tampered download installed")
	}
	got, _ := os.ReadFile(target)
	if string(got) != "old program" {
		t.Fatal("old program was replaced")
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".update-*"))
	if len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}
