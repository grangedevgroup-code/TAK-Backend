package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/pkg/plugin"
)

func webHelper() {
	p, err := plugin.Load()
	if err != nil {
		fmt.Println("helper error", err)
		os.Exit(2)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		u, ok := plugin.UserOf(r)
		fmt.Fprintf(w, "%s %s %v cookie=%q auth=%q", p.Setting("greeting", "?"), u.Name, ok, r.Header.Get("Cookie"), r.Header.Get("Authorization"))
	})
	mux.HandleFunc("/public/info", func(w http.ResponseWriter, r *http.Request) {
		_, ok := plugin.UserOf(r)
		fmt.Fprintf(w, "public signed-in=%v", ok)
	})
	p.Serve(context.Background(), mux)
}

func TestPluginWebPagesAndSettings(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "plugin.json"), []byte(`{"name":"web","version":"2.0.0","description":"test pages","command":"x","http":true,"public":true,"page":"Test page",
"settings":[{"key":"greeting","label":"Greeting","type":"text","default":"hello"},{"key":"apikey","label":"Key","type":"secret"},{"key":"mode","label":"Mode","type":"select","options":["a","b"]}]}`), 0o600)
	s := newTestServer(t, func(c *Config) {
		c.Plugins = []PluginConfig{{Name: "web", Command: exe, Args: []string{"-test.run=^TestPluginHelperProcess$"}, Dir: dir, Enabled: true, Env: map[string]string{"GOLANGTAKSERVER_TEST_HELPER": "web"}}}
	})
	s.dir.AddUser("viewer", "viewer-password", false, nil)
	tok, _, _ := s.dir.CreateToken("viewer", "api", "t", time.Hour, 0)
	auth := map[string]string{"Authorization": "Bearer " + tok, "Cookie": "golangtakserver_session=secret"}
	adminAuth := adminToken(t, s)

	var body []byte
	waitFor(t, "the plugin page", 20*time.Second, func() bool {
		var st int
		st, body = doReq(t, http.DefaultClient, "GET", plainURL(s, "/plugins/web/hello"), nil, auth)
		return st == 200
	})
	if got := string(body); got != `hello viewer true cookie="" auth=""` {
		t.Fatalf("page: %s", got)
	}
	if st, _ := doReq(t, http.DefaultClient, "GET", plainURL(s, "/plugins/web/hello"), nil, nil); st == 200 {
		t.Fatal("plugin page served without signing in")
	}
	st, body := doReq(t, http.DefaultClient, "GET", plainURL(s, "/plugins/web/public/info"), nil, nil)
	if st != 200 || string(body) != "public signed-in=false" {
		t.Fatalf("public page: %d %s", st, body)
	}
	st, body = doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/plugin-pages"), nil, auth)
	if st != 200 || !strings.Contains(string(body), `"page":"Test page"`) {
		t.Fatalf("plugin pages: %d %s", st, body)
	}

	if st, _ := doReq(t, http.DefaultClient, "PUT", plainURL(s, "/api/server-plugins/web/settings"), strings.NewReader(`{"mode":"c"}`), adminAuth); st != http.StatusBadRequest {
		t.Fatal("invalid select option accepted")
	}
	if st, _ := doReq(t, http.DefaultClient, "PUT", plainURL(s, "/api/server-plugins/web/settings"), strings.NewReader(`{"unknown":"x"}`), adminAuth); st != http.StatusBadRequest {
		t.Fatal("unknown setting accepted")
	}
	if st, b := doReq(t, http.DefaultClient, "PUT", plainURL(s, "/api/server-plugins/web/settings"), strings.NewReader(`{"greeting":"howdy","apikey":"s3cret","mode":"b"}`), adminAuth); st != 200 {
		t.Fatalf("settings: %d %s", st, b)
	}
	waitFor(t, "the plugin to restart with new settings", 20*time.Second, func() bool {
		_, body = doReq(t, http.DefaultClient, "GET", plainURL(s, "/plugins/web/hello"), nil, auth)
		return strings.HasPrefix(string(body), "howdy ")
	})
	_, body = doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/server-plugins"), nil, adminAuth)
	var list []PluginStatus
	json.Unmarshal(body, &list)
	if len(list) != 1 || list[0].Version != "2.0.0" || list[0].Settings["apikey"] != secretMask || list[0].URL != "/plugins/web/" {
		t.Fatalf("status: %s", body)
	}
	if st, _ := doReq(t, http.DefaultClient, "PUT", plainURL(s, "/api/server-plugins/web/settings"), strings.NewReader(`{"apikey":"********","greeting":"yo"}`), adminAuth); st != 200 {
		t.Fatal("second settings save")
	}
	for _, p := range s.Config().Plugins {
		if p.Settings["apikey"] != "s3cret" {
			t.Fatalf("masked secret overwrote the value: %v", p.Settings)
		}
	}
}
