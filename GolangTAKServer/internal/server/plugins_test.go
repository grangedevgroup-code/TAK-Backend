package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPluginHelperProcess(t *testing.T) {
	mode := os.Getenv("GOLANGTAKSERVER_TEST_HELPER")
	if mode == "" {
		t.Skip("helper process for the plugin tests")
	}
	if mode == "web" {
		webHelper()
		return
	}
	req, _ := http.NewRequest("GET", os.Getenv("GOLANGTAKSERVER_URL")+"/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+os.Getenv("GOLANGTAKSERVER_TOKEN"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("helper error", err)
		os.Exit(2)
	}
	var me struct {
		User string `json:"user"`
	}
	json.NewDecoder(resp.Body).Decode(&me)
	resp.Body.Close()
	fmt.Println("helper ok", resp.StatusCode, me.User, os.Getenv("GOLANGTAKSERVER_PLUGIN"), os.Getenv("PLUGIN_SETTING"))
	if mode == "crash" {
		os.Exit(3)
	}
	for {
		time.Sleep(time.Hour)
	}
}

func waitFor(t *testing.T, what string, timeout time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func pluginState(s *Server, name string) PluginStatus {
	for _, p := range s.pluginStatusList() {
		if p.Name == name {
			return p
		}
	}
	return PluginStatus{}
}

func pluginLogText(s *Server, name string) string {
	lines, _ := s.plugins.logs(name)
	return strings.Join(lines, "\n")
}

func TestServerPlugins(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := func(name, mode string) PluginConfig {
		return PluginConfig{Name: name, Command: exe, Args: []string{"-test.run=^TestPluginHelperProcess$"}, Enabled: true, Env: map[string]string{"GOLANGTAKSERVER_TEST_HELPER": mode, "PLUGIN_SETTING": "configured"}}
	}
	s := newTestServer(t, func(c *Config) {
		c.Plugins = []PluginConfig{helper("steady", "run"), helper("crashy", "crash")}
	})

	waitFor(t, "the steady plugin to call the API", 20*time.Second, func() bool {
		return strings.Contains(pluginLogText(s, "steady"), "helper ok 200 plugin-steady steady configured")
	})
	if st := pluginState(s, "steady"); st.State != "running" || st.PID == 0 {
		t.Fatalf("steady plugin status %+v", st)
	}
	waitFor(t, "the crashing plugin to be restarted", 20*time.Second, func() bool {
		return pluginState(s, "crashy").Restarts >= 2
	})
	if st := pluginState(s, "crashy"); !strings.Contains(st.LastExit, "status 3") {
		t.Fatalf("crashy last exit %q", st.LastExit)
	}

	s.dir.AddUser("pluginadmin", "plugin-password", true, nil)
	secret, _, err := s.dir.CreateToken("pluginadmin", "api", "test", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	base := "http://127.0.0.1:" + strconv.Itoa(s.Config().Ports.HTTP)
	auth := map[string]string{"Authorization": "Bearer " + secret, "Content-Type": "application/json"}
	body := `{"name":"evil","command":"/bin/sh","args":["-c","id"],"enabled":true}`
	if st, b := doReq(t, http.DefaultClient, "PUT", base+"/api/server-plugins/evil", strings.NewReader(body), auth); st != http.StatusForbidden {
		t.Fatalf("adding a plugin with an API token returned %d %s", st, b)
	}
	st, b, _ := s.LocalRequest("PUT", "/api/server-plugins/third", []byte(`{"name":"third","command":`+strconv.Quote(exe)+`,"args":["-test.run=^TestPluginHelperProcess$"],"env":{"GOLANGTAKSERVER_TEST_HELPER":"run"},"enabled":true}`))
	if st != http.StatusOK {
		t.Fatalf("adding a plugin from the command line returned %d %s", st, b)
	}
	waitFor(t, "the third plugin to start", 20*time.Second, func() bool {
		return strings.Contains(pluginLogText(s, "third"), "helper ok 200 plugin-third third")
	})

	var settings Config
	if st, b := doReq(t, http.DefaultClient, "GET", base+"/api/settings", nil, auth); st != 200 {
		t.Fatalf("settings %d %s", st, b)
	} else if err := json.Unmarshal(b, &settings); err != nil {
		t.Fatal(err)
	}
	for _, p := range settings.Plugins {
		for _, v := range p.Env {
			if v != "********" {
				t.Fatalf("plugin environment leaked in settings: %v", p.Env)
			}
		}
	}
	tamper := `{"plugins":[{"name":"evil","command":"/bin/sh","enabled":true}]}`
	if st, b := doReq(t, http.DefaultClient, "PUT", base+"/api/settings", strings.NewReader(tamper), auth); st != 200 {
		t.Fatalf("settings update %d %s", st, b)
	}
	for _, p := range s.Config().Plugins {
		if p.Name == "evil" {
			t.Fatal("the settings API changed the plugin list")
		}
	}

	pid := pluginState(s, "steady").PID
	if st, b := doReq(t, http.DefaultClient, "POST", base+"/api/server-plugins/steady/restart", nil, auth); st != 200 {
		t.Fatalf("restart %d %s", st, b)
	}
	waitFor(t, "the steady plugin to restart with a new process", 20*time.Second, func() bool {
		st := pluginState(s, "steady")
		return st.State == "running" && st.PID != 0 && st.PID != pid
	})
	if st, b := doReq(t, http.DefaultClient, "POST", base+"/api/server-plugins/steady/disable", nil, auth); st != 200 {
		t.Fatalf("disable %d %s", st, b)
	}
	if st := pluginState(s, "steady"); st.State != "disabled" || st.PID != 0 {
		t.Fatalf("disabled plugin status %+v", st)
	}
	st, b, _ = s.LocalRequest("DELETE", "/api/server-plugins/third", nil)
	if st != http.StatusOK {
		t.Fatalf("delete %d %s", st, b)
	}
	if _, ok := s.dir.User("plugin-third"); ok {
		t.Fatal("the plugin's account was not removed")
	}
	_, logBody := doReq(t, http.DefaultClient, "GET", base+"/api/server-plugins/crashy/logs", nil, auth)
	var lines []string
	json.Unmarshal(logBody, &lines)
	if len(lines) == 0 {
		t.Fatal("no plugin log lines")
	}
	io.Discard.Write(logBody)
}

func TestLinkCodeConnectsServers(t *testing.T) {
	a := newTestServer(t, nil)
	b := newTestServer(t, nil)
	if _, err := a.CreateLinkInvite("", nil); err == nil {
		t.Fatal("an empty link name was accepted")
	}
	inv, err := a.CreateLinkInvite("Partner Team", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(inv.Code, linkCodePrefix) || inv.User != "link-partner-team" {
		t.Fatalf("invite %+v", inv)
	}
	if _, err := b.JoinLink("golangtakserver-link:not-a-code", "", nil); err == nil {
		t.Fatal("a damaged code was accepted")
	}
	p, err := b.JoinLink(inv.Code, "hq", nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "hq" || !strings.HasPrefix(p.URL, "tls://") {
		t.Fatalf("peer %+v", p)
	}
	waitPeer(t, b, "hq")
	checkBothWays(t, a, b, "linkcode")
	waitFor(t, "the link to appear as a server link on the inviting side", 5*time.Second, func() bool {
		for _, c := range a.hub.Clients() {
			if c.Kind == KindPeer && c.Relay && c.Name == "partner-team" {
				return true
			}
		}
		return false
	})
}
