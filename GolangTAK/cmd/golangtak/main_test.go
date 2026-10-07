package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/server"
)

func TestParseArgs(t *testing.T) {
	a, err := parseArgs([]string{"add", "bob", "--admin", "--groups", "Red,Blue", "--password=s3cret-pass", "--data", "/tmp/x", "-5"}, []string{"groups", "password"}, []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a.pos, []string{"add", "bob", "-5"}) {
		t.Fatalf("positionals %v", a.pos)
	}
	if !a.on("admin") || a.val("groups") != "Red,Blue" || a.val("password") != "s3cret-pass" || a.val("data") != "/tmp/x" {
		t.Fatalf("flags %+v %+v", a.vals, a.flags)
	}
	if _, err := parseArgs([]string{"--nope"}, nil, nil); err == nil {
		t.Fatal("unknown option accepted")
	}
	if _, err := parseArgs([]string{"--groups"}, []string{"groups"}, nil); err == nil {
		t.Fatal("missing value accepted")
	}
	if a, err := parseArgs([]string{"--admin=false", "--", "--literal"}, nil, []string{"admin"}); err != nil || a.on("admin") || a.arg(0) != "--literal" {
		t.Fatalf("%v %+v", err, a)
	}
}

func TestCommandAliases(t *testing.T) {
	for alias, want := range map[string]string{"users": "user", "setup": "install", "serve": "run", "log": "logs", "certs": "cert", "settings": "config"} {
		c := findCommand(alias)
		if c == nil || c.name != want {
			t.Fatalf("%s -> %v", alias, c)
		}
	}
	if findCommand("bogus") != nil {
		t.Fatal("unknown command resolved")
	}
}

func TestConfigPatch(t *testing.T) {
	var cfg map[string]any
	b, _ := json.Marshal(server.DefaultConfig())
	json.Unmarshal(b, &cfg)
	cases := []struct {
		key, raw, want string
	}{
		{"ports.tls", "9443", `{"ports":{"tls":9443}}`},
		{"Ports.WebSocket", "0", `{"ports":{"websocket":0}}`},
		{"name", "1234", `{"name":"1234"}`},
		{"allowAnonymous", "false", `{"allowAnonymous":false}`},
		{"extraNames", "tak.example.org, 10.0.0.5", `{"extraNames":["tak.example.org","10.0.0.5"]}`},
		{"mesh.groups", `["239.2.3.1:6969"]`, `{"mesh":{"groups":["239.2.3.1:6969"]}}`},
	}
	for _, c := range cases {
		p, err := patchFor(cfg, c.key, c.raw)
		if err != nil {
			t.Fatalf("%s: %v", c.key, err)
		}
		got, _ := json.Marshal(p)
		if string(got) != c.want {
			t.Fatalf("%s: got %s want %s", c.key, got, c.want)
		}
	}
	if _, err := patchFor(cfg, "ports.nope", "1"); err == nil {
		t.Fatal("unknown key accepted")
	}
	if _, err := patchFor(cfg, "ports.tls", "abc"); err == nil {
		t.Fatal("non-number accepted for a port")
	}
	if _, err := patchFor(cfg, "protobuf", "maybe"); err == nil {
		t.Fatal("non-boolean accepted")
	}
	merged := map[string]any{}
	for _, kv := range [][2]string{{"ports.tls", "1"}, {"ports.tcp", "2"}} {
		p, _ := patchFor(cfg, kv[0], kv[1])
		merge(merged, p)
	}
	got, _ := json.Marshal(merged)
	if string(got) != `{"ports":{"tcp":2,"tls":1}}` {
		t.Fatalf("merge: %s", got)
	}
}

func TestFirewallRules(t *testing.T) {
	cfg := server.DefaultConfig()
	got := strings.Join(ruleStrings(firewallRules(cfg)), " ")
	for _, want := range []string{"8087/tcp", "8088/tcp", "8089/tcp", "8080/tcp", "8443/tcp", "8446/tcp", "8090/tcp", "19023/tcp", "8087/udp", "6969/udp", "17012/udp"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
	if strings.Contains(got, "9000/tcp") {
		t.Fatal("federation port opened while federation is off")
	}
	cfg.Federation.Enabled = true
	cfg.Ports.Federation = 9000
	if !strings.Contains(strings.Join(ruleStrings(firewallRules(cfg)), " "), "9000/tcp") {
		t.Fatal("federation port not opened")
	}
	if r := parseRules(ruleStrings(firewallRules(cfg))); len(r) != len(firewallRules(cfg)) {
		t.Fatal("rules do not round trip")
	}
}
