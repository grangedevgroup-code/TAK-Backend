package server

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fed2Pair(t *testing.T, tweak func(c *Config)) (*Server, *Server) {
	t.Helper()
	a := newTestServer(t, func(c *Config) {
		c.Federation.Enabled = true
		if tweak != nil {
			tweak(c)
		}
	})
	b := newTestServer(t, func(c *Config) {
		c.Federation.Enabled = true
		c.Ports.FederationV2 = freePort(t)
		if tweak != nil {
			tweak(c)
		}
	})
	if _, err := b.UpdateConfig(func(c *Config) error {
		c.Federation.TrustPEM = []string{string(a.pki.CA.CertPEM)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	trust := filepath.Join(t.TempDir(), "b-ca.pem")
	if err := os.WriteFile(trust, b.pki.CA.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	addPeer(t, a, PeerConfig{Name: "fed2-b", URL: "fed2://127.0.0.1:" + strconv.Itoa(b.Config().Ports.FederationV2), Enabled: true, Direction: "both", TrustFile: trust})
	waitPeer(t, a, "fed2-b")
	return a, b
}

func TestFederationV2BothWays(t *testing.T) {
	a, b := fed2Pair(t, nil)
	checkBothWays(t, a, b, "fed2")
	waitFor(t, "the inbound v2 federate to be listed", 5*time.Second, func() bool {
		for _, f := range b.fed.clients() {
			if f.version == "v2" && f.dir == "inbound" {
				return true
			}
		}
		return false
	})
}

func missionBody(t *testing.T, s *Server, name string) string {
	t.Helper()
	st, body := doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/missions/"+name+"?logs=true"), nil, nil)
	if st != 200 {
		return ""
	}
	return string(body)
}

func TestFederationV2Missions(t *testing.T) {
	a, b := fed2Pair(t, func(c *Config) { c.Federation.AllowDelete = true })
	base := plainURL(a, "/Marti/api/missions/fedops")
	if st, body := doReq(t, http.DefaultClient, "PUT", base+"?creatorUid=ANDROID-a&tool=public&description=Shared", nil, nil); st >= 300 {
		t.Fatalf("create: %d %s", st, body)
	}
	waitFor(t, "the mission to reach the other server", 10*time.Second, func() bool {
		return strings.Contains(missionBody(t, b, "fedops"), "Shared")
	})
	content := []byte("federated mission file " + time.Now().String())
	hash := uploadPackage(t, a, "plan.txt", content, "ANDROID-a")
	if st, body := doReq(t, http.DefaultClient, "PUT", base+"/contents?creatorUid=ANDROID-a", strings.NewReader(`{"hashes":["`+hash+`"]}`), map[string]string{"Content-Type": "application/json"}); st >= 300 {
		t.Fatalf("add contents: %d %s", st, body)
	}
	if st, body := doReq(t, http.DefaultClient, "POST", plainURL(a, "/Marti/api/missions/logs/entries"), strings.NewReader(`{"missionNames":["fedops"],"content":"federated log line","creatorUid":"ANDROID-a"}`), map[string]string{"Content-Type": "application/json"}); st >= 300 {
		t.Fatalf("log: %d %s", st, body)
	}
	waitFor(t, "the file and log to reach the other server", 10*time.Second, func() bool {
		body := missionBody(t, b, "fedops")
		return strings.Contains(body, hash) && strings.Contains(body, "federated log line")
	})
	st, got := doReq(t, http.DefaultClient, "GET", plainURL(b, "/Marti/sync/content?hash="+hash), nil, nil)
	if st != 200 || string(got) != string(content) {
		t.Fatalf("federated file download: %d %q", st, got)
	}

	if st, body := doReq(t, http.DefaultClient, "PUT", plainURL(b, "/Marti/api/missions/backops?creatorUid=ANDROID-b&tool=public&description=FromB"), nil, nil); st >= 300 {
		t.Fatalf("create on b: %d %s", st, body)
	}
	waitFor(t, "a mission made on the listening server to reach the linking server", 10*time.Second, func() bool {
		return strings.Contains(missionBody(t, a, "backops"), "FromB")
	})
	if strings.Contains(missionBody(t, b, "fedops"), "fedops") && strings.Count(missionBody(t, b, "fedops"), "federated log line") != 1 {
		t.Fatal("log entry was duplicated by a federation loop")
	}

	if st, body := doReq(t, http.DefaultClient, "DELETE", base+"?creatorUid=ANDROID-a", nil, nil); st >= 300 {
		t.Fatalf("delete: %d %s", st, body)
	}
	waitFor(t, "the mission delete to reach the other server", 10*time.Second, func() bool {
		return missionBody(t, b, "fedops") == ""
	})
}

func TestFederationV2MissionSnapshot(t *testing.T) {
	a := newTestServer(t, func(c *Config) { c.Federation.Enabled = true })
	if st, body := doReq(t, http.DefaultClient, "PUT", plainURL(a, "/Marti/api/missions/early?creatorUid=ANDROID-a&tool=public&description=BeforeLink"), nil, nil); st >= 300 {
		t.Fatalf("create: %d %s", st, body)
	}
	b := newTestServer(t, func(c *Config) {
		c.Federation.Enabled = true
		c.Ports.FederationV2 = freePort(t)
	})
	b.UpdateConfig(func(c *Config) error {
		c.Federation.TrustPEM = []string{string(a.pki.CA.CertPEM)}
		return nil
	})
	trust := filepath.Join(t.TempDir(), "b-ca.pem")
	os.WriteFile(trust, b.pki.CA.CertPEM, 0o600)
	addPeer(t, a, PeerConfig{Name: "fed2-b", URL: "fed2://127.0.0.1:" + strconv.Itoa(b.Config().Ports.FederationV2), Enabled: true, Direction: "both", TrustFile: trust})
	waitFor(t, "missions that existed before the link to be shared", 10*time.Second, func() bool {
		return strings.Contains(missionBody(t, b, "early"), "BeforeLink")
	})
}

func TestParseROL(t *testing.T) {
	op, res, params := parseROL("create mission\n{\"name\":\"x\"};")
	if op != "create" || res != "mission" || string(params) != `{"name":"x"}` {
		t.Fatalf("got %q %q %q", op, res, params)
	}
	op, res, params = parseROL("delete data_feed {\"uuid\":\"1\"}")
	if op != "delete" || res != "data_feed" || string(params) != `{"uuid":"1"}` {
		t.Fatalf("got %q %q %q", op, res, params)
	}
}
