package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
)

func joinedNode(t *testing.T, code string) *Server {
	t.Helper()
	body := strings.TrimPrefix(code, clusterCodePrefix)
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatal(err)
	}
	var cc clusterCode
	json.Unmarshal(raw, &cc)
	dir := t.TempDir()
	os.MkdirAll(certDir(dir), 0o700)
	os.WriteFile(filepath.Join(certDir(dir), "ca.pem"), []byte(cc.CA), 0o644)
	os.WriteFile(filepath.Join(certDir(dir), "ca.key"), []byte(cc.CAKey), 0o600)
	return newTestServerIn(t, dir, func(c *Config) {
		c.Cluster = ClusterConfig{Enabled: true, Secret: cc.Secret, Dial: []string{cc.URL}}
	})
}

func waitCluster(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !fn() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func syncedLinks(s *Server) int {
	n := 0
	s.cluster.mu.Lock()
	defer s.cluster.mu.Unlock()
	for _, l := range s.cluster.links {
		if l.synced.Load() {
			n++
		}
	}
	return n
}

func TestClusterReplicationAndTraffic(t *testing.T) {
	a := newTestServer(t, nil)
	a.dir.AddUser("before-join", "before-join-pw", false, []string{"Blue"})
	code, err := a.ClusterInvite()
	if err != nil {
		t.Fatal(err)
	}
	b := joinedNode(t, code)
	defer func() {
		if t.Failed() {
			sa, _ := json.Marshal(a.ClusterStatus())
			sb, _ := json.Marshal(b.ClusterStatus())
			t.Logf("a %s b %s", sa, sb)
		}
	}()
	waitCluster(t, "a and b to sync", func() bool { return syncedLinks(a) == 1 && syncedLinks(b) == 1 })

	if _, ok := b.dir.User("before-join"); !ok {
		t.Fatal("existing user not copied to the new node")
	}
	a.dir.AddUser("after-join", "after-join-pw", false, []string{"Blue"})
	waitCluster(t, "new user on b", func() bool { _, ok := b.dir.User("after-join"); return ok })
	if _, err := b.dir.CheckPassword("127.0.0.1", "after-join", "after-join-pw"); err != nil {
		t.Fatalf("password does not work on the other node: %v", err)
	}
	b.dir.EnsureGroup("Purple", "made on b", false)
	waitCluster(t, "group on a", func() bool { _, ok := a.dir.Group("Purple"); return ok })

	onA := dialTCP(t, a)
	onA.send(saXML("node-a-device", "ALPHA", 10, 10))
	onB := dialTCP(t, b)
	onB.send(saXML("node-b-device", "BRAVO", 11, 11))
	onB.expect(uidIs("node-a-device"), "position from the other node")
	onA.expect(uidIs("node-b-device"), "position from the other node")

	waitCluster(t, "b presence on a", func() bool { return a.clusterHas("node-b-device") })
	onA.send(chatXML("node-a-device", "ALPHA", "BRAVO", "node-b-device", "hello across the cluster"))
	onB.expect(func(e *cot.Event) bool { return e.IsChat() }, "private chat across nodes")
	time.Sleep(300 * time.Millisecond)
	if n := len(a.PendingChats()) + len(b.PendingChats()); n != 0 {
		t.Fatalf("chat to an online device was stored for later: %d", n)
	}

	content := "cluster file " + time.Now().String()
	hash := uploadPackage(t, a, "shared", []byte(content), "node-a-device")
	waitCluster(t, "file on b", func() bool {
		st, body := doReq(t, http.DefaultClient, "GET", plainURL(b, "/Marti/sync/content?hash="+hash), nil, nil)
		return st == 200 && string(body) == content
	})

	base := plainURL(a, "/Marti/api/missions/cluster-op")
	if st, body := doReq(t, http.DefaultClient, "PUT", base+"?creatorUid=node-a-device", nil, nil); st >= 300 {
		t.Fatalf("create mission: %d %s", st, body)
	}
	waitCluster(t, "mission on b", func() bool { _, ok := b.missions.Get("cluster-op"); return ok })
	if st, body := doReq(t, http.DefaultClient, "PUT", plainURL(b, "/Marti/api/missions/cluster-op/subscription?uid=node-b-device"), nil, nil); st >= 300 {
		t.Fatalf("subscribe on b: %d %s", st, body)
	}
	waitCluster(t, "subscription on a", func() bool {
		m, _ := a.missions.Get("cluster-op")
		return m.sub("node-b-device") != nil
	})
	marker := cot.New("cluster-mission-marker", "a-h-G", "h-e", 10*time.Minute)
	marker.Point = cot.Point{Lat: 1, Lon: 2, Ce: 1, Le: 1}
	marker.SetDests([]cot.Dest{{Mission: "cluster-op"}})
	onA.send(marker.String())
	onB.expect(uidIs("cluster-mission-marker"), "mission item for a subscriber on the other node")
	waitCluster(t, "mission item replicated", func() bool {
		m, _ := b.missions.Get("cluster-op")
		return m.item("cluster-mission-marker") != nil
	})
	time.Sleep(500 * time.Millisecond)
	m, _ := a.missions.Get("cluster-op")
	adds := 0
	for _, c := range m.Changes {
		if c.Type == "ADD_CONTENT" && c.ContentUID == "cluster-mission-marker" {
			adds++
		}
	}
	if adds != 1 {
		t.Fatalf("mission change recorded %d times", adds)
	}

	a.dir.DeleteUser("after-join")
	waitCluster(t, "user deleted on b", func() bool { _, ok := b.dir.User("after-join"); return !ok })

	code2, err := b.ClusterInvite()
	if err != nil {
		t.Fatal(err)
	}
	c := joinedNode(t, code2)
	waitCluster(t, "c linked to both nodes", func() bool { return syncedLinks(c) == 2 && syncedLinks(a) == 2 })
	if _, ok := c.dir.Group("Purple"); !ok {
		t.Fatal("third node missing data")
	}
	onC := dialTCP(t, c)
	onC.send(saXML("node-c-device", "CHARLIE", 12, 12))
	onA.expect(uidIs("node-c-device"), "position from the third node")
	onB.expect(uidIs("node-c-device"), "position from the third node")

	st, body := doReq(t, http.DefaultClient, "GET", plainURL(a, "/api/cluster"), nil, adminToken(t, a))
	if st != 200 || strings.Count(string(body), `"state":"connected"`) != 2 {
		t.Fatalf("cluster status: %d %s", st, body)
	}
}

func TestClusterRejectsWrongSecret(t *testing.T) {
	a := newTestServer(t, nil)
	a.ClusterInvite()
	req, _ := http.NewRequest("GET", plainURL(a, "/api/cluster/blob/"+strings.Repeat("a", 64)), nil)
	req.Header.Set("Authorization", "Cluster wrong")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong secret: %d", resp.StatusCode)
	}
}
