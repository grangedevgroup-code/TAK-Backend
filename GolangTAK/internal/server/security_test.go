package server

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
)

func identifySA(t *testing.T, s *Server, c *Client, uid string) {
	t.Helper()
	e, err := cot.Parse([]byte(saXML(uid, "CS-"+uid, 1, 1)))
	if err != nil {
		t.Fatal(err)
	}
	s.hub.Identify(c, NewMessage(e, c, c.Identity().Out))
}

func TestUIDCannotBeTakenFromAnotherUser(t *testing.T) {
	s := newTestServer(t, nil)
	s.dir.AddUser("alice", "alice-password", false, nil)
	s.dir.AddUser("bob", "bob-password", false, nil)
	aliceID, _ := s.dir.Identity("alice", "test")
	bobID, _ := s.dir.Identity("bob", "test")
	alice := s.hub.NewClient(KindTLS, "10.0.0.1:1", aliceID)
	bob := s.hub.NewClient(KindTLS, "10.0.0.2:1", bobID)
	anon := s.hub.NewClient(KindTCP, "10.0.0.3:1", s.dir.Anonymous())
	defer s.hub.Remove(alice)
	defer s.hub.Remove(bob)
	defer s.hub.Remove(anon)

	identifySA(t, s, alice, "ANDROID-alice")
	if s.hub.ByUID("ANDROID-alice") != alice {
		t.Fatal("alice does not own her uid")
	}
	identifySA(t, s, bob, "ANDROID-alice")
	identifySA(t, s, anon, "ANDROID-alice")
	if s.hub.ByUID("ANDROID-alice") != alice {
		t.Fatal("another user took over alice's uid")
	}

	again := s.hub.NewClient(KindTLS, "10.0.0.1:2", aliceID)
	defer s.hub.Remove(again)
	identifySA(t, s, again, "ANDROID-alice")
	if s.hub.ByUID("ANDROID-alice") != again {
		t.Fatal("alice's reconnecting device could not reclaim her uid")
	}

	other := s.hub.NewClient(KindTCP, "10.0.0.4:1", s.dir.Anonymous())
	defer s.hub.Remove(other)
	identifySA(t, s, anon, "ANDROID-anon")
	identifySA(t, s, other, "ANDROID-anon")
	if s.hub.ByUID("ANDROID-anon") != other {
		t.Fatal("anonymous uid ownership changed behaviour")
	}
}

func TestMissionAuthorizationHoles(t *testing.T) {
	s := newTestServer(t, nil)
	s.dir.AddUser("alice", "alice-password", false, []string{"__ANON__"})
	secret, _, err := s.dir.CreateToken("alice", "api", "test", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	base := "http://127.0.0.1:" + strconv.Itoa(s.Config().Ports.HTTP)
	alice := map[string]string{"Authorization": "Bearer " + secret, "Content-Type": "application/json"}
	anon := map[string]string{"Content-Type": "application/json"}

	if st, b := doReq(t, http.DefaultClient, "PUT", base+"/Marti/api/missions/ops?creatorUid=ANDROID-alice&group=__ANON__", nil, alice); st >= 300 {
		t.Fatalf("create mission: %d %s", st, b)
	}
	if st, _ := doReq(t, http.DefaultClient, "DELETE", base+"/Marti/api/missions/ops?creatorUid=ANDROID-alice", nil, anon); st != http.StatusForbidden {
		t.Fatalf("anonymous caller impersonating the owner's device deleted the mission: %d", st)
	}
	if _, ok := s.missions.Get("ops"); !ok {
		t.Fatal("mission ops is gone")
	}
	if st, b := doReq(t, http.DefaultClient, "DELETE", base+"/Marti/api/missions/ops?creatorUid=ANDROID-alice", nil, alice); st >= 300 {
		t.Fatalf("the real owner could not delete the mission: %d %s", st, b)
	}

	if st, b := doReq(t, http.DefaultClient, "POST", base+"/api/missions", strings.NewReader(`{"name":"ro","groups":["__ANON__"],"defaultRole":"MISSION_READONLY_SUBSCRIBER"}`), alice); st >= 300 {
		t.Fatalf("create read-only mission: %d %s", st, b)
	}
	if st, _ := doReq(t, http.DefaultClient, "POST", base+"/Marti/api/missions/logs/entries", strings.NewReader(`{"content":"forged","missionNames":["ro"]}`), anon); st != http.StatusForbidden {
		t.Fatalf("a read-only caller wrote a mission log entry: %d", st)
	}
	if st, _ := doReq(t, http.DefaultClient, "POST", base+"/Marti/api/citrap/attachment?missionName=ro&filename=x.txt", strings.NewReader("data"), map[string]string{"Content-Type": "text/plain"}); st != http.StatusForbidden {
		t.Fatalf("a read-only caller attached a file to the mission: %d", st)
	}
	m, _ := s.missions.Get("ro")
	if len(m.Contents) != 0 || len(m.Logs) != 0 {
		t.Fatalf("read-only mission was changed: %d contents, %d logs", len(m.Contents), len(m.Logs))
	}
}

func TestOfflineDevicesStayInTheirGroups(t *testing.T) {
	s := newTestServer(t, nil)
	s.dir.AddUser("carol", "carol-password", false, []string{"Red"})
	id, _ := s.dir.Identity("carol", "test")
	c := s.hub.NewClient(KindTLS, "10.0.0.9:1", id)
	identifySA(t, s, c, "ANDROID-carol")
	s.devices.Seen(c, "Disconnected")
	s.hub.Remove(c)
	base := "http://127.0.0.1:" + strconv.Itoa(s.Config().Ports.HTTP)
	st, body := doReq(t, http.DefaultClient, "GET", base+"/Marti/api/clientEndPoints", nil, nil)
	if st != 200 {
		t.Fatalf("client endpoints: %d %s", st, body)
	}
	if strings.Contains(string(body), "ANDROID-carol") {
		t.Fatal("an anonymous caller saw an offline device from another group")
	}
}
