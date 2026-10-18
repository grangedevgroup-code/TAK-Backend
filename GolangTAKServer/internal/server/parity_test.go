package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

func adminHeaders(t *testing.T, s *Server) map[string]string {
	t.Helper()
	if _, ok := s.dir.User("boss"); !ok {
		if _, err := s.dir.AddUser("boss", "boss-password", true, nil); err != nil {
			t.Fatal(err)
		}
	}
	tok, _, err := s.dir.CreateToken("boss", "api", "t", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{"Authorization": "Bearer " + tok, "Content-Type": "application/json"}
}

func TestParityMissionRouteFixes(t *testing.T) {
	s := newTestServer(t, nil)
	a := adminHeaders(t, s)
	do := func(method, path, body string) (int, string) {
		t.Helper()
		st, b := doReq(t, http.DefaultClient, method, plainURL(s, path), strings.NewReader(body), a)
		return st, string(b)
	}
	for _, name := range []string{"parent1", "child1"} {
		if st, b := do("PUT", "/Marti/api/missions/"+name+"?creatorUid=ANDROID-a", ""); st >= 300 {
			t.Fatalf("create %s: %d %s", name, st, b)
		}
	}
	p, _ := s.missions.Get("parent1")
	c, _ := s.missions.Get("child1")
	if st, b := do("PUT", "/Marti/api/missions/guid/"+c.GUID+"/parent/guid/"+p.GUID, ""); st != 200 {
		t.Fatalf("set parent by guid: %d %s", st, b)
	}
	if c, _ = s.missions.Get("child1"); c.Parent != "parent1" {
		t.Fatalf("parent not set: %q", c.Parent)
	}

	do("POST", "/Marti/api/missions/child1/externaldata?creatorUid=ANDROID-a", `{"id":"ext1","name":"one","url":"https://a"}`)
	do("POST", "/Marti/api/missions/child1/externaldata?creatorUid=ANDROID-a", `{"id":"ext1","name":"two","url":"https://b"}`)
	if c, _ = s.missions.Get("child1"); len(c.ExternalData) != 1 || c.ExternalData[0]["name"] != "two" {
		t.Fatalf("external data not upserted: %v", c.ExternalData)
	}
	before := len(c.ExternalData)
	if st, b := do("POST", "/Marti/api/missions/child1/externaldata/ext1/change?creatorUid=ANDROID-a&notes=updated", "updated"); st != 200 {
		t.Fatalf("external data change: %d %s", st, b)
	}
	if c, _ = s.missions.Get("child1"); len(c.ExternalData) != before {
		t.Fatal("change notice added external data")
	}
	if st, _ := do("POST", "/Marti/api/missions/child1/externaldata/missing/change", ""); st != 404 {
		t.Fatalf("change on missing external data: %d", st)
	}

	if st, b := do("PUT", "/Marti/api/missions/child1/subscription?uid=ANDROID-b", ""); st >= 300 {
		t.Fatalf("subscribe: %d %s", st, b)
	}
	if st, b := do("POST", "/Marti/api/missions/child1/subscription?creatorUid=ANDROID-a", `[{"clientUid":"ANDROID-b","role":{"type":"MISSION_READONLY_SUBSCRIBER"}}]`); st != 200 {
		t.Fatalf("set subscription role: %d %s", st, b)
	}
	c, _ = s.missions.Get("child1")
	if sub := c.sub("ANDROID-b"); sub == nil || sub.Role != RoleReadOnly {
		t.Fatalf("role not changed: %+v", sub)
	}

	if st, b := do("POST", "/Marti/api/citrap/nope/attachment?clientUid=ANDROID-a", "data"); st != 404 || !strings.Contains(b, "report not found") {
		t.Fatalf("citrap attachment route: %d %s", st, b)
	}
}

func TestParityActiveGroups(t *testing.T) {
	s := newTestServer(t, nil)
	a := adminHeaders(t, s)
	if _, err := s.dir.AddUser("field", "field-password", false, []string{"Blue", "Red"}); err != nil {
		t.Fatal(err)
	}
	tok, _, _ := s.dir.CreateToken("field", "api", "t", time.Hour, 0)
	u := map[string]string{"Authorization": "Bearer " + tok, "Content-Type": "application/json"}
	blue, _ := s.dir.Group("Blue")
	st, b := doReq(t, http.DefaultClient, "PUT", plainURL(s, "/Marti/api/groups/activebits?clientUid=ANDROID-f"), strings.NewReader("["+itoa(blue.Bit)+"]"), u)
	if st != 200 {
		t.Fatalf("activebits: %d %s", st, b)
	}
	usr, _ := s.dir.User("field")
	if !slices.Contains(usr.Inactive, "Red|"+DirIn) || slices.Contains(usr.Inactive, "Blue|"+DirIn) {
		t.Fatalf("activebits not applied: %v", usr.Inactive)
	}
	body, _ := json.Marshal([]activeGroup{{Name: "Red", Direction: DirIn, Active: true}})
	if st, b := doReq(t, http.DefaultClient, "PUT", plainURL(s, "/Marti/api/groups/activeForce?username=field"), strings.NewReader(string(body)), u); st != http.StatusForbidden {
		t.Fatalf("non-admin forced groups: %d %s", st, b)
	}
	if st, b := doReq(t, http.DefaultClient, "PUT", plainURL(s, "/Marti/api/groups/activeForce?username=field"), strings.NewReader(string(body)), a); st != 200 {
		t.Fatalf("activeForce: %d %s", st, b)
	}
	if usr, _ = s.dir.User("field"); slices.Contains(usr.Inactive, "Red|"+DirIn) {
		t.Fatalf("activeForce not applied: %v", usr.Inactive)
	}
	if st, b := doReq(t, http.DefaultClient, "POST", plainURL(s, "/Marti/api/groups/update"), strings.NewReader(`["field"]`), a); st != 200 {
		t.Fatalf("bulk update: %d %s", st, b)
	}
	if st, _ := doReq(t, http.DefaultClient, "POST", plainURL(s, "/Marti/TracksKML"), strings.NewReader(""), a); st != 200 {
		t.Fatalf("TracksKML POST: %d", st)
	}
}
