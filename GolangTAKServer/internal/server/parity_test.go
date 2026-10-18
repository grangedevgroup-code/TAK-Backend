package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"image/png"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/takproto"
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

func zipNames(t *testing.T, data []byte) []string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("not a zip: %v", err)
	}
	var out []string
	for _, f := range zr.File {
		out = append(out, f.Name)
	}
	return out
}

func TestParityDeviceProfiles(t *testing.T) {
	s := newTestServer(t, nil)
	a := adminHeaders(t, s)
	do := func(method, path, body string) (int, []byte) {
		t.Helper()
		return doReq(t, http.DefaultClient, method, plainURL(s, path), strings.NewReader(body), a)
	}
	if st, b := do("POST", "/Marti/api/device/profile/field-kit", ""); st != 200 {
		t.Fatalf("create: %d %s", st, b)
	}
	if st, b := do("PUT", "/Marti/api/device/profile/field-kit/file?filename=team.pref", "<preferences/>"); st != 200 {
		t.Fatalf("add file: %d %s", st, b)
	}
	st, b := do("GET", "/Marti/api/device/profile/field-kit/files", "")
	if st != 200 || !strings.Contains(string(b), `"team.pref"`) {
		t.Fatalf("files: %d %s", st, b)
	}
	os.MkdirAll(filepath.Join(s.DataDir, "profiles", "maps"), 0o700)
	os.WriteFile(filepath.Join(s.DataDir, "profiles", "maps", "area.kml"), []byte("<kml/>"), 0o600)
	if st, b := do("GET", "/Marti/api/device/profile/directories", ""); st != 200 || !strings.Contains(string(b), `"maps"`) {
		t.Fatalf("valid directories: %d %s", st, b)
	}
	if st, b := do("PUT", "/Marti/api/device/profile/field-kit/directories/maps", ""); st != 200 {
		t.Fatalf("set directories: %d %s", st, b)
	}
	if st, b := do("PUT", "/Marti/api/device/profile/field-kit/directories/..", ""); st != 400 {
		t.Fatalf("traversal accepted: %d %s", st, b)
	}
	st, b = do("GET", "/Marti/api/device/profile/field-kit/missionpackage", "")
	if names := zipNames(t, b); st != 200 || !slices.Contains(names, "team.pref") || !slices.Contains(names, "maps/area.kml") {
		t.Fatalf("mission package: %d %v", st, names)
	}
	st, b = do("GET", "/Marti/api/device/profile/connection?clientUid=x&syncSecago=0", "")
	if st != 200 || !slices.Contains(zipNames(t, b), "profile-"+s.shortID()+"/team.pref") {
		t.Fatalf("connection profile missing named profile: %d", st)
	}
	if st, b := do("PUT", "/Marti/api/device/profile/field-kit", `{"type":"Tool","tool":"medic","applyOnConnect":false}`); st != 200 {
		t.Fatalf("update: %d %s", st, b)
	}
	st, b = do("GET", "/Marti/api/device/profile/tool/medic?clientUid=x", "")
	if st != 200 || !slices.Contains(zipNames(t, b), "profile-medic/team.pref") {
		t.Fatalf("tool profile: %d", st)
	}
	st, b = do("GET", "/Marti/api/device/profile/tool/medic/file?relativePath=maps/area.kml", "")
	if names := zipNames(t, b); st != 200 || len(names) != 2 || !slices.Contains(names, "maps/area.kml") {
		t.Fatalf("tool file: %d %v", st, names)
	}
	if st, _ := do("DELETE", "/Marti/api/device/profile/field-kit", ""); st != 200 {
		t.Fatalf("delete: %d", st)
	}
	if st, _ := do("GET", "/Marti/api/device/profile/field-kit", ""); st != 404 {
		t.Fatalf("still there: %d", st)
	}
}

func TestParityDataFeedCRUD(t *testing.T) {
	s := newTestServer(t, nil)
	a := adminHeaders(t, s)
	do := func(method, path, body string) (int, string) {
		t.Helper()
		st, b := doReq(t, http.DefaultClient, method, plainURL(s, path), strings.NewReader(body), a)
		return st, string(b)
	}
	port := freeUDPPort(t)
	if st, b := do("POST", "/Marti/api/datafeeds", `{"name":"sensors","protocol":"udp","port":`+itoa(port)+`,"tag":["wx"],"filtergroup":[],"sync":true}`); st != 200 || !strings.Contains(b, `"sensors"`) {
		t.Fatalf("create: %d %s", st, b)
	}
	if st, _ := do("POST", "/Marti/api/datafeeds", `{"name":"sensors","protocol":"udp","port":1}`); st != 400 {
		t.Fatalf("duplicate accepted: %d", st)
	}
	conn, err := net.Dial("udp", "127.0.0.1:"+itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var b string
	for time.Now().Before(deadline) {
		conn.Write([]byte(saXML("WX-1", "WX", 2, 3)))
		time.Sleep(150 * time.Millisecond)
		if _, b = do("GET", "/Marti/api/datafeeds/sensors", ""); strings.Contains(b, `"messages":`) && !strings.Contains(b, `"messages":0`) {
			break
		}
	}
	conn.Close()
	if !strings.Contains(b, `"messages":`) || strings.Contains(b, `"messages":0`) {
		t.Fatalf("live feed received nothing: %s", b)
	}
	port2 := freeUDPPort(t)
	if st, b := do("PUT", "/Marti/api/datafeeds/sensors", `{"port":`+itoa(port2)+`}`); st != 200 || !strings.Contains(b, `"port":`+itoa(port2)) {
		t.Fatalf("modify: %d %s", st, b)
	}
	if st, _ := do("DELETE", "/Marti/api/datafeeds/sensors", ""); st != 200 {
		t.Fatalf("delete: %d", st)
	}
	if st, _ := do("GET", "/Marti/api/datafeeds/sensors", ""); st != 404 {
		t.Fatalf("still there: %d", st)
	}
	if st, b := do("POST", "/Marti/api/datafeeds/predicate", `{"uuid":"p1","name":"hostiles","predicateLang":"cql","dataSourceEndpoint":"https://example.org/feed","predicate":"type LIKE 'a-h-%'"}`); st != 200 {
		t.Fatalf("predicate create: %d %s", st, b)
	}
	if _, b := do("GET", "/Marti/api/datafeeds", ""); !strings.Contains(b, `"Predicate"`) || !strings.Contains(b, `"predicateLang":"cql"`) {
		t.Fatalf("predicate feed not listed: %s", b)
	}
	if st, _ := do("DELETE", "/Marti/api/datafeeds/predicate/p1", ""); st != 200 {
		t.Fatalf("predicate delete: %d", st)
	}
}

func dialPort(t *testing.T, port int) *testClient {
	t.Helper()
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+itoa(port), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &testClient{t: t, conn: c, r: takproto.NewReader(c, 1<<22)}
}

func TestParityInputsWithFilterGroups(t *testing.T) {
	s := newTestServer(t, nil)
	a := adminHeaders(t, s)
	port := freePort(t)
	st, b := doReq(t, http.DefaultClient, "POST", plainURL(s, "/Marti/api/inputs"), strings.NewReader(`{"name":"bravo","protocol":"stcp","port":`+itoa(port)+`,"auth":"anonymous","filtergroup":["Bravo"]}`), a)
	if st != 200 {
		t.Fatalf("create input: %d %s", st, b)
	}
	b1 := dialPort(t, port)
	b2 := dialPort(t, port)
	main := dialTCP(t, s)
	b1.send(saXML("B-1", "BRAVO1", 1, 1))
	b2.send(saXML("B-2", "BRAVO2", 1, 1))
	main.send(saXML("M-1", "MAIN1", 1, 1))
	b2.expect(func(e *cot.Event) bool { return e.UID == "B-1" }, "bravo member sees bravo traffic")
	main.expectNone(func(e *cot.Event) bool { return e.UID == "B-1" || e.UID == "B-2" }, "anonymous group must not see bravo traffic", 700*time.Millisecond)
	b1.expectNone(func(e *cot.Event) bool { return e.UID == "M-1" }, "bravo must not see anonymous traffic", 300*time.Millisecond)
	st, b = doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/inputs/bravo"), nil, a)
	if st != 200 || !strings.Contains(string(b), `"numClients":2`) || !strings.Contains(string(b), `"Bravo"`) {
		t.Fatalf("input metrics: %d %s", st, b)
	}
	if st, _ := doReq(t, http.DefaultClient, "DELETE", plainURL(s, "/Marti/api/inputs/bravo"), nil, a); st != 200 {
		t.Fatalf("delete input: %d", st)
	}
	time.Sleep(200 * time.Millisecond)
	if c, err := net.DialTimeout("tcp", "127.0.0.1:"+itoa(port), time.Second); err == nil {
		c.Close()
		t.Fatal("input still listening after delete")
	}
}

func TestParityIconsets(t *testing.T) {
	s := newTestServer(t, nil)
	a := adminHeaders(t, s)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create("iconset.xml")
	f.Write([]byte(`<iconset version="1" name="Fire" uid="fire-icons" skipResize="false" default_friendly="Fire/engine.png"/>`))
	f, _ = zw.Create("Fire/engine.png")
	png.Encode(f, renderTypeIcon("a-f-G", "", "", false))
	zw.Close()
	if st, b := doReq(t, http.DefaultClient, "POST", plainURL(s, "/Marti/api/iconset"), bytes.NewReader(buf.Bytes()), map[string]string{"Authorization": a["Authorization"], "Content-Type": "application/zip"}); st != 200 {
		t.Fatalf("upload: %d %s", st, b)
	}
	if _, b := doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/iconset/all/uid"), nil, a); !strings.Contains(string(b), "fire-icons") {
		t.Fatalf("uids: %s", b)
	}
	_, b := doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/iconseturl/fire-icons"), nil, a)
	if !strings.Contains(string(b), "/Marti/api/icon/fire-icons/Fire/engine.png") {
		t.Fatalf("urls: %s", b)
	}
	if st, b := doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/icon/fire-icons/Fire/engine.png"), nil, a); st != 200 || !bytes.HasPrefix(b, []byte("\x89PNG")) {
		t.Fatalf("icon: %d", st)
	}
	if st, b := doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/iconimage?cotType=a-h-G&medevac=true"), nil, a); st != 200 || !bytes.HasPrefix(b, []byte("\x89PNG")) {
		t.Fatalf("type icon: %d", st)
	}
	if _, b := doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/iconurl?iconsetpath=fire-icons/Fire/engine.png"), nil, a); !strings.HasSuffix(string(b), "/Marti/api/icon/fire-icons/Fire/engine.png") {
		t.Fatalf("iconurl: %s", b)
	}
}
