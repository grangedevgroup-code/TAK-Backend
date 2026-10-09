package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
)

func TestTAKExtraEndpoints(t *testing.T) {
	s := newTestServer(t, nil)
	s.dir.AddUser("xadmin", "x-admin-pw", true, nil)
	admin := map[string]string{"basic": "xadmin:x-admin-pw", "Content-Type": "application/json"}
	base := plainURL(s, "/Marti/api")
	get := func(path string, hdr map[string]string) string {
		t.Helper()
		st, b := doReq(t, http.DefaultClient, "GET", path, nil, hdr)
		if st != 200 {
			t.Fatalf("GET %s: %d %s", path, st, b)
		}
		return string(b)
	}

	doReq(t, http.DefaultClient, "PUT", base+"/properties/dev-1", strings.NewReader(`{"color":"red"}`), admin)
	doReq(t, http.DefaultClient, "PUT", base+"/properties/dev-1", strings.NewReader(`{"color":"blue"}`), admin)
	doReq(t, http.DefaultClient, "PUT", base+"/properties/dev-1", strings.NewReader(`{"key":"role","value":"medic"}`), admin)
	if b := get(base+"/properties/dev-1/color", nil); !strings.Contains(b, `["red","blue"]`) {
		t.Fatalf("property values: %s", b)
	}
	if b := get(base+"/properties/dev-1/all", nil); !strings.Contains(b, `"role":["medic"]`) {
		t.Fatalf("all properties: %s", b)
	}
	if b := get(base+"/properties/uids", nil); !strings.Contains(b, "dev-1") {
		t.Fatalf("uids: %s", b)
	}
	doReq(t, http.DefaultClient, "DELETE", base+"/properties/dev-1/color", nil, admin)
	if b := get(base+"/properties/dev-1/all", nil); strings.Contains(b, "color") {
		t.Fatalf("deleted key still there: %s", b)
	}

	if a, b := get(base+"/sync/sequence/k1", nil), get(base+"/sync/sequence/k1", nil); a != "1" || b != "2" {
		t.Fatalf("sequence %q %q", a, b)
	}

	c := dialTCP(t, s)
	c.send(saXML("search-me-1", "SEARCHY", 1, 1))
	time.Sleep(300 * time.Millisecond)
	if b := get(base+"/cot/matchUid?search=search-me", nil); !strings.Contains(b, "search-me-1") {
		t.Fatalf("matchUid: %s", b)
	}
	s.devices.Flush()
	day := time.Now().UTC().Format("2006-01-02")
	if b := get(base+"/uidsearch?startDate="+day+"&endDate="+day, nil); !strings.Contains(b, "SEARCHY") {
		t.Fatalf("uidsearch: %s", b)
	}
	if st, _ := doReq(t, http.DefaultClient, "GET", base+"/uidsearch", nil, nil); st != 400 {
		t.Fatalf("uidsearch without dates: %d", st)
	}
	if b := get(base+"/database/cotCount", admin); !strings.Contains(b, "cotEvents") {
		t.Fatalf("cotCount: %s", b)
	}

	doReq(t, http.DefaultClient, "PUT", base+"/missions/cop-a?creatorUid=x&tool=vbm&path=east/north", nil, nil)
	doReq(t, http.DefaultClient, "PUT", base+"/missions/cop-b?creatorUid=x&tool=vbm&path=east/south", nil, nil)
	doReq(t, http.DefaultClient, "PUT", base+"/missions/plain?creatorUid=x&tool=public", nil, nil)
	if b := get(base+"/cops", nil); !strings.Contains(b, "cop-a") || strings.Contains(b, `"plain"`) {
		t.Fatalf("cops: %s", b)
	}
	if b := get(base+"/cops?path=east/south", nil); strings.Contains(b, "cop-a") || !strings.Contains(b, "cop-b") {
		t.Fatalf("cops by path: %s", b)
	}
	var h struct {
		Data []copNode `json:"data"`
	}
	json.Unmarshal([]byte(get(base+"/cops/hierarchy", nil)), &h)
	if len(h.Data) != 1 || h.Data[0].Name != "east" || len(h.Data[0].Children) != 2 {
		t.Fatalf("hierarchy %+v", h.Data)
	}
	if b := get(base+"/missioncount?tool=vbm", nil); !strings.Contains(b, `"data":2`) {
		t.Fatalf("missioncount: %s", b)
	}

	vbm := `{"vbmEnabled":true,"saDisabled":true,"chatDisabled":false,"networkClassification":"UNCLASSIFIED"}`
	if st, _ := doReq(t, http.DefaultClient, "POST", plainURL(s, "/Marti/vbm/api/config"), strings.NewReader(vbm), admin); st != 200 {
		t.Fatalf("vbm set: %d", st)
	}
	if b := get(plainURL(s, "/Marti/vbm/api/classification"), nil); b != "UNCLASSIFIED" {
		t.Fatalf("classification %q", b)
	}
	other := dialTCP(t, s)
	other.send(saXML("vbm-other", "OTHER", 1, 1))
	c.expectNone(uidIs("vbm-other"), "position while SA sharing is off", 500*time.Millisecond)
	other.send(chatXML("vbm-other", "OTHER", "SEARCHY", "search-me-1", "chat still works"))
	c.expect(func(e *cot.Event) bool { return e.IsChat() }, "chat while only SA sharing is off")
}

func TestToolProfiles(t *testing.T) {
	s := newTestServer(t, nil)
	s.profiles.PutItem(ProfileItem{Kind: "pref", Key: "missionSyncAuto", Class: "Boolean", Value: "true", Tool: "missions"})
	s.profiles.PutItem(ProfileItem{Kind: "pref", Key: "plainPref", Value: "x", Enrollment: true})
	st, body := doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/device/profile/tool/missions?clientUid=x"), nil, nil)
	if st != 200 || !strings.HasPrefix(string(body), "PK") || !strings.Contains(string(body), "missionSyncAuto") && !strings.Contains(string(body), "preference.pref") {
		t.Fatalf("tool profile: %d %q", st, body[:min(len(body), 80)])
	}
	if st, _ := doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/device/profile/tool/other?clientUid=x"), nil, nil); st != http.StatusNoContent {
		t.Fatalf("unknown tool: %d", st)
	}
	for _, e := range s.profileEntries(true, "", 0).prefs {
		if e.Key == "missionSyncAuto" {
			t.Fatal("tool preference leaked into the enrollment profile")
		}
	}
}
