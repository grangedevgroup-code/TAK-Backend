package server

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
)

func feedEvent(uid, typ, callsign string, lat, lon float64) string {
	e := cot.New(uid, typ, "m-g", 5*time.Minute)
	e.Point = cot.Point{Lat: lat, Lon: lon, Ce: 10, Le: 10}
	e.Detail.AddNew("contact", "callsign", callsign)
	return e.String()
}

func feedAdmin(t *testing.T, s *Server) map[string]string {
	t.Helper()
	s.dir.AddUser("feedadmin", "feed-password", true, nil)
	secret, _, err := s.dir.CreateToken("feedadmin", "api", "test", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{"Authorization": "Bearer " + secret}
}

func newFeedServer(t *testing.T) (*Server, int) {
	t.Helper()
	port := freePort(t)
	s := newTestServer(t, func(c *Config) {
		c.DataFeeds = []DataFeedConfig{{UUID: "feed-sensors", Name: "Sensors", Protocol: "tcp", Port: port, Groups: []string{"Sensors"}, Tags: []string{"uas"}, Sync: true, Archive: true, Enabled: true}}
	})
	s.dir.EnsureGroup("Sensors", "", false)
	return s, port
}

func TestDataFeedInput(t *testing.T) {
	s, port := newFeedServer(t)
	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte(feedEvent("UAS-1", "a-h-A-M-F-Q", "Drone", 38.9, -77.0) + feedEvent("SENSOR-2", "a-u-G", "Ground sensor", 39.5, -76.5)))
	waitFor(t, "feed messages to be counted", 5*time.Second, func() bool {
		st := s.dfeeds.state("feed-sensors")
		st.mu.Lock()
		defer st.mu.Unlock()
		return st.count == 2
	})

	admin := feedAdmin(t, s)
	get := func(path string) map[string]any {
		st, body := doReq(t, http.DefaultClient, "GET", plainURL(s, path), nil, admin)
		if st != 200 {
			t.Fatalf("%s: %d %s", path, st, body)
		}
		var out map[string]any
		json.Unmarshal(body, &out)
		return out
	}
	feeds := get("/Marti/api/datafeeds")["data"].([]any)
	var found map[string]any
	for _, f := range feeds {
		if f.(map[string]any)["uuid"] == "feed-sensors" {
			found = f.(map[string]any)
		}
	}
	if found == nil || found["type"] != "Streaming" || found["protocol"] != "tcp" || found["messages"].(float64) != 2 {
		t.Fatalf("datafeeds: %v", feeds)
	}
	types := get("/Marti/api/datafeeds/feed-sensors/cots_types")["data"].([]any)
	if len(types) != 2 {
		t.Fatalf("types: %v", types)
	}
	cots := get("/Marti/api/datafeeds/feed-sensors/cots/a-h")["data"].([]any)
	if len(cots) != 1 || !strings.Contains(cots[0].(string), "UAS-1") {
		t.Fatalf("cots: %v", cots)
	}
	stats := get("/Marti/api/datafeeds/stats/feed-sensors")["data"].(map[string]any)
	if stats["dataFeedNumMessages"].(float64) != 2 || stats["dataFeedMaxLat"].(float64) != 39.5 {
		t.Fatalf("stats: %v", stats)
	}
	bounds := get("/Marti/api/datafeeds/bounds/40,-78,38,-76")["data"].([]any)
	if len(bounds) != 1 || bounds[0] != "feed-sensors" {
		t.Fatalf("bounds: %v", bounds)
	}
	if b := get("/Marti/api/datafeeds/bounds/10,10,0,20")["data"].([]any); len(b) != 0 {
		t.Fatalf("empty bounds: %v", b)
	}
}

func TestMissionFeedDelivery(t *testing.T) {
	s, port := newFeedServer(t)
	sub := dialTCP(t, s)
	sub.send(saXML("ANDROID-sub", "SUB", 1, 1))
	time.Sleep(200 * time.Millisecond)
	base := plainURL(s, "/Marti/api/missions/watch")
	if st, body := doReq(t, http.DefaultClient, "PUT", base+"?creatorUid=ANDROID-sub&tool=public", nil, nil); st >= 300 {
		t.Fatalf("create: %d %s", st, body)
	}
	if st, body := doReq(t, http.DefaultClient, "PUT", base+"/subscription?uid=ANDROID-sub", nil, nil); st >= 300 {
		t.Fatalf("subscribe: %d %s", st, body)
	}
	q := url.Values{"creatorUid": {"ANDROID-sub"}, "dataFeedUid": {"feed-sensors"}, "filterCotTypes": {`["a-h"]`}, "filterPolygon": {"-78,38", "-76,38", "-76,40", "-78,40"}}
	st, body := doReq(t, http.DefaultClient, "POST", base+"/feed?"+q.Encode(), nil, feedAdmin(t, s))
	if st != 200 || !strings.Contains(string(body), `"dataFeedUid":"feed-sensors"`) || !strings.Contains(string(body), `"name":"Sensors"`) {
		t.Fatalf("add feed: %d %s", st, body)
	}
	sub.expect(func(e *cot.Event) bool { return strings.Contains(e.String(), "CREATE_DATA_FEED") }, "data feed change notification")

	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte(feedEvent("UAS-OUT", "a-h-A", "Far away", 10, 10) + feedEvent("FRIEND-IN", "a-f-G", "Friendly", 39, -77) + feedEvent("UAS-IN", "a-h-A", "Inside", 39, -77)))
	sub.expect(func(e *cot.Event) bool { return e.UID == "UAS-IN" }, "matching feed object delivered to the mission subscriber")
	sub.expectNone(func(e *cot.Event) bool { return e.UID == "UAS-OUT" || e.UID == "FRIEND-IN" }, "filtered feed objects", time.Second)

	_, body = doReq(t, http.DefaultClient, "GET", base, nil, nil)
	var env struct {
		Data []struct {
			Feeds []map[string]any `json:"feeds"`
		} `json:"data"`
	}
	json.Unmarshal(body, &env)
	if len(env.Data) != 1 || len(env.Data[0].Feeds) != 1 || env.Data[0].Feeds[0]["filterPolygon"] != "-78 38,-76 38,-76 40,-78 40,-78 38" {
		t.Fatalf("mission feeds: %s", body)
	}
	uid := env.Data[0].Feeds[0]["uid"].(string)
	if st, body := doReq(t, http.DefaultClient, "DELETE", base+"/feed/"+uid+"?creatorUid=ANDROID-sub", nil, nil); st != 200 {
		t.Fatalf("remove feed: %d %s", st, body)
	}
	conn.Write([]byte(feedEvent("UAS-LATE", "a-h-A", "Late", 39, -77)))
	sub.expectNone(func(e *cot.Event) bool { return e.UID == "UAS-LATE" }, "feed object after the feed was removed", time.Second)
}

func TestMapLayers(t *testing.T) {
	s := newTestServer(t, nil)
	s.dir.AddUser("mapadmin", "map-password", true, nil)
	secret, _, err := s.dir.CreateToken("mapadmin", "api", "test", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	admin := map[string]string{"Authorization": "Bearer " + secret, "Content-Type": "application/json"}
	layer := `{"name":"Topo","type":"MapTile","url":"https://tile.example.org/{z}/{x}/{y}.png","minZoom":0,"maxZoom":17,"enabled":true,"defaultLayer":true}`
	if st, _ := doReq(t, http.DefaultClient, "POST", plainURL(s, "/Marti/api/maplayers"), strings.NewReader(layer), map[string]string{"Content-Type": "application/json"}); st != http.StatusForbidden && st != http.StatusUnauthorized {
		t.Fatalf("anonymous map layer create returned %d", st)
	}
	st, body := doReq(t, http.DefaultClient, "POST", plainURL(s, "/Marti/api/maplayers"), strings.NewReader(layer), admin)
	var created struct {
		Data MapLayer `json:"data"`
	}
	if st != 200 || json.Unmarshal(body, &created) != nil || created.Data.UID == "" || created.Data.MaxZoom == nil || *created.Data.MaxZoom != 17 {
		t.Fatalf("create: %d %s", st, body)
	}
	if st, _ := doReq(t, http.DefaultClient, "POST", plainURL(s, "/Marti/api/maplayers"), strings.NewReader(`{"name":"Bad","url":"javascript:alert(1)"}`), admin); st != http.StatusBadRequest {
		t.Fatalf("bad url accepted: %d", st)
	}
	st, body = doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/maplayers/all"), nil, nil)
	if st != 200 || !strings.Contains(string(body), "Topo") {
		t.Fatalf("all: %d %s", st, body)
	}
	created.Data.Name = "Topo 2"
	upd, _ := json.Marshal(created.Data)
	if st, body := doReq(t, http.DefaultClient, "PUT", plainURL(s, "/Marti/api/maplayers"), strings.NewReader(string(upd)), admin); st != 200 || !strings.Contains(string(body), "Topo 2") {
		t.Fatalf("update: %d %s", st, body)
	}
	if st, _ := doReq(t, http.DefaultClient, "DELETE", plainURL(s, "/Marti/api/maplayers/"+created.Data.UID), nil, admin); st != 200 {
		t.Fatalf("delete: %d", st)
	}

	base := plainURL(s, "/Marti/api/missions/layered")
	doReq(t, http.DefaultClient, "PUT", base+"?creatorUid=ANDROID-x&tool=public", nil, nil)
	st, body = doReq(t, http.DefaultClient, "POST", base+"/maplayers?creatorUid=ANDROID-x", strings.NewReader(`{"name":"Imagery","type":"WMS","url":"https://wms.example.org/wms","layers":"0"}`), map[string]string{"Content-Type": "application/json"})
	if st != 200 || json.Unmarshal(body, &created) != nil {
		t.Fatalf("mission layer: %d %s", st, body)
	}
	_, body = doReq(t, http.DefaultClient, "GET", base, nil, nil)
	if !strings.Contains(string(body), `"mapLayers":[{`) || !strings.Contains(string(body), "Imagery") {
		t.Fatalf("mission json: %s", body)
	}
	if st, _ := doReq(t, http.DefaultClient, "DELETE", base+"/maplayers/"+created.Data.UID+"?creatorUid=ANDROID-x", nil, nil); st != 200 {
		t.Fatalf("mission layer delete: %d", st)
	}
	_, body = doReq(t, http.DefaultClient, "GET", base+"/changes", nil, nil)
	if strings.Count(string(body), created.Data.UID) < 2 {
		t.Fatalf("map layer changes missing: %s", body)
	}
}

func TestFederationV2FeedsAndLayers(t *testing.T) {
	a, b := fed2Pair(t, func(c *Config) { c.Federation.AllowDelete = true })
	base := plainURL(a, "/Marti/api/missions/fedlayers")
	doReq(t, http.DefaultClient, "PUT", base+"?creatorUid=ANDROID-a&tool=public", nil, nil)
	waitFor(t, "mission on the other server", 10*time.Second, func() bool { return missionBody(t, b, "fedlayers") != "" })
	doReq(t, http.DefaultClient, "POST", base+"/maplayers?creatorUid=ANDROID-a", strings.NewReader(`{"uid":"layer-1","name":"Shared imagery","url":"https://tiles.example.org/{z}/{x}/{y}.png"}`), map[string]string{"Content-Type": "application/json"})
	q := url.Values{"creatorUid": {"ANDROID-a"}, "dataFeedUid": {FeedADSB}, "uid": {"mf-1"}}
	if st, body := doReq(t, http.DefaultClient, "POST", base+"/feed?"+q.Encode(), nil, nil); st != 200 {
		t.Fatalf("feed: %d %s", st, body)
	}
	waitFor(t, "map layer and feed on the other server", 10*time.Second, func() bool {
		body := missionBody(t, b, "fedlayers")
		return strings.Contains(body, "Shared imagery") && strings.Contains(body, `"uid":"mf-1"`)
	})
	doReq(t, http.DefaultClient, "DELETE", base+"/maplayers/layer-1?creatorUid=ANDROID-a", nil, nil)
	waitFor(t, "map layer removal on the other server", 10*time.Second, func() bool {
		return !strings.Contains(missionBody(t, b, "fedlayers"), "Shared imagery")
	})
}
