package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
)

func TestADSBEventMapping(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	cases := []struct {
		in       string
		uid, typ string
		callsign string
		remark   string
		hae      float64
	}{
		{`{"hex":"a1b2c3","flight":"UAL123  ","r":"N12345","t":"B738","alt_baro":35000,"alt_geom":35500,"gs":450,"track":90,"lat":40.7,"lon":-74.0,"squawk":"1200","category":"A3"}`, "ICAO-A1B2C3", "a-n-A-C-F", "UAL123", "Type B738", 35500 * feetToMeters},
		{`{"hex":"ae1234","r":"12-3456","alt_baro":"ground","lat":38.8,"lon":-77.0,"category":"A7","dbFlags":1}`, "ICAO-AE1234", "a-n-A-M-H", "12-3456", "Military", 0},
		{`{"hex":"~2d0001","flight":"","alt_baro":1200,"lat":1,"lon":2,"squawk":"7700","emergency":"general"}`, "ICAO-2D0001", "a-n-A-C-F", "2D0001", "EMERGENCY GENERAL", 1200 * feetToMeters},
	}
	for _, c := range cases {
		var a adsbAircraft
		if err := json.Unmarshal([]byte(c.in), &a); err != nil {
			t.Fatal(err)
		}
		e := adsbEvent(a, time.Minute)
		if e == nil {
			t.Fatalf("%s: no event", c.uid)
		}
		if e.UID != c.uid || e.Type != c.typ || e.Callsign() != c.callsign {
			t.Fatalf("got %s %s %s", e.UID, e.Type, e.Callsign())
		}
		if !strings.Contains(e.Remarks(), c.remark) {
			t.Fatalf("%s remarks %q", c.uid, e.Remarks())
		}
		if d := e.Point.Hae - c.hae; d > 0.01 || d < -0.01 {
			t.Fatalf("%s hae %v want %v", c.uid, e.Point.Hae, c.hae)
		}
		if _, err := cot.Parse(e.XML()); err != nil {
			t.Fatalf("%s does not round trip: %v", c.uid, err)
		}
	}
	if adsbEvent(adsbAircraft{Hex: "abc"}, time.Minute) != nil {
		t.Fatal("aircraft without a position produced an event")
	}
	if adsbEvent(adsbAircraft{Hex: "abc", Lat: f(1), Lon: f(1), SeenPos: f(120)}, time.Minute) != nil {
		t.Fatal("old position produced an event")
	}
	var a adsbAircraft
	json.Unmarshal([]byte(`{"hex":"abcdef","lat":1,"lon":2,"gs":100,"track":45}`), &a)
	e := adsbEvent(a, time.Minute)
	tr := e.D("track")
	if tr == nil || tr.Attr("course") != "45.0" || !strings.HasPrefix(tr.Attr("speed"), "51.44") {
		t.Fatalf("track %v", e)
	}
}

func TestAISEventMapping(t *testing.T) {
	var v map[string]any
	json.Unmarshal([]byte(`{"MMSI":366999712,"TIME":"2026-10-07 20:00:00 GMT","LONGITUDE":-122.4,"LATITUDE":37.8,"COG":271.5,"SOG":12.3,"HEADING":270,"NAVSTAT":0,"IMO":9301234,"NAME":"PACIFIC TRADER@@","CALLSIGN":"WDC1234","TYPE":71,"DEST":"OAKLAND"}`), &v)
	e := aisEvent(v, time.Hour)
	if e == nil || e.UID != "MMSI-366999712" || e.Type != "a-n-S-X-M-C" || e.Callsign() != "PACIFIC TRADER" {
		t.Fatalf("event %v", e)
	}
	if !strings.Contains(e.Remarks(), "IMO 9301234") || !strings.Contains(e.Remarks(), "Destination OAKLAND") {
		t.Fatalf("remarks %q", e.Remarks())
	}
	if tr := e.D("track"); tr == nil || tr.Attr("course") != "271.5" {
		t.Fatalf("track %v", e)
	}
	json.Unmarshal([]byte(`{"MMSI":123,"LONGITUDE":0,"LATITUDE":0}`), &v)
	if aisEvent(v, time.Hour) != nil {
		t.Fatal("vessel without a position produced an event")
	}
	for typ, want := range map[int]string{30: "a-n-S-X-F", 35: "a-n-S-C", 37: "a-n-S-X-R", 60: "a-n-S-X-M-P", 84: "a-n-S-X-M-O", 0: "a-n-S-X"} {
		if got := aisShipType(typ); got != want {
			t.Fatalf("ship type %d: %s", typ, got)
		}
	}
}

func TestADSBFeedPublishes(t *testing.T) {
	var hits atomic.Int32
	var gotPath, gotKey atomic.Value
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		gotPath.Store(r.URL.Path)
		gotKey.Store(r.Header.Get("api-auth"))
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ac":[{"hex":"c0ffee","flight":"TEST1","lat":45.5,"lon":-73.5,"alt_geom":1000,"gs":120,"track":10}],"msg":"No error"}`))
	}))
	defer fake.Close()
	s := newTestServer(t, func(c *Config) {
		c.Feeds.ADSB = ADSBFeed{Enabled: true, URL: fake.URL + "/v2/point", APIKey: "k1", Lat: 45.5, Lon: -73.5, RadiusNM: 10, IntervalSec: 5}
	})
	cl := dialTCP(t, s)
	cl.send(saXML("ANDROID-feed", "FEED", 45, -73))
	e := cl.expect(uidIs("ICAO-C0FFEE"), "aircraft from the ADS-B feed")
	if e.Callsign() != "TEST1" {
		t.Fatalf("callsign %q", e.Callsign())
	}
	if p, _ := gotPath.Load().(string); p != "/v2/point/45.50000/-73.50000/10" {
		t.Fatalf("request path %q", p)
	}
	if k, _ := gotKey.Load().(string); k != "k1" {
		t.Fatalf("api key header %q", k)
	}
	st := s.feedStatus()
	if len(st) == 0 || st[0].Name != "adsb" || st[0].Items != 1 || st[0].Error != "" {
		t.Fatalf("status %+v", st)
	}
	time.Sleep(300 * time.Millisecond)
	if s.history.Written.Load() > 0 {
		for _, ev := range s.history.Query(historyQuery{UID: "ICAO-C0FFEE"}) {
			t.Fatalf("feed event stored in history: %s", ev.UID)
		}
	}
	if _, err := s.UpdateConfig(func(c *Config) error {
		c.Feeds.ADSB.Enabled = false
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	n := hits.Load()
	time.Sleep(6 * time.Second)
	if hits.Load() != n {
		t.Fatal("feed kept polling after it was disabled")
	}
}
