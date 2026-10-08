package server

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
)

func TestAISNMEADecode(t *testing.T) {
	d := newAISDecoder()
	v := d.Line("!AIVDM,1,1,,A,15RTgt0PAso;90TKcjM8h6g208CQ,0*4A")
	if v == nil {
		t.Fatal("position report not decoded")
	}
	near := func(k string, want float64) {
		got, _ := v[k].(float64)
		if math.Abs(got-want) > 1e-4 {
			t.Errorf("%s = %v, want %v", k, got, want)
		}
	}
	near("MMSI", 371798000)
	near("LATITUDE", 48.381633)
	near("LONGITUDE", -123.395383)
	near("SOG", 12.3)
	near("COG", 224)
	near("HEADING", 215)
	if d.Line("!AIVDM,1,1,,A,15RTgt0PAso;90TKcjM8h6g208CQ,0*4B") != nil {
		t.Fatal("a bad checksum was accepted")
	}

	if d.Line(`\s:rtl_ais,c:1700000000*00\!AIVDM,2,1,1,A,55?MbV02;H;s<HtKR20EHE:0@T4@Dn2222222216L961O5Gf0NSQEp6ClRp8,0*1C`) != nil {
		t.Fatal("first fragment should wait for the second")
	}
	d.Line("!AIVDM,2,2,1,A,88888888880,2*25")
	st := d.vessels[351759000]
	if st == nil || st["NAME"] != "EVER DIADEM" || st["CALLSIGN"] != "3FOF8" || st["DEST"] != "NEW YORK" || st["TYPE"] != float64(70) || st["IMO"] != float64(9134270) {
		t.Fatalf("static data: %v", st)
	}
	e := aisEvent(v, time.Minute)
	if e == nil || e.UID != "MMSI-371798000" {
		t.Fatalf("event: %v", e)
	}
}

func TestSBSParse(t *testing.T) {
	st := &sbsState{tracks: map[string]*sbsTrack{}}
	now := time.Now()
	if st.line("MSG,1,111,11111,A1B2C3,111111,2026/10/08,12:00:00.000,2026/10/08,12:00:00.000,UAL123  ,,,,,,,,,,,", now) != nil {
		t.Fatal("identification alone should not place an aircraft")
	}
	a := st.line("MSG,3,111,11111,A1B2C3,111111,2026/10/08,12:00:00.000,2026/10/08,12:00:00.000,,35000,,,38.95,-77.45,,,0,0,0,0", now)
	if a == nil || *a.Lat != 38.95 || *a.Lon != -77.45 || a.Flight != "UAL123" {
		t.Fatalf("position: %+v", a)
	}
	if st.line("MSG,4,111,11111,A1B2C3,111111,,,,,,,450,270,,,,,,,,0", now.Add(time.Second)) != nil {
		t.Fatal("updates should be throttled")
	}
	a = st.line("MSG,6,111,11111,A1B2C3,111111,,,,,,,,,,,,7700,0,1,0,0", now.Add(3*time.Second))
	if a == nil || *a.Speed != 450 || *a.Track != 270 || a.Squawk != "7700" {
		t.Fatalf("merged: %+v", a)
	}
	e := adsbEvent(*a, time.Minute)
	if e == nil || e.UID != "ICAO-A1B2C3" || math.Abs(e.Point.Hae-35000*feetToMeters) > 0.01 {
		t.Fatalf("event: %v", e)
	}
}

func feedLatest(s *Server, feed, uid string) *cot.Event {
	st := s.dfeeds.state(feed)
	st.mu.Lock()
	defer st.mu.Unlock()
	if m := st.latest[uid]; m != nil {
		return m.Event
	}
	return nil
}

func TestReceiverFeeds(t *testing.T) {
	sbs, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sbs.Close()
	go func() {
		for {
			c, err := sbs.Accept()
			if err != nil {
				return
			}
			fmt.Fprint(c, "MSG,1,1,1,ABC123,1,,,,,DAL55   ,,,,,,,,,,,\r\nMSG,3,1,1,ABC123,1,,,,,,12000,,,40.1,-75.2,,,,,,0\r\n")
			time.Sleep(5 * time.Second)
			c.Close()
		}
	}()
	dump := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/data/aircraft.json" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"now":1,"aircraft":[{"hex":"def456","flight":"N12AB","altitude":2500,"speed":110,"track":90,"lat":41.5,"lon":-74.1,"seen_pos":1.2},{"hex":"fff000","flight":"NOPOS"}]}`))
	}))
	defer dump.Close()
	fix := time.Now().UTC().Add(-time.Minute).Format("2006-01-02T15:04:05.000+0000")
	tc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "ops" || p != "traccar-pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/devices":
			w.Write([]byte(`[{"id":1,"name":"Truck 7","uniqueId":"864000","status":"online","category":"truck"},{"id":2,"name":"Old","uniqueId":"old1","status":"offline"}]`))
		case "/api/positions":
			w.Write([]byte(`[{"deviceId":1,"fixTime":"` + fix + `","latitude":35.2,"longitude":-80.8,"speed":20,"course":45,"attributes":{"batteryLevel":77}},{"deviceId":2,"fixTime":"2020-01-01T00:00:00.000+0000","latitude":35.3,"longitude":-80.9}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer tc.Close()
	sbsPort := sbs.Addr().(*net.TCPAddr).Port
	aisPort, osmPort := freeUDPPort(t), freePort(t)
	s := newTestServer(t, func(c *Config) {
		c.DataFeeds = []DataFeedConfig{
			{UUID: "f-sbs", Name: "SBS", Protocol: "sbs", Address: "127.0.0.1", Port: sbsPort, Sync: true, Enabled: true},
			{UUID: "f-dump", Name: "Dump", Protocol: "dump1090", URL: dump.URL, Sync: true, Enabled: true},
			{UUID: "f-ais", Name: "AIS", Protocol: "ais", Port: aisPort, Sync: true, Enabled: true},
			{UUID: "f-osm", Name: "Phones", Protocol: "osmand", Port: osmPort, Password: "k1", Sync: true, Enabled: true},
			{UUID: "f-tc", Name: "Fleet", Protocol: "traccar", URL: tc.URL, Username: "ops", Password: "traccar-pass", Interval: 1, Sync: true, Enabled: true},
		}
	})

	waitFor(t, "SBS aircraft", 5*time.Second, func() bool { return feedLatest(s, "f-sbs", "ICAO-ABC123") != nil })
	if e := feedLatest(s, "f-sbs", "ICAO-ABC123"); e.Point.Lat != 40.1 || e.Detail.Child("contact").Attr("callsign") != "DAL55" {
		t.Fatalf("sbs: %s", e.String())
	}
	waitFor(t, "dump1090 aircraft", 5*time.Second, func() bool { return feedLatest(s, "f-dump", "ICAO-DEF456") != nil })
	if e := feedLatest(s, "f-dump", "ICAO-DEF456"); math.Abs(e.Point.Hae-2500*feetToMeters) > 0.01 {
		t.Fatalf("dump1090 altitude: %s", e.String())
	}

	uc, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(aisPort))
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	waitFor(t, "AIS vessel", 5*time.Second, func() bool {
		uc.Write([]byte("!AIVDM,1,1,,A,15RTgt0PAso;90TKcjM8h6g208CQ,0*4A\r\n"))
		return feedLatest(s, "f-ais", "MMSI-371798000") != nil
	})

	base := "http://127.0.0.1:" + strconv.Itoa(osmPort)
	if st, _ := doReq(t, http.DefaultClient, "GET", base+"/?id=phone1&lat=33.5&lon=-84.4&speed=5&bearing=180&batt=64", nil, nil); st != http.StatusUnauthorized {
		t.Fatalf("missing key: %d", st)
	}
	if st, body := doReq(t, http.DefaultClient, "POST", base+"/?id=phone1&lat=33.5&lon=-84.4&speed=5&bearing=180&batt=64&key=k1&timestamp="+strconv.FormatInt(time.Now().Unix(), 10), nil, nil); st != 200 {
		t.Fatalf("osmand: %d %s", st, body)
	}
	e := feedLatest(s, "f-osm", "traccar-phone1")
	if e == nil || e.Point.Lat != 33.5 || e.Detail.Child("status").Attr("battery") != "64" || e.Type != "a-f-G-U-C" {
		t.Fatalf("osmand event: %v", e)
	}
	js := `{"device_id":"phone2","location":{"timestamp":"` + time.Now().UTC().Format(time.RFC3339) + `","coords":{"latitude":33.6,"longitude":-84.5,"speed":2,"heading":90,"accuracy":5},"battery":{"level":0.5}}}`
	if st, body := doReq(t, http.DefaultClient, "POST", base+"/?key=k1", strings.NewReader(js), map[string]string{"Content-Type": "application/json"}); st != 200 {
		t.Fatalf("osmand json: %d %s", st, body)
	}
	if e := feedLatest(s, "f-osm", "traccar-phone2"); e == nil || e.Point.Ce != 5 || e.Detail.Child("status").Attr("battery") != "50" {
		t.Fatalf("osmand json event: %v", e)
	}

	waitFor(t, "Traccar devices", 5*time.Second, func() bool { return feedLatest(s, "f-tc", "traccar-864000") != nil })
	if e := feedLatest(s, "f-tc", "traccar-864000"); e.Type != "a-f-G-E-V-C" || e.Detail.Child("contact").Attr("callsign") != "Truck 7" {
		t.Fatalf("traccar: %s", e.String())
	}
	if feedLatest(s, "f-tc", "traccar-old1") != nil {
		t.Fatal("a position from 2020 was published")
	}

	admin := feedAdmin(t, s)
	_, body := doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/settings"), nil, admin)
	if strings.Contains(string(body), "traccar-pass") {
		t.Fatal("the Traccar password was returned by the settings API")
	}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}
