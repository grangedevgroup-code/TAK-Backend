package cot

import (
	"strings"
	"testing"
	"time"
)

const sample = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><event version="2.0" uid="ANDROID-abc" type="a-f-G-U-C" how="m-g" time="2026-01-02T03:04:05.123Z" start="2026-01-02T03:04:05.123Z" stale="2026-01-02T03:10:05.123Z" access="Undefined"><point lat="40.123456" lon="-105.654321" hae="1600.5" ce="9999999.0" le="9999999.0"/><detail><takv os="34" version="5.4.0.16 (abc).1735333744-CIV" device="SAMSUNG SM-S918U" platform="ATAK-CIV"/><contact endpoint="*:-1:stcp" callsign="ALPHA"/><uid Droid="ALPHA"/><precisionlocation altsrc="GPS" geopointsrc="GPS"/><__group role="Team Member" name="Cyan"/><status battery="88"/><track course="123.4" speed="1.5"/><marti><dest callsign="BRAVO"/><dest uid="IOS-1"/><dest mission="ops"/></marti><link uid="X" type="a-f-G" relation="p-p"/></detail></event>`

func TestParseSA(t *testing.T) {
	e, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if e.UID != "ANDROID-abc" || e.Type != "a-f-G-U-C" || e.How != "m-g" || e.Access != "Undefined" {
		t.Fatalf("attrs: %+v", e)
	}
	if e.Point.Lat != 40.123456 || e.Point.Lon != -105.654321 || e.Point.Hae != 1600.5 || e.Point.Ce != Unknown {
		t.Fatalf("point: %+v", e.Point)
	}
	if !e.Time.Equal(time.Date(2026, 1, 2, 3, 4, 5, 123e6, time.UTC)) {
		t.Fatalf("time %v", e.Time)
	}
	if e.Callsign() != "ALPHA" || e.Endpoint() != "*:-1:stcp" {
		t.Fatal("contact")
	}
	if n, r := e.Team(); n != "Cyan" || r != "Team Member" {
		t.Fatal("team")
	}
	if _, p, _, v := e.Takv(); p != "ATAK-CIV" || !strings.HasPrefix(v, "5.4") {
		t.Fatal("takv")
	}
	d := e.Dests()
	if len(d) != 3 || d[0].Callsign != "BRAVO" || d[1].UID != "IOS-1" || d[2].Mission != "ops" {
		t.Fatalf("dests %+v", d)
	}
	if !e.IsSA() || e.IsChat() || e.IsPing() {
		t.Fatal("classification")
	}
	out := e.String()
	again, err := Parse([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if again.String() != out {
		t.Fatalf("unstable:\n%s\n%s", out, again.String())
	}
	if !strings.Contains(out, `time="2026-01-02T03:04:05.123Z"`) || !strings.Contains(out, `hae="1600.5"`) || !strings.Contains(out, `ce="9999999.0"`) {
		t.Fatalf("formatting: %s", out)
	}
}

func TestTimes(t *testing.T) {
	cases := map[string]time.Time{
		"2026-01-02T03:04:05Z":           time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		"2026-01-02T03:04:05.5Z":         time.Date(2026, 1, 2, 3, 4, 5, 5e8, time.UTC),
		"2026-01-02T03:04:05.123456789Z": time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC),
		"2026-01-02T05:04:05+02:00":      time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		"2026-01-02T05:04:05.000+0200":   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		"2026-01-02T03:04:05":            time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		"1767323045000":                  time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	for in, want := range cases {
		got, err := ParseTime(in)
		if err != nil || !got.Equal(want) {
			t.Errorf("%s: got %v %v want %v", in, got, err, want)
		}
	}
	if _, err := ParseTime("yesterday"); err == nil {
		t.Error("bad time accepted")
	}
}

func TestMissingFields(t *testing.T) {
	if _, err := Parse([]byte(`<event type="a"/>`)); err != ErrNoUID {
		t.Fatalf("want ErrNoUID got %v", err)
	}
	if _, err := Parse([]byte(`<event uid="a"/>`)); err != ErrNoType {
		t.Fatalf("want ErrNoType got %v", err)
	}
	if _, err := Parse([]byte(`<auth/>`)); err != ErrNotEvent {
		t.Fatalf("want ErrNotEvent got %v", err)
	}
	e, err := Parse([]byte(`<event uid="u" type="a-f-G" time="2026-01-02T03:04:05Z"><point lat="NaN" lon="x"/></event>`))
	if err != nil {
		t.Fatal(err)
	}
	if e.Start != e.Time || e.Stale.Sub(e.Start) != 2*time.Minute || e.Point.Lat != 0 || e.Point.Hae != Unknown || e.Detail == nil {
		t.Fatalf("defaults: %+v", e)
	}
	if !strings.Contains(e.String(), "<detail/>") {
		t.Fatal("empty detail not serialized")
	}
}

func TestBuilders(t *testing.T) {
	d := DeleteFor("ANDROID-1", "a-f-G-U-C")
	if !d.IsDelete() || len(d.Links()) != 1 || d.Links()[0].UID != "ANDROID-1" {
		t.Fatal("delete")
	}
	c := Chat("SRV", "Server", "All Chat Rooms", "All Chat Rooms", "hello <all>", nil)
	if !c.IsChat() || c.Remarks() != "hello <all>" || c.D("__chat").Attr("senderCallsign") != "Server" {
		t.Fatalf("chat: %s", c)
	}
	back, err := Parse(c.XML())
	if err != nil || back.Remarks() != "hello <all>" {
		t.Fatalf("chat roundtrip %v", err)
	}
	c.AddFlowTag("GolangTAKServer-x", time.Now())
	if c.FlowTag("GolangTAKServer-x") == "" {
		t.Fatal("flow tag")
	}
	if len(NewUID()) != 36 {
		t.Fatal("uid length")
	}
	cl := c.Clone()
	cl.Detail.Child("remarks").Text = "changed"
	if c.Remarks() == "changed" {
		t.Fatal("clone shares detail")
	}
}
