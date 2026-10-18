package takproto

import (
	"slices"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
)

func TestFedEventFeedAndMissionGUIDs(t *testing.T) {
	e := cot.New("FEED-1", "a-f-G-U-C", "m-g", time.Minute)
	e.Point = cot.Point{Lat: 1.5, Lon: 2.5, Hae: 3, Ce: 4, Le: 5}
	in := FedEvent{Event: e, Groups: []string{"Red"}, FeedUID: "8b1f8e1c-feed", MissionGUIDs: []string{"6f0c1b2a-0000-4000-8000-000000000001"}}
	out, err := UnmarshalFed(MarshalFed(in))
	if err != nil {
		t.Fatal(err)
	}
	if out.FeedUID != in.FeedUID || !slices.Equal(out.MissionGUIDs, in.MissionGUIDs) || out.Event.UID != "FEED-1" {
		t.Fatalf("round trip %+v", out)
	}
	plain, err := UnmarshalFed(MarshalFed(FedEvent{Event: e}))
	if err != nil || plain.FeedUID != "" || len(plain.MissionGUIDs) != 0 {
		t.Fatalf("event without feed or mission guids: %+v %v", plain, err)
	}
}

func TestGeoEventMatchesOfficialDetailHandling(t *testing.T) {
	e := cot.New("GEO-1", "a-f-G-U-C", "m-g", time.Minute)
	e.Point = cot.Point{Lat: 10, Lon: 20, Hae: 30, Ce: 9, Le: 9}
	d := e.EnsureDetail()
	d.AddNew("track", "speed", "12.5", "course", "270")
	d.AddNew("status", "battery", "88")
	d.AddNew("precisionlocation", "geopointsrc", "GPS", "altsrc", "DTED0")
	d.AddNew("contact", "callsign", "ALPHA")
	out, err := UnmarshalFed(MarshalFed(FedEvent{Event: e}))
	if err != nil {
		t.Fatal(err)
	}
	od := out.Event.Detail
	if tr := od.Child("track"); tr == nil || tr.Attr("speed") != "12.5" || tr.Attr("course") != "270" {
		t.Fatalf("track %v", od)
	}
	if st := od.Child("status"); st == nil || st.Attr("battery") != "88" {
		t.Fatalf("status %v", od)
	}
	if pl := od.Child("precisionlocation"); pl == nil || pl.Attr("geopointsrc") != "GPS" || pl.Attr("altsrc") != "DTED0" {
		t.Fatalf("precisionlocation %v", od)
	}
	if c := od.Child("contact"); c == nil || c.Attr("callsign") != "ALPHA" {
		t.Fatalf("contact %v", od)
	}
	if n := len(od.Children("track")); n != 1 {
		t.Fatalf("%d track elements", n)
	}
}
