package server

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
)

func parseEvent(t *testing.T, xml string) *cot.Event {
	t.Helper()
	e, err := cot.Parse([]byte(xml))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func shapeXML(uid, typ, lat, detail string) string {
	return fmt.Sprintf(`<event version="2.0" uid="%s" type="%s" how="h-e" time="2026-10-08T00:00:00Z" start="2026-10-08T00:00:00Z" stale="2030-01-01T00:00:00Z"><point lat="%s" lon="-77" hae="0" ce="9999999" le="9999999"/><detail>%s</detail></event>`, uid, typ, lat, detail)
}

func TestShapeParsing(t *testing.T) {
	route := parseEvent(t, shapeXML("r1", "b-m-r", "38.9", `<link uid="w1" callsign="SP" type="b-m-p-w" point="38.9,-77.0,0" relation="c"/><link uid="w2" callsign="CP1" type="b-m-p-c" point="38.91,-77.01" relation="c"/><link uid="w3" type="b-m-p-w" point="38.92,-77.02" relation="c"/><link_attr color="-16776961" method="Driving" direction="Infil"/><contact callsign="Route 1"/>`))
	sv := shapeOf(route)
	if sv == nil || !sv.Route || len(sv.Points) != 3 || sv.Stroke != "rgba(0,0,255,1.00)" {
		t.Fatalf("route: %+v", sv)
	}

	poly := parseEvent(t, shapeXML("p1", "u-d-f", "38.9", `<link point="38.9,-77.0"/><link point="38.95,-77.0"/><link point="38.95,-77.05"/><strokeColor value="-65536"/><fillColor value="1728053247"/><strokeWeight value="4.0"/>`))
	sv = shapeOf(poly)
	if sv == nil || !sv.Closed || len(sv.Points) != 3 || sv.Width != 4 || sv.Fill == "" {
		t.Fatalf("polygon: %+v", sv)
	}

	line := parseEvent(t, shapeXML("l1", "u-d-f", "38.9", `<link point="38.9,-77.0"/><link point="38.95,-77.0"/><strokeColor value="-1"/>`))
	if sv = shapeOf(line); sv == nil || sv.Closed {
		t.Fatalf("open line: %+v", sv)
	}

	circle := parseEvent(t, shapeXML("c1", "u-d-c-c", "38.9", `<shape><ellipse major="250" minor="250" angle="360"/></shape><strokeColor value="-1"/>`))
	if sv = shapeOf(circle); sv == nil || sv.Radius != 250 || !sv.Closed {
		t.Fatalf("circle: %+v", sv)
	}

	rb := parseEvent(t, shapeXML("rb1", "u-rb-a", "38.9", `<range value="1000"/><bearing value="90"/>`))
	if sv = shapeOf(rb); sv == nil || len(sv.Points) != 2 || sv.Points[1][1] <= -77 {
		t.Fatalf("range and bearing: %+v", sv)
	}

	if shapeOf(parseEvent(t, shapeXML("a1", "a-f-G", "38.9", `<contact callsign="x"/>`))) != nil {
		t.Fatal("a unit should not have a shape")
	}
	bad := parseEvent(t, shapeXML("b1", "u-d-f", "38.9", `<link point="999,-77"/><link point="nonsense"/>`))
	if shapeOf(bad) != nil {
		t.Fatal("invalid points produced a shape")
	}
}

func TestCasevacAndImage(t *testing.T) {
	s := newTestServer(t, nil)
	s.dir.AddUser("viewer", "viewer-password", true, nil)
	secret, _, err := s.dir.CreateToken("viewer", "api", "test", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	auth := map[string]string{"Authorization": "Bearer " + secret}
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	img.Set(1, 1, color.RGBA{255, 0, 0, 255})
	var buf bytes.Buffer
	png.Encode(&buf, img)
	b64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	c := dialTCP(t, s)
	c.send(saXML("ANDROID-medic", "MEDIC", 38.9, -77))
	medevac := cot.New("casevac-1", "b-r-f-h-c", "h-g-i-g-o", 10*time.Minute)
	medevac.Point = cot.Point{Lat: 38.91, Lon: -77.01, Ce: 10, Le: 10}
	medevac.Detail.AddNew("contact", "callsign", "MEDEVAC-1")
	medevac.Detail.AddNew("_medevac_", "title", "MEDEVAC-1", "freq", "38.90", "urgent", "2", "priority", "1", "security", "1", "hlz_marking", "2", "litter", "2", "casevac", "true")
	medevac.Detail.AddNew("image", "mime", "image/png", "type", "EO").Text = b64
	c.send(medevac.String())
	waitFor(t, "the casevac report to be cached", 5*time.Second, func() bool { return s.hub.CachedEvent("casevac-1") != nil })

	st, body := doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/cot/latest"), nil, auth)
	if st != 200 || !strings.Contains(string(body), `"medevac":{`) || !strings.Contains(string(body), `"urgent":"2"`) || !strings.Contains(string(body), `"image":true`) {
		t.Fatalf("latest: %d %s", st, body)
	}
	st, got := doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/cot/casevac-1/image"), nil, auth)
	if st != 200 || !bytes.Equal(got, buf.Bytes()) {
		t.Fatalf("image: %d %d bytes", st, len(got))
	}
	st, _ = doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/cot/ANDROID-medic/image"), nil, auth)
	if st != http.StatusNotFound {
		t.Fatalf("missing image returned %d", st)
	}
}
