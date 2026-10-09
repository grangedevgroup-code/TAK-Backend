package server

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
)

func TestSubscriptionAdminAPI(t *testing.T) {
	s := newTestServer(t, nil)
	s.dir.AddUser("subadmin", "sub-admin-pw", true, nil)
	admin := map[string]string{"basic": "subadmin:sub-admin-pw", "Content-Type": "application/json"}
	base := plainURL(s, "/Marti/api")

	watcher := dialTCP(t, s)
	watcher.send(saXML("sub-watch", "WATCH", 1, 1))
	ghost := dialTCP(t, s)
	ghost.send(saXML("sub-ghost", "GHOST", 1, 1))
	watcher.expect(uidIs("sub-ghost"), "ghost position before incognito")

	if st, _ := doReq(t, http.DefaultClient, "GET", base+"/subscription/sub-ghost", nil, admin); st != 200 {
		t.Fatalf("get one: %d", st)
	}
	if st, _ := doReq(t, http.DefaultClient, "POST", base+"/subscriptions/incognito/sub-ghost", nil, admin); st != 200 {
		t.Fatalf("incognito: %d", st)
	}
	ghost.send(saXML("sub-ghost", "GHOST", 2, 2))
	watcher.expectNone(uidIs("sub-ghost"), "position while incognito", 500*time.Millisecond)
	_, body := doReq(t, http.DefaultClient, "GET", base+"/subscription/sub-ghost", nil, admin)
	if !strings.Contains(string(body), `"incognito":true`) {
		t.Fatalf("incognito not reported: %s", body)
	}
	doReq(t, http.DefaultClient, "POST", base+"/subscriptions/incognito/sub-ghost", nil, admin)

	filter := `<filter><geospatialFilter><boundingBox minLatitude="10" minLongitude="10" maxLatitude="20" maxLongitude="20"/></geospatialFilter></filter>`
	if st, b := doReq(t, http.DefaultClient, "PUT", base+"/subscriptions/sub-watch/filter", strings.NewReader(filter), map[string]string{"basic": "subadmin:sub-admin-pw", "Content-Type": "application/xml"}); st != 200 {
		t.Fatalf("set filter: %d %s", st, b)
	}
	far := cot.New("sub-far", "a-h-G", "h-e", time.Minute)
	far.Point = cot.Point{Lat: 50, Lon: 50, Ce: 1, Le: 1}
	near := cot.New("sub-near", "a-h-G", "h-e", time.Minute)
	near.Point = cot.Point{Lat: 15, Lon: 15, Ce: 1, Le: 1}
	ghost.send(far.String())
	ghost.send(near.String())
	watcher.expect(uidIs("sub-near"), "item inside the filter")
	watcher.expectNone(uidIs("sub-far"), "item outside the filter", 400*time.Millisecond)
	if st, _ := doReq(t, http.DefaultClient, "DELETE", base+"/subscriptions/sub-watch/filter", nil, admin); st != 200 {
		t.Fatalf("delete filter: %d", st)
	}
	ghost.send(far.String())
	watcher.expect(uidIs("sub-far"), "item after the filter was removed")

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	add := `{"uid":"static-1","protocol":"udp","subaddr":"127.0.0.1","subport":"` + strconv.Itoa(port) + `","xpath":"","filterGroups":""}`
	if st, b := doReq(t, http.DefaultClient, "POST", base+"/subscriptions/add", strings.NewReader(add), admin); st != 201 {
		t.Fatalf("add static: %d %s", st, b)
	}
	deadline := time.Now().Add(5 * time.Second)
	got := false
	buf := make([]byte, 65536)
	for time.Now().Before(deadline) && !got {
		ghost.send(saXML("sub-static-test", "STATIC", 3, 3))
		pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if n, _, err := pc.ReadFrom(buf); err == nil && strings.Contains(string(buf[:n]), "sub-static-test") {
			got = true
		}
	}
	if !got {
		t.Fatal("static subscription received nothing")
	}
	if st, b := doReq(t, http.DefaultClient, "DELETE", base+"/subscriptions/delete/static-1", nil, admin); st != 200 {
		t.Fatalf("delete static: %d %s", st, b)
	}
	for _, p := range s.Config().Peers {
		if p.Name == "static-1" {
			t.Fatal("static subscription still configured")
		}
	}
	if st, _ := doReq(t, http.DefaultClient, "POST", base+"/subscriptions/add", strings.NewReader(add), map[string]string{"Content-Type": "application/json"}); st != 401 && st != 403 {
		t.Fatalf("anonymous add: %d", st)
	}
}
