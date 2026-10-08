package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
)

func adminToken(t *testing.T, s *Server) map[string]string {
	t.Helper()
	s.dir.AddUser("root", "root-password", true, nil)
	tok, _, err := s.dir.CreateToken("root", "api", "t", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{"Authorization": "Bearer " + tok, "Content-Type": "application/json"}
}

func TestCotInjectors(t *testing.T) {
	s := newTestServer(t, nil)
	a := adminToken(t, s)
	base := plainURL(s, "/Marti/api/injectors/cot/uid")
	if st, _ := doReq(t, http.DefaultClient, "POST", base, strings.NewReader(`{"uid":"ANDROID-cam","toInject":"<__video url=\"rtsp://cam/1\"/>"}`), nil); st != http.StatusForbidden && st != http.StatusUnauthorized {
		t.Fatalf("anonymous injector create: %d", st)
	}
	if st, _ := doReq(t, http.DefaultClient, "POST", base, strings.NewReader(`{"uid":"x","toInject":"<broken"}`), a); st != http.StatusBadRequest {
		t.Fatal("malformed XML accepted")
	}
	if st, body := doReq(t, http.DefaultClient, "POST", base, strings.NewReader(`{"uid":"ANDROID-cam","toInject":"<__video url=\"rtsp://cam/1\"/>"}`), a); st != 200 {
		t.Fatalf("create: %d %s", st, body)
	}
	recv := dialTCP(t, s)
	recv.send(saXML("ANDROID-recv", "RECV", 1, 1))
	time.Sleep(200 * time.Millisecond)
	cam := dialTCP(t, s)
	cam.send(saXML("ANDROID-cam", "CAM", 2, 2))
	got := recv.expect(func(e *cot.Event) bool { return e.UID == "ANDROID-cam" }, "camera position")
	if v := got.D("__video"); v == nil || v.Attr("url") != "rtsp://cam/1" {
		t.Fatalf("injected detail missing: %s", got.String())
	}
	_, body := doReq(t, http.DefaultClient, "GET", base+"/ANDROID-cam", nil, a)
	if !strings.Contains(string(body), "rtsp://cam/1") {
		t.Fatalf("get: %s", body)
	}
	q := url.Values{"uid": {"ANDROID-cam"}, "toInject": {`<__video url="rtsp://cam/1"/>`}}
	if st, _ := doReq(t, http.DefaultClient, "DELETE", base+"?"+q.Encode(), nil, a); st != 200 {
		t.Fatal("delete failed")
	}
	if len(s.injectorsFor("")) != 0 {
		t.Fatal("injector still stored")
	}
}

func TestLocate(t *testing.T) {
	s := newTestServer(t, func(c *Config) { c.Locate = LocateConfig{Enabled: true, Public: true, Mission: "locate"} })
	recv := dialTCP(t, s)
	recv.send(saXML("ANDROID-sar", "SAR", 1, 1))
	time.Sleep(200 * time.Millisecond)
	st, body := doReq(t, http.DefaultClient, "GET", plainURL(s, "/locate"), nil, nil)
	if st != 200 || !strings.Contains(string(body), "Share your location") {
		t.Fatalf("page: %d", st)
	}
	form := url.Values{"latitude": {"44.5"}, "longitude": {"-110.2"}, "name": {"Lost Hiker"}, "remarks": {"near the creek"}}
	st, body = doReq(t, http.DefaultClient, "POST", plainURL(s, "/locate/api?"+form.Encode()), nil, nil)
	if st != 200 {
		t.Fatalf("locate: %d %s", st, body)
	}
	got := recv.expect(func(e *cot.Event) bool { return e.UID == "locate-lost-hiker" }, "located person")
	if got.Callsign() != "Lost Hiker" || got.Point.Lat != 44.5 || got.Remarks() != "near the creek" {
		t.Fatalf("event: %s", got.String())
	}
	waitFor(t, "the report to be added to the locate mission", 5*time.Second, func() bool {
		m, ok := s.missions.Get("locate")
		return ok && m.item("locate-lost-hiker") != nil
	})
	if st, _ := doReq(t, http.DefaultClient, "POST", plainURL(s, "/locate/api?latitude=200&longitude=0&name=x"), nil, nil); st != http.StatusBadRequest {
		t.Fatal("bad latitude accepted")
	}

	off := newTestServer(t, nil)
	if st, _ := doReq(t, http.DefaultClient, "POST", plainURL(off, "/locate/api?"+form.Encode()), nil, nil); st != http.StatusNotFound {
		t.Fatalf("locate while disabled: %d", st)
	}
}

func TestCertAdminAPI(t *testing.T) {
	s := newTestServer(t, nil)
	a := adminToken(t, s)
	s.dir.AddUser("alice", "correct-horse", false, nil)
	c := httpsClient(s, nil)
	enroll := "https://127.0.0.1:" + strconv.Itoa(s.Config().Ports.Enroll)
	for i := 0; i < 2; i++ {
		_, csr := newCSR(t, "alice")
		if st, body := doReq(t, c, "POST", enroll+"/Marti/api/tls/signClient/v2?clientUid=ANDROID-alice&version=3", strings.NewReader(csr), map[string]string{"basic": "alice:correct-horse", "Accept": "application/json"}); st != 200 {
			t.Fatalf("enroll: %d %s", st, body)
		}
		time.Sleep(20 * time.Millisecond)
	}
	get := func(path string) []map[string]any {
		st, body := doReq(t, http.DefaultClient, "GET", plainURL(s, path), nil, a)
		var env struct {
			Data []map[string]any `json:"data"`
		}
		if st != 200 || json.Unmarshal(body, &env) != nil {
			t.Fatalf("%s: %d %s", path, st, body)
		}
		return env.Data
	}
	all := get("/Marti/api/certadmin/cert?username=alice")
	if len(all) != 2 || all[0]["hash"] == "" || !strings.Contains(all[0]["certificate"].(string), "BEGIN CERTIFICATE") {
		t.Fatalf("list: %v", all)
	}
	if active := get("/Marti/api/certadmin/cert/active"); len(active) != 1 {
		t.Fatalf("active: %d", len(active))
	}
	if replaced := get("/Marti/api/certadmin/cert/replaced"); len(replaced) != 1 {
		t.Fatalf("replaced: %d", len(replaced))
	}
	hash := all[0]["hash"].(string)
	st, body := doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/certadmin/cert/"+hash+"/download"), nil, a)
	if st != 200 || !strings.HasPrefix(string(body), "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("download: %d", st)
	}
	id := strconv.FormatInt(int64(all[0]["id"].(float64)), 10)
	if st, _ := doReq(t, http.DefaultClient, "DELETE", plainURL(s, "/Marti/api/certadmin/cert/revoke/"+id), nil, a); st != 200 {
		t.Fatal("revoke failed")
	}
	if revoked := get("/Marti/api/certadmin/cert/revoked"); len(revoked) != 1 || revoked[0]["revocationDate"] == nil {
		t.Fatalf("revoked: %v", revoked)
	}
	u, _ := s.dir.User("alice")
	if !s.dir.IsRevoked(u.Certs[len(u.Certs)-1].Serial) && !s.dir.IsRevoked(u.Certs[0].Serial) {
		t.Fatal("certificate not revoked in the directory")
	}
	if st, _ := doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/certadmin/cert"), nil, map[string]string{"basic": "alice:correct-horse"}); st != http.StatusForbidden {
		t.Fatalf("non-admin listed certificates: %d", st)
	}
}
