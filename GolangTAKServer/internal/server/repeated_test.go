package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
)

func TestRepeatedMessages(t *testing.T) {
	s := newTestServer(t, func(c *Config) { c.Replay = "sa" })
	s.dir.AddUser("ftsadmin", "fts-password", true, nil)
	secret, _, err := s.dir.CreateToken("ftsadmin", "api", "test", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	auth := map[string]string{"Content-Type": "application/json", "Authorization": "Bearer " + secret}
	api := "http://127.0.0.1:" + strconv.Itoa(s.Config().Ports.API)
	st, body := doReq(t, http.DefaultClient, "POST", api+"/ManageGeoObject/postGeoObject", strings.NewReader(`{"latitude":38.9,"longitude":-77.0,"attitude":"friendly","geoObject":"Ground","name":"Checkpoint","timeout":120,"repeat":true}`), auth)
	if st != 200 {
		t.Fatalf("post: %d %s", st, body)
	}
	uid := strings.TrimSpace(string(body))

	late := dialTCP(t, s)
	late.send(saXML("ANDROID-late", "LATE", 1, 1))
	late.expect(func(e *cot.Event) bool { return e.UID == uid }, "repeated object sent to a device that connected later")

	st, body = doReq(t, http.DefaultClient, "GET", api+"/ManageGeoObject/GetRepeatedMessages", nil, auth)
	var got struct {
		Messages map[string]string `json:"messages"`
	}
	if st != 200 || json.Unmarshal(body, &got) != nil || !strings.Contains(got.Messages[uid], "Checkpoint") {
		t.Fatalf("list: %d %s", st, body)
	}

	st, body = doReq(t, http.DefaultClient, "DELETE", api+"/ManageGeoObject/DeleteRepeatedMessage?ids="+uid, nil, auth)
	if st != 200 {
		t.Fatalf("delete: %d %s", st, body)
	}
	late.expect(func(e *cot.Event) bool { return e.Type == "t-x-d-d" }, "delete for the repeated object")
	if len(s.repeatedList()) != 0 {
		t.Fatal("repeated message still stored")
	}
	st, _ = doReq(t, http.DefaultClient, "DELETE", api+"/ManageGeoObject/DeleteRepeatedMessage?ids="+uid, nil, auth)
	if st != http.StatusInternalServerError {
		t.Fatalf("deleting twice returned %d", st)
	}
}
