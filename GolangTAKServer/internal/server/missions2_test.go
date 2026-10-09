package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
)

func TestMissionCopySendTokenLayersKeywords(t *testing.T) {
	s := newTestServer(t, nil)
	owner := dialTCP(t, s)
	owner.send(saXML("ANDROID-own", "OWN", 1, 1))
	friend := dialTCP(t, s)
	friend.send(saXML("ANDROID-friend", "FRIEND", 1, 1))
	time.Sleep(200 * time.Millisecond)
	base := plainURL(s, "/Marti/api/missions/ops2")
	do := func(method, url, body string) (int, string) {
		t.Helper()
		var rd *strings.Reader
		if body != "" {
			rd = strings.NewReader(body)
		} else {
			rd = strings.NewReader("")
		}
		st, b := doReq(t, http.DefaultClient, method, url, rd, map[string]string{"Content-Type": "application/json"})
		return st, string(b)
	}
	if st, b := do("PUT", base+"?creatorUid=ANDROID-own&password=secret1", ""); st >= 300 {
		t.Fatalf("create: %d %s", st, b)
	}
	hash := uploadPackage(t, s, "plan2", []byte("copy me "+time.Now().String()), "ANDROID-own")
	if st, b := do("PUT", base+"/contents?creatorUid=ANDROID-own", `{"hashes":["`+hash+`"]}`); st >= 300 {
		t.Fatalf("contents: %d %s", st, b)
	}
	marker := cot.New("ops2-marker", "a-h-G", "h-e", 10*time.Minute)
	marker.Point = cot.Point{Lat: 1, Lon: 2, Ce: 1, Le: 1}
	marker.SetDests([]cot.Dest{{Mission: "ops2"}})
	owner.send(marker.String())
	time.Sleep(300 * time.Millisecond)

	if st, b := do("PUT", base+"/content/"+hash+"/keywords?creatorUid=ANDROID-own", `["map","day1"]`); st != 200 {
		t.Fatalf("content keywords: %d %s", st, b)
	}
	if st, b := do("PUT", base+"/uid/ops2-marker/keywords?creatorUid=ANDROID-own", `["hostile"]`); st != 200 {
		t.Fatalf("uid keywords: %d %s", st, b)
	}
	if st, b := do("PUT", base+"/uid/missing/keywords?creatorUid=ANDROID-own", `["x"]`); st != 404 {
		t.Fatalf("keywords on missing uid: %d %s", st, b)
	}
	_, b := do("GET", base+"?password=secret1", "")
	if !strings.Contains(b, `"day1"`) || !strings.Contains(b, `"hostile"`) {
		t.Fatalf("keywords not in mission: %s", b)
	}

	st, b := do("PUT", base+"/layers?creatorUid=ANDROID-own&name=Phase%201&type=GROUP&uid=L1", "")
	if st != 200 || !strings.Contains(b, `"L1"`) {
		t.Fatalf("create layer: %d %s", st, b)
	}
	do("PUT", base+"/layers?creatorUid=ANDROID-own&name=Phase%202&type=GROUP&uid=L2&afterUid=L1", "")
	do("PUT", base+"/layers?creatorUid=ANDROID-own&name=Targets&type=UID&uid=L3&parentUid=L1", "")
	if st, b := do("PUT", base+"/layers?creatorUid=ANDROID-own&name=Bad&type=NOPE", ""); st != 400 {
		t.Fatalf("bad type accepted: %d %s", st, b)
	}
	do("PUT", base+"/layers/L2/name?creatorUid=ANDROID-own&name=Phase%20Two", "")
	do("PUT", base+"/layers/L2/position?creatorUid=ANDROID-own", "")
	if st, b := do("PUT", base+"/layers/parent?creatorUid=ANDROID-own&layerUid=L1&parentUid=L3", ""); st != 400 {
		t.Fatalf("cycle accepted: %d %s", st, b)
	}
	_, b = do("GET", base+"/layers?password=secret1", "")
	var layers struct {
		Data []struct {
			UID      string `json:"uid"`
			Name     string `json:"name"`
			Children []struct {
				UID string `json:"uid"`
			} `json:"mission_layers"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(b), &layers); err != nil {
		t.Fatal(err)
	}
	if len(layers.Data) != 2 || layers.Data[0].UID != "L2" || layers.Data[0].Name != "Phase Two" || layers.Data[1].UID != "L1" || len(layers.Data[1].Children) != 1 {
		t.Fatalf("layers %s", b)
	}
	do("DELETE", base+"/layers?creatorUid=ANDROID-own&uid=L1", "")
	_, b = do("GET", base+"/layers?password=secret1", "")
	if strings.Contains(b, `"L1"`) || strings.Contains(b, `"L3"`) || !strings.Contains(b, `"L2"`) {
		t.Fatalf("delete should remove L1 and its child: %s", b)
	}

	if st, b := do("GET", base+"/token?password=wrong", ""); st != 403 {
		t.Fatalf("token with wrong password: %d %s", st, b)
	}
	st, b = do("GET", base+"/token?password=secret1", "")
	var tok struct {
		Data string `json:"data"`
	}
	json.Unmarshal([]byte(b), &tok)
	if st != 201 || strings.Count(tok.Data, ".") != 2 {
		t.Fatalf("token: %d %s", st, b)
	}
	if c, err := s.parseMissionToken(tok.Data); err != nil || c.Mission != "ops2" {
		t.Fatalf("token claims %+v %v", c, err)
	}

	st, b = do("PUT", base+"/copy?creatorUid=ANDROID-own&copyName=ops2-copy&password=secret1", "")
	if st != 200 || !strings.Contains(b, "ops2-copy") || !strings.Contains(b, hash) || !strings.Contains(b, "ops2-marker") {
		t.Fatalf("copy: %d %s", st, b)
	}
	if st, b := do("PUT", base+"/copy?creatorUid=ANDROID-own&copyName=ops2-copy&password=secret1", ""); st != 409 {
		t.Fatalf("copy over existing: %d %s", st, b)
	}
	if st, b := do("GET", plainURL(s, "/Marti/api/missions/ops2-copy/cot"), ""); st != 200 || !strings.Contains(b, "ops2-marker") {
		t.Fatalf("copied cot: %d %s", st, b)
	}

	if st, b := do("POST", base+"/send?creatorUid=ANDROID-own&password=secret1&contacts=ANDROID-friend", ""); st != 200 {
		t.Fatalf("send: %d %s", st, b)
	}
	e := friend.expect(func(e *cot.Event) bool { return e.Type == "b-f-t-r" }, "mission package offer")
	fs := e.D("fileshare")
	if fs == nil || fs.Attr("filename") != "ops2.zip" || !strings.Contains(fs.Attr("senderUrl"), "/Marti/sync/content?hash=") {
		t.Fatalf("fileshare %v", fs)
	}
	owner.expectNone(func(e *cot.Event) bool { return e.Type == "b-f-t-r" }, "package for someone else", 500*time.Millisecond)
	st, _ = doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/sync/content?hash="+fs.Attr("sha256")), nil, nil)
	if st != 200 {
		t.Fatalf("download sent package: %d", st)
	}
}
