package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
)

func TestQoSLimiters(t *testing.T) {
	s := newTestServer(t, nil)
	a := adminHeaders(t, s)
	put := func(path, body string) {
		t.Helper()
		if st, b := doReq(t, http.DefaultClient, "PUT", plainURL(s, path), strings.NewReader(body), a); st != 200 {
			t.Fatalf("%s: %d %s", path, st, b)
		}
	}
	put("/Marti/api/qos/delivery/set", `[{"clientThresholdCount":0,"reportingRateLimitSeconds":60}]`)
	put("/Marti/api/qos/delivery/enable", "true")
	tx := dialTCP(t, s)
	rx := dialTCP(t, s)
	rx.send(saXML("RX", "RX", 1, 1))
	tx.send(saXML("TX", "TX", 1, 1))
	rx.expect(func(e *cot.Event) bool { return e.UID == "TX" }, "first report delivered")
	tx.send(saXML("TX", "TX", 2, 2))
	rx.expectNone(func(e *cot.Event) bool { return e.UID == "TX" }, "second report within the limit", 600*time.Millisecond)
	_, b := doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/qos/ratelimit/delivery/active"), nil, a)
	if !strings.Contains(string(b), `"data":60`) {
		t.Fatalf("active delivery limit: %s", b)
	}
	put("/Marti/api/qos/delivery/enable", "false")
	put("/Marti/api/qos/read/set", `[{"clientThresholdCount":0,"reportingRateLimitSeconds":60}]`)
	put("/Marti/api/qos/read/enable", "true")
	tx2 := dialTCP(t, s)
	tx2.send(saXML("TX2", "TX2", 1, 1))
	rx.expect(func(e *cot.Event) bool { return e.UID == "TX2" }, "first read accepted")
	tx2.send(saXML("TX2", "TX2", 3, 3))
	rx.expectNone(func(e *cot.Event) bool { return e.UID == "TX2" }, "second read dropped", 600*time.Millisecond)
	chat := cot.New("chat-1", "b-t-f", "h-g-i-g-o", time.Minute)
	tx2.send(chat.String())
	rx.expect(func(e *cot.Event) bool { return e.UID == "chat-1" }, "chat is never limited")
	_, b = doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/qos/conf"), nil, a)
	if !strings.Contains(string(b), `"readRateLimiter":{"enabled":true`) {
		t.Fatalf("qos conf: %s", b)
	}
}
