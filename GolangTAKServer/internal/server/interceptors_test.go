package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/websocket"
)

func TestPluginInterceptor(t *testing.T) {
	s := newTestServer(t, nil)
	a := adminHeaders(t, s)
	u := "ws://127.0.0.1:" + strconv.Itoa(s.Config().Ports.HTTP) + "/api/plugins/intercept?types=a-*&timeoutMs=2000"
	conn, _, err := websocket.Dial(context.Background(), u, &websocket.DialOptions{Header: http.Header{"Authorization": {a["Authorization"]}}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	go func() {
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var m struct {
				ID  uint64 `json:"id"`
				XML string `json:"xml"`
				UID string `json:"uid"`
			}
			json.Unmarshal(data, &m)
			reply := map[string]any{"id": m.ID, "action": "pass"}
			switch {
			case strings.HasPrefix(m.UID, "DROP"):
				reply["action"] = "drop"
			case strings.HasPrefix(m.UID, "EDIT"):
				reply["action"], reply["xml"] = "replace", strings.Replace(m.XML, `callsign="EDIT"`, `callsign="EDITED"`, 1)
			}
			b, _ := json.Marshal(reply)
			conn.WriteText(string(b))
		}
	}()
	waitFor(t, "interceptor attached", 3*time.Second, func() bool { return len(s.intercept.active()) == 1 })
	rx := dialTCP(t, s)
	tx := dialTCP(t, s)
	rx.send(saXML("RX-I", "RXI", 1, 1))
	time.Sleep(200 * time.Millisecond)
	tx.send(saXML("DROP-1", "DROP", 1, 1))
	tx.send(saXML("EDIT-1", "EDIT", 1, 1))
	got := rx.expect(uidIs("EDIT-1"), "edited event")
	if got.Callsign() != "EDITED" {
		t.Fatalf("event not replaced: %s", got.XML())
	}
	rx.expectNone(uidIs("DROP-1"), "dropped event", 300*time.Millisecond)
	chat := cot.New("DROP-chat", "b-t-f", "h-g-i-g-o", time.Minute)
	tx.send(chat.String())
	rx.expect(uidIs("DROP-chat"), "types outside the interceptor filter pass untouched")
}
