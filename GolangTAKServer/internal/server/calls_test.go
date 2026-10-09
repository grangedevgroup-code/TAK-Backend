package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/websocket"
)

type callTestConn struct {
	t    *testing.T
	c    *websocket.Conn
	id   string
	msgs chan map[string]any
}

func dialCalls(t *testing.T, s *Server, user string, groups []string) *callTestConn {
	t.Helper()
	s.dir.AddUser(user, user+"-password", false, groups)
	tok, _, err := s.dir.CreateToken(user, "api", "calls", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	c, _, err := websocket.Dial(context.Background(), strings.Replace(plainURL(s, "/api/calls/ws"), "http://", "ws://", 1), &websocket.DialOptions{Header: h})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.CloseNow() })
	tc := &callTestConn{t: t, c: c, msgs: make(chan map[string]any, 64)}
	go func() {
		for {
			_, b, err := c.ReadMessage()
			if err != nil {
				close(tc.msgs)
				return
			}
			var m map[string]any
			json.Unmarshal(b, &m)
			tc.msgs <- m
		}
	}()
	hello := tc.expect("hello")
	tc.id = hello["id"].(string)
	return tc
}

func (c *callTestConn) send(v map[string]any) {
	b, _ := json.Marshal(v)
	c.c.WriteText(string(b))
}

func (c *callTestConn) expect(kind string) map[string]any {
	c.t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case m, ok := <-c.msgs:
			if !ok {
				c.t.Fatalf("connection closed waiting for %s", kind)
			}
			if m["t"] == kind {
				return m
			}
		case <-deadline:
			c.t.Fatalf("no %s message", kind)
		}
	}
}

func (c *callTestConn) expectNone(kind string, wait time.Duration) {
	c.t.Helper()
	deadline := time.After(wait)
	for {
		select {
		case m := <-c.msgs:
			if m["t"] == kind {
				c.t.Fatalf("unexpected %s: %v", kind, m)
			}
		case <-deadline:
			return
		}
	}
}

func TestCallSignalling(t *testing.T) {
	s := newTestServer(t, nil)
	alice := dialCalls(t, s, "calla", []string{"Blue"})
	bob := dialCalls(t, s, "callb", []string{"Blue"})
	carol := dialCalls(t, s, "callc", []string{"Red"})

	p := alice.expect("presence")
	for p["users"] == nil || !strings.Contains(strings.Join(toStrings(p["users"]), ","), "callb") {
		p = alice.expect("presence")
	}
	if strings.Contains(strings.Join(toStrings(p["users"]), ","), "callc") {
		t.Fatal("a user in another group is offered for calls")
	}

	alice.send(map[string]any{"t": "ring", "room": "room-0001", "to": []string{"callb", "callc"}, "video": true})
	r := bob.expect("ring")
	if r["from"] != "calla" || r["room"] != "room-0001" || r["video"] != true {
		t.Fatalf("ring %v", r)
	}
	carol.expectNone("ring", 300*time.Millisecond)

	alice.send(map[string]any{"t": "join", "room": "room-0001"})
	if peers := alice.expect("peers"); len(peers["peers"].([]any)) != 0 {
		t.Fatalf("first joiner sees peers %v", peers)
	}
	carol.send(map[string]any{"t": "join", "room": "room-0001"})
	if e := carol.expect("error"); !strings.Contains(e["error"].(string), "not invited") {
		t.Fatalf("uninvited join: %v", e)
	}
	bob.send(map[string]any{"t": "join", "room": "room-0001"})
	peers := bob.expect("peers")["peers"].([]any)
	if len(peers) != 1 || peers[0].(map[string]any)["id"] != alice.id {
		t.Fatalf("peers %v", peers)
	}
	if j := alice.expect("joined"); j["peer"] != bob.id {
		t.Fatalf("joined %v", j)
	}

	bob.send(map[string]any{"t": "signal", "to": alice.id, "data": map[string]any{"description": map[string]string{"type": "offer", "sdp": "v=0"}}})
	sig := alice.expect("signal")
	if sig["from"] != bob.id || sig["user"] != "callb" {
		t.Fatalf("signal %v", sig)
	}
	carol.send(map[string]any{"t": "signal", "to": alice.id, "data": map[string]any{"x": 1}})
	alice.expectNone("signal", 300*time.Millisecond)

	bob.send(map[string]any{"t": "leave"})
	if l := alice.expect("left"); l["peer"] != bob.id {
		t.Fatalf("left %v", l)
	}

	st, body := doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/calls"), nil, map[string]string{"basic": "calla:calla-password"})
	if st != 200 || !strings.Contains(string(body), `"enabled":true`) {
		t.Fatalf("calls info: %d %s", st, body)
	}
}

func toStrings(v any) []string {
	var out []string
	if list, ok := v.([]any); ok {
		for _, x := range list {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
