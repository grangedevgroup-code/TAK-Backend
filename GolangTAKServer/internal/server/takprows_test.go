package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/takproto"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/websocket"
)

func dialTakProtoWS(t *testing.T, port int, h http.Header) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.Dial(context.Background(), "ws://127.0.0.1:"+strconv.Itoa(port)+"/takproto/1", &websocket.DialOptions{Header: h})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.CloseNow() })
	return conn
}

func readTakProtoWS(t *testing.T, conn *websocket.Conn, uid string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn.SetReadDeadline(deadline)
		op, data, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("waiting for %s: %v", uid, err)
		}
		if op != websocket.OpBinary || len(data) == 0 || data[0] != takproto.Magic {
			t.Fatalf("expected a binary TAK protobuf stream frame, got op %d %q", op, data)
		}
		fr := takproto.NewReader(bytes.NewReader(data), 1<<20)
		f, err := fr.Next()
		if err != nil || !f.Proto {
			t.Fatalf("frame %v %v", f, err)
		}
		e, err := takproto.UnmarshalEvent(f.Data)
		if err != nil {
			t.Fatal(err)
		}
		if e.UID == uid {
			return
		}
	}
	t.Fatalf("no %s over /takproto/1", uid)
}

func TestTakProtoWebSocket(t *testing.T) {
	s := newTestServer(t, func(c *Config) { c.AllowAnonymous = true })
	a := adminHeaders(t, s)
	h := http.Header{"Authorization": {a["Authorization"]}}
	for _, port := range []int{s.Config().Ports.HTTP, s.Config().Ports.WebSocket} {
		ws := dialTakProtoWS(t, port, h)
		tcp := dialTCP(t, s)
		time.Sleep(100 * time.Millisecond)
		tcp.send(saXML("XML-"+strconv.Itoa(port), "XMLCALL", 1, 1))
		readTakProtoWS(t, ws, "XML-"+strconv.Itoa(port))
		ev, err := cot.Parse([]byte(saXML("PB-"+strconv.Itoa(port), "PBCALL", 2, 2)))
		if err != nil {
			t.Fatal(err)
		}
		pb := takproto.Marshal(ev)
		if err := ws.WriteBinary(takproto.AppendStreamFrame(nil, pb)); err != nil {
			t.Fatal(err)
		}
		tcp.expect(uidIs("PB-"+strconv.Itoa(port)), "framed protobuf from /takproto/1")
		ev.UID = "RAW-" + strconv.Itoa(port)
		if err := ws.WriteBinary(takproto.Marshal(ev)); err != nil {
			t.Fatal(err)
		}
		tcp.expect(uidIs("RAW-"+strconv.Itoa(port)), "unframed protobuf from /takproto/1")
		ws.WriteText("<event/>")
		ws.SetReadDeadline(time.Now().Add(3 * time.Second))
		for {
			_, _, err := ws.ReadMessage()
			if err == nil {
				continue
			}
			var ce *websocket.CloseError
			if !errors.As(err, &ce) || ce.Code != websocket.CloseUnsupportedData {
				t.Fatalf("text frame: %v", err)
			}
			break
		}
	}
}

func TestTakProtoWebSocketRequiresAuth(t *testing.T) {
	s := newTestServer(t, func(c *Config) { c.AllowAnonymous = false })
	_, resp, err := websocket.Dial(context.Background(), "ws://127.0.0.1:"+strconv.Itoa(s.Config().Ports.HTTP)+"/takproto/1", nil)
	if err == nil {
		t.Fatal("anonymous /takproto/1 accepted")
	}
	if resp != nil && resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}
	r, err := http.Get(plainURL(s, "/takproto/1"))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("plain GET status %d", r.StatusCode)
	}
}
