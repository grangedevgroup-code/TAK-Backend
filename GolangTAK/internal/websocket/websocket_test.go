package websocket

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func echoServer(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := Accept(w, r, []string{"cot"})
		if err != nil {
			return
		}
		c.MaxMessage = 1 << 20
		defer c.CloseNow()
		for {
			op, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			if string(msg) == "close-me" {
				c.Close(CloseGoingAway, "bye")
				return
			}
			c.WriteMessage(op, msg)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestEcho(t *testing.T) {
	srv := echoServer(t)
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	c, _, err := Dial(context.Background(), url+"/path?x=1", &DialOptions{Subprotocols: []string{"other", "cot"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	if c.Subprotocol() != "cot" {
		t.Fatalf("subprotocol %q", c.Subprotocol())
	}
	for _, size := range []int{0, 1, 125, 126, 65535, 65536, 300000} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		if err := c.WriteBinary(payload); err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		op, got, err := c.ReadMessage()
		if err != nil || op != OpBinary || !bytes.Equal(got, payload) {
			t.Fatalf("size %d: op=%d err=%v len=%d", size, op, err, len(got))
		}
	}
	if err := c.WriteText("<event uid=\"a\"/>"); err != nil {
		t.Fatal(err)
	}
	if op, got, _ := c.ReadMessage(); op != OpText || string(got) != "<event uid=\"a\"/>" {
		t.Fatal("text echo")
	}
	if err := c.Ping([]byte("p")); err != nil {
		t.Fatal(err)
	}
	c.WriteText("still alive")
	if _, got, _ := c.ReadMessage(); string(got) != "still alive" {
		t.Fatal("after ping")
	}
	c.writeFrameRaw(t, OpText, false, []byte("frag-"))
	c.writeFrameRaw(t, OpPing, true, []byte("mid"))
	c.writeFrameRaw(t, OpContinuation, true, []byte("ment"))
	if _, got, err := c.ReadMessage(); err != nil || string(got) != "frag-ment" {
		t.Fatalf("fragmented: %q %v", got, err)
	}
	c.WriteText("close-me")
	_, _, err = c.ReadMessage()
	var ce *CloseError
	if !errors.As(err, &ce) || ce.Code != CloseGoingAway || ce.Reason != "bye" {
		t.Fatalf("close: %v", err)
	}
}

func (c *Conn) writeFrameRaw(t *testing.T, op int, fin bool, payload []byte) {
	t.Helper()
	b0 := byte(op)
	if fin {
		b0 |= 0x80
	}
	key := []byte{1, 2, 3, 4}
	out := []byte{b0, 0x80 | byte(len(payload))}
	out = append(out, key...)
	for i, p := range payload {
		out = append(out, p^key[i&3])
	}
	if _, err := c.conn.Write(out); err != nil {
		t.Fatal(err)
	}
}

func TestLimitAndBadHandshake(t *testing.T) {
	srv := echoServer(t)
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	c, _, err := Dial(context.Background(), url, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.WriteBinary(make([]byte, 2<<20))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err = c.ReadMessage()
	var ce *CloseError
	if !errors.As(err, &ce) || ce.Code != CloseTooBig {
		t.Fatalf("want CloseTooBig, got %v", err)
	}
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("plain GET status %d", resp.StatusCode)
	}
	if _, _, err := Dial(context.Background(), "ftp://x", nil); err == nil {
		t.Fatal("bad scheme accepted")
	}
}
