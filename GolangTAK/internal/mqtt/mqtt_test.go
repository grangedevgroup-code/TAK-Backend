package mqtt

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestMatch(t *testing.T) {
	cases := []struct {
		f, t string
		ok   bool
	}{
		{"msh/#", "msh/US/2/e/LongFast/!abcd", true},
		{"msh/+/2/e/+/+", "msh/US/2/e/LongFast/!abcd", true},
		{"msh/+/2/e/+/+", "msh/US/2/json/LongFast/!abcd", false},
		{"a/b", "a/b", true},
		{"a/b", "a/b/c", false},
		{"a/#", "a", true},
		{"#", "$SYS/x", false},
		{"+/x", "/x", true},
	}
	for _, c := range cases {
		if Match(c.f, c.t) != c.ok {
			t.Fatalf("%s vs %s", c.f, c.t)
		}
	}
	for f, ok := range map[string]bool{"a/#": true, "a/#/b": false, "a/b#": false, "+": true, "a+/b": false, "": false} {
		if validFilter(f) != ok {
			t.Fatalf("filter %q", f)
		}
	}
}

func startBroker(t *testing.T, b *Broker) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go b.Serve(ln)
	t.Cleanup(func() {
		ln.Close()
		b.Close()
	})
	return "mqtt://" + ln.Addr().String()
}

func TestBrokerAndClient(t *testing.T) {
	got := make(chan Message, 10)
	b := &Broker{
		Auth: func(id, user, pass string, _ net.Addr) bool { return user == "node" && pass == "secret" },
		OnPublish: func(m Message) {
			got <- m
		},
	}
	url := startBroker(t, b)
	ctx := context.Background()
	if _, err := Dial(ctx, url, ClientOptions{ClientID: "bad", Username: "node", Password: "wrong"}); err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("bad password: %v", err)
	}
	sub, err := Dial(ctx, url, ClientOptions{ClientID: "sub", Username: "node", Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	if err := sub.Subscribe("msh/+/2/e/#"); err != nil {
		t.Fatal(err)
	}
	pub, err := Dial(ctx, "mqtt://node:secret@"+strings.TrimPrefix(url, "mqtt://"), ClientOptions{ClientID: "pub"})
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()
	if err := pub.Publish("msh/US/2/e/LongFast/!aabbccdd", []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if err := pub.Publish("other/topic", []byte("x")); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-sub.Messages():
		if m.Topic != "msh/US/2/e/LongFast/!aabbccdd" || string(m.Payload) != "\x01\x02\x03" {
			t.Fatalf("message %+v", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("subscriber did not receive the message")
	}
	select {
	case m := <-sub.Messages():
		t.Fatalf("unexpected %s", m.Topic)
	case <-time.After(300 * time.Millisecond):
	}
	for i := 0; i < 2; i++ {
		select {
		case m := <-got:
			if m.Client != "pub" {
				t.Fatalf("hook got %+v", m)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("publish hook not called")
		}
	}
	b.Publish("msh/US/2/e/LongFast/!server", []byte("down"))
	select {
	case m := <-sub.Messages():
		if string(m.Payload) != "down" {
			t.Fatalf("%+v", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("broker publish not delivered")
	}
	if b.Clients() != 2 {
		t.Fatalf("clients %d", b.Clients())
	}
}

func TestQoS1AndPing(t *testing.T) {
	b := &Broker{}
	url := startBroker(t, b)
	c, err := net.Dial("tcp", strings.TrimPrefix(url, "mqtt://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := bufio.NewReader(c)
	c.Write(encode(typeConnect, 0, str("MQTT"), []byte{4, 2}, u16(30), str("raw")))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	p, err := readPacket(r, 1024)
	if err != nil || p.kind != typeConnack || p.body[1] != 0 {
		t.Fatalf("connack %+v %v", p, err)
	}
	c.Write(publishPacket("a/b", []byte("hi"), 1, 77, false))
	p, err = readPacket(r, 1024)
	if err != nil || p.kind != typePuback || p.body[0] != 0 || p.body[1] != 77 {
		t.Fatalf("puback %+v %v", p, err)
	}
	c.Write(encode(typePingreq, 0))
	p, err = readPacket(r, 1024)
	if err != nil || p.kind != typePingresp {
		t.Fatalf("pingresp %+v %v", p, err)
	}
	c.Write(encode(typeConnect, 0, str("MQTT"), []byte{5, 2}, u16(30), str("v5")))
	c2, _ := net.Dial("tcp", strings.TrimPrefix(url, "mqtt://"))
	defer c2.Close()
	c2.Write(encode(typeConnect, 0, str("MQTT"), []byte{5, 2}, u16(30), str("v5")))
	c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	p, err = readPacket(bufio.NewReader(c2), 1024)
	if err != nil || p.kind != typeConnack || p.body[1] != 1 {
		t.Fatalf("mqtt 5 should be refused with code 1: %+v %v", p, err)
	}
}
