package server

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTokenBucket(t *testing.T) {
	var b tokenBucket
	now := time.Unix(1000, 0)
	got := 0
	for i := 0; i < 20; i++ {
		if b.allow(2, 5, now) {
			got++
		}
	}
	if got != 5 {
		t.Fatalf("burst allowed %d, want 5", got)
	}
	if !b.allow(2, 5, now.Add(600*time.Millisecond)) || b.allow(2, 5, now.Add(600*time.Millisecond)) {
		t.Fatal("refill after 0.6s at 2/s should allow exactly one")
	}
	if !b.allow(0, 0, now) {
		t.Fatal("rate 0 must not limit")
	}
}

func TestConnLimiter(t *testing.T) {
	var l connLimiter
	now := time.Unix(1000, 0)
	for i := 0; i < 3; i++ {
		if !l.allow("10.0.0.1", 3, now) {
			t.Fatalf("connection %d refused", i)
		}
	}
	if l.allow("10.0.0.1", 3, now) {
		t.Fatal("fourth connection in a minute allowed")
	}
	if !l.allow("10.0.0.2", 3, now) {
		t.Fatal("other address refused")
	}
	if !l.allow("10.0.0.1", 3, now.Add(61*time.Second)) {
		t.Fatal("not allowed again after a minute")
	}
}

func TestRateLimitsOnStreams(t *testing.T) {
	s := newTestServer(t, func(c *Config) {
		c.RateLimits = RateLimitConfig{Enabled: true, ReadPerSec: 1, ReadBurst: 5, DeliveryPerSec: 1000, DeliveryBurst: 1000, ConnectPerMinute: 4}
	})
	rx := dialTCP(t, s)
	rx.send(saXML("rate-rx", "RX", 1, 1))
	tx := dialTCP(t, s)
	time.Sleep(200 * time.Millisecond)
	for i := 0; i < 30; i++ {
		tx.send(saXML(fmt.Sprintf("rate-tx-%d", i), "TX", 1, 1))
	}
	tx.send(chatXML("rate-tx-0", "TX", "RX", "rate-rx", "still delivered"))
	seen := 0
	chat := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		e, err := rx.next(500 * time.Millisecond)
		if err != nil {
			break
		}
		switch {
		case strings.HasPrefix(e.UID, "rate-tx-") && e.Type != "b-t-f":
			seen++
		case e.Type == "b-t-f":
			chat = true
		}
	}
	if seen < 5 || seen > 7 {
		t.Fatalf("received %d position updates, want about the burst of 5", seen)
	}
	if !chat {
		t.Fatal("chat was rate limited")
	}
	if s.hub.RateDropped.Load() == 0 {
		t.Fatal("no drops counted")
	}

	addr := "127.0.0.1:" + strconv.Itoa(s.Config().Ports.TCP)
	refused := false
	for i := 0; i < 6; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 1)
		if _, err := c.Read(buf); err != nil && !isTimeout(err) {
			refused = true
		}
		c.Close()
	}
	if !refused {
		t.Fatal("connection flood was not refused")
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
