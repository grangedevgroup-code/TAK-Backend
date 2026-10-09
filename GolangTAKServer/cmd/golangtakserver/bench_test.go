package main

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/takproto"
)

func fakeHub(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	conns := map[net.Conn]bool{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns[c] = true
			mu.Unlock()
			go func() {
				defer func() {
					mu.Lock()
					delete(conns, c)
					mu.Unlock()
					c.Close()
				}()
				r := takproto.NewReader(c, 1<<20)
				for {
					fr, err := r.Next()
					if err != nil {
						return
					}
					mu.Lock()
					for o := range conns {
						if o != c {
							o.Write(fr.Data)
						}
					}
					mu.Unlock()
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestBench(t *testing.T) {
	addr := fakeHub(t)
	res := runBench(benchOptions{addr: addr, clients: 8, every: 100 * time.Millisecond, duration: 2 * time.Second, ramp: 200 * time.Millisecond, out: io.Discard})
	if res.Connected != 8 || res.Failed != 0 {
		t.Fatalf("connected %d, failed %d: %s", res.Connected, res.Failed, res.FirstError)
	}
	if res.Sent < 80 {
		t.Fatalf("sent only %d", res.Sent)
	}
	if res.Received == 0 || float64(res.Received) < 0.8*res.Expected {
		t.Fatalf("received %d of %.0f expected", res.Received, res.Expected)
	}
	if res.P50 < 0 || res.P50 > time.Second || res.Max < res.P99 || res.Max <= 0 {
		t.Fatalf("latency %v %v %v", res.P50, res.P99, res.Max)
	}

	dead := runBench(benchOptions{addr: "127.0.0.1:1", clients: 2, every: time.Second, duration: time.Second, out: io.Discard})
	if dead.Connected != 0 || dead.Failed != 2 || dead.FirstError == "" {
		t.Fatalf("unreachable server: %+v", dead)
	}
}
