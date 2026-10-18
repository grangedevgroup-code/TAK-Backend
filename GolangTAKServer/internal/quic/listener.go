package quic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
)

const ALPN = "takstream"

type Listener struct {
	pc        net.PacketConn
	cfg       *tls.Config
	idle      time.Duration
	mu        sync.Mutex
	conns     map[string]*Conn
	accept    chan *Stream
	done      chan struct{}
	closeOnce sync.Once
	MaxConns  int
}

func serverConfig(cfg *tls.Config) *tls.Config {
	c := cfg.Clone()
	c.NextProtos = []string{ALPN}
	c.MinVersion, c.MaxVersion = tls.VersionTLS13, 0
	if gc := c.GetConfigForClient; gc != nil {
		c.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			nc, err := gc(h)
			if nc == nil || err != nil {
				return nc, err
			}
			nc = nc.Clone()
			nc.NextProtos = []string{ALPN}
			nc.MinVersion, nc.MaxVersion = tls.VersionTLS13, 0
			nc.GetConfigForClient = nil
			return nc, nil
		}
	}
	return c
}

func Listen(pc net.PacketConn, cfg *tls.Config, idle time.Duration) *Listener {
	l := &Listener{pc: pc, cfg: serverConfig(cfg), idle: idle, conns: map[string]*Conn{}, accept: make(chan *Stream, 64), done: make(chan struct{})}
	go l.readLoop()
	return l
}

func (l *Listener) Addr() net.Addr { return l.pc.LocalAddr() }

func (l *Listener) Accept() (*Stream, error) {
	select {
	case st := <-l.accept:
		return st, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *Listener) Conns() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	seen := map[*Conn]bool{}
	for _, c := range l.conns {
		seen[c] = true
	}
	return len(seen)
}

func longIDs(b []byte) (version uint32, dcid, scid []byte, ok bool) {
	if len(b) < 7 || b[0]&0x80 == 0 {
		return 0, nil, nil, false
	}
	version = binary.BigEndian.Uint32(b[1:5])
	dl := int(b[5])
	if dl > 20 || len(b) < 7+dl {
		return 0, nil, nil, false
	}
	dcid = b[6 : 6+dl]
	sl := int(b[6+dl])
	if sl > 20 || len(b) < 7+dl+sl {
		return 0, nil, nil, false
	}
	return version, dcid, b[7+dl : 7+dl+sl], true
}

func (l *Listener) readLoop() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := l.pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-l.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				l.Close()
				return
			}
			time.Sleep(time.Millisecond)
			continue
		}
		if n == 0 {
			continue
		}
		d := buf[:n]
		var key []byte
		var newConn bool
		var version uint32
		var dcid, scid []byte
		if d[0]&0x80 == 0 {
			if n < 1+cidLen {
				continue
			}
			key = d[1 : 1+cidLen]
		} else {
			var ok bool
			if version, dcid, scid, ok = longIDs(d); !ok {
				continue
			}
			key = dcid
		}
		l.mu.Lock()
		c := l.conns[string(key)]
		if c == nil && d[0]&0x80 != 0 {
			switch {
			case version != version1:
				if n >= minInitial && version != 0 {
					l.pc.WriteTo(versionNegotiation(scid, dcid), addr)
				}
			case (d[0]>>4)&0x3 == byte(ptInitial) && n >= minInitial && len(dcid) >= 8:
				if l.MaxConns <= 0 || len(l.conns)/2 < l.MaxConns {
					c = l.newServerConn(addr, dcid, scid)
					newConn = c != nil
				}
			}
		}
		l.mu.Unlock()
		if c == nil {
			continue
		}
		if newConn {
			go c.run(l.remover(c))
		}
		select {
		case c.in <- datagram{append([]byte(nil), d...), addr}:
		default:
		}
	}
}

func (l *Listener) newServerConn(addr net.Addr, dcid, scid []byte) *Conn {
	c := newConn(false, l.pc, addr, l.idle)
	c.ourCID = randomCID()
	c.origDCID = append([]byte(nil), dcid...)
	c.peerCID = append([]byte(nil), scid...)
	c.spaces[spInitial].rx, c.spaces[spInitial].tx = initialKeys(c.origDCID, true)
	c.onStream = func(st *Stream) {
		go func() {
			select {
			case l.accept <- st:
			case <-l.done:
				st.c.Close()
			case <-st.c.done:
			}
		}()
	}
	if err := c.startTLS(l.cfg); err != nil {
		return nil
	}
	l.conns[string(c.ourCID)] = c
	l.conns[string(c.origDCID)] = c
	return c
}

func (l *Listener) remover(c *Conn) func() {
	return func() {
		l.mu.Lock()
		if l.conns[string(c.ourCID)] == c {
			delete(l.conns, string(c.ourCID))
		}
		if l.conns[string(c.origDCID)] == c {
			delete(l.conns, string(c.origDCID))
		}
		l.mu.Unlock()
	}
}

func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
		l.mu.Lock()
		var all []*Conn
		seen := map[*Conn]bool{}
		for _, c := range l.conns {
			if !seen[c] {
				seen[c] = true
				all = append(all, c)
			}
		}
		l.mu.Unlock()
		var wg sync.WaitGroup
		for _, c := range all {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c.mu.Lock()
				c.closing = true
				c.mu.Unlock()
				c.poke()
				select {
				case <-c.done:
				case <-time.After(200 * time.Millisecond):
				}
			}()
		}
		wg.Wait()
		l.pc.Close()
		for _, c := range all {
			c.mu.Lock()
			c.terminate(ErrClosed)
			c.mu.Unlock()
		}
	})
	return nil
}

func Dial(ctx context.Context, addr string, cfg *tls.Config, idle time.Duration) (*Stream, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	tc := cfg.Clone()
	if len(tc.NextProtos) == 0 {
		tc.NextProtos = []string{ALPN}
	}
	tc.MinVersion = tls.VersionTLS13
	c := newConn(true, pc, ua, idle)
	c.ourCID = randomCID()
	dcid := make([]byte, 8)
	copy(dcid, randomCID())
	c.peerCID = dcid
	c.spaces[spInitial].rx, c.spaces[spInitial].tx = initialKeys(dcid, false)
	if err := c.startTLS(tc); err != nil {
		pc.Close()
		return nil, err
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			select {
			case c.in <- datagram{append([]byte(nil), buf[:n]...), from}:
			case <-c.done:
				return
			}
		}
	}()
	go c.run(func() { pc.Close() })
	c.poke()
	select {
	case <-c.established:
	case <-c.done:
		if err := c.Err(); err != nil && !errors.Is(err, ErrClosed) {
			return nil, err
		}
		return nil, ErrClosed
	case <-ctx.Done():
		c.Close()
		return nil, ctx.Err()
	}
	c.mu.Lock()
	c.stream = newStream(c, 0)
	c.stream.peerMax = c.peer.maxStreamDataBR
	c.mu.Unlock()
	return c.stream, nil
}
