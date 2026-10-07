package mqtt

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Message struct {
	Topic   string
	Payload []byte
	Client  string
}

type Broker struct {
	Auth      func(clientID, username, password string, remote net.Addr) bool
	OnPublish func(m Message)
	Log       *slog.Logger
	MaxPacket int

	mu       sync.RWMutex
	sessions map[*session]struct{}
	closed   atomic.Bool
	wg       sync.WaitGroup
}

type session struct {
	b    *Broker
	conn net.Conn
	id   string
	user string
	mu   sync.Mutex
	subs []string
	out  chan []byte
	done chan struct{}
	once sync.Once
}

func (b *Broker) logger() *slog.Logger {
	if b.Log != nil {
		return b.Log
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func (b *Broker) Serve(ln net.Listener) error {
	b.mu.Lock()
	if b.sessions == nil {
		b.sessions = map[*session]struct{}{}
	}
	b.mu.Unlock()
	for {
		c, err := ln.Accept()
		if err != nil {
			if b.closed.Load() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			b.handle(c)
		}()
	}
}

func (b *Broker) Close() {
	b.closed.Store(true)
	b.mu.RLock()
	for s := range b.sessions {
		s.close()
	}
	b.mu.RUnlock()
	b.wg.Wait()
}

func (b *Broker) Clients() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.sessions)
}

func (b *Broker) Publish(topic string, payload []byte) {
	b.deliver(Message{Topic: topic, Payload: payload}, nil)
}

func (b *Broker) deliver(m Message, from *session) {
	pkt := publishPacket(m.Topic, m.Payload, 0, 0, false)
	b.mu.RLock()
	defer b.mu.RUnlock()
	for s := range b.sessions {
		if s == from {
			continue
		}
		if !s.subscribed(m.Topic) {
			continue
		}
		select {
		case s.out <- pkt:
		default:
		}
	}
}

func (s *session) subscribed(topic string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.subs {
		if Match(f, topic) {
			return true
		}
	}
	return false
}

func (s *session) close() {
	s.once.Do(func() {
		close(s.done)
		s.conn.Close()
	})
}

func (s *session) writer() {
	for {
		select {
		case <-s.done:
			return
		case p := <-s.out:
			s.conn.SetWriteDeadline(time.Now().Add(20 * time.Second))
			if _, err := s.conn.Write(p); err != nil {
				s.close()
				return
			}
		}
	}
}

func (s *session) send(p []byte) {
	select {
	case s.out <- p:
	case <-s.done:
	case <-time.After(5 * time.Second):
		s.close()
	}
}

func (b *Broker) handle(c net.Conn) {
	limit := b.MaxPacket
	if limit <= 0 {
		limit = 1 << 20
	}
	r := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	p, err := readPacket(r, limit)
	if err != nil || p.kind != typeConnect {
		c.Close()
		return
	}
	rd := &reader{b: p.body}
	proto := rd.string()
	level := rd.byte()
	flags := rd.byte()
	keepAlive := rd.uint16()
	clientID := rd.string()
	if flags&0x04 != 0 {
		rd.string()
		rd.bytes()
	}
	var user, pass string
	if flags&0x80 != 0 {
		user = rd.string()
	}
	if flags&0x40 != 0 {
		pass = string(rd.bytes())
	}
	if rd.err != nil || (proto != "MQTT" && proto != "MQIsdp") {
		c.Close()
		return
	}
	if level != 3 && level != 4 {
		c.Write(encode(typeConnack, 0, []byte{0, 1}))
		c.Close()
		return
	}
	if b.Auth != nil && !b.Auth(clientID, user, pass, c.RemoteAddr()) {
		c.Write(encode(typeConnack, 0, []byte{0, 5}))
		b.logger().Warn("mqtt client refused", "client", clientID, "user", user, "remote", c.RemoteAddr())
		c.Close()
		return
	}
	s := &session{b: b, conn: c, id: clientID, user: user, out: make(chan []byte, 512), done: make(chan struct{})}
	b.mu.Lock()
	if b.sessions == nil {
		b.sessions = map[*session]struct{}{}
	}
	b.sessions[s] = struct{}{}
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.sessions, s)
		b.mu.Unlock()
		s.close()
	}()
	go s.writer()
	s.send(encode(typeConnack, 0, []byte{0, 0}))
	b.logger().Info("mqtt client connected", "client", clientID, "user", user, "remote", c.RemoteAddr())
	idle := time.Duration(keepAlive) * time.Second * 3 / 2
	if keepAlive == 0 {
		idle = 30 * time.Minute
	}
	for {
		c.SetReadDeadline(time.Now().Add(idle))
		p, err := readPacket(r, limit)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				b.logger().Debug("mqtt client dropped", "client", clientID, "err", err)
			}
			return
		}
		switch p.kind {
		case typePublish:
			qos := (p.flags >> 1) & 3
			rd := &reader{b: p.body}
			topic := rd.string()
			var id uint16
			if qos > 0 {
				id = rd.uint16()
			}
			if rd.err != nil || qos > 2 || !validTopic(topic) {
				return
			}
			payload := append([]byte(nil), rd.b...)
			if qos == 1 {
				s.send(encode(typePuback, 0, u16(id)))
			} else if qos == 2 {
				s.send(encode(typePubrec, 0, u16(id)))
			}
			m := Message{Topic: topic, Payload: payload, Client: clientID}
			b.deliver(m, s)
			if b.OnPublish != nil {
				b.OnPublish(m)
			}
		case typePubrel:
			rd := &reader{b: p.body}
			id := rd.uint16()
			s.send(encode(typePubcomp, 0, u16(id)))
		case typeSubscribe:
			rd := &reader{b: p.body}
			id := rd.uint16()
			var codes []byte
			var added []string
			for len(rd.b) > 0 && rd.err == nil {
				f := rd.string()
				rd.byte()
				if rd.err != nil {
					break
				}
				if !validFilter(f) {
					codes = append(codes, 0x80)
					continue
				}
				added = append(added, f)
				codes = append(codes, 0)
			}
			if rd.err != nil || len(codes) == 0 {
				return
			}
			s.mu.Lock()
			for _, f := range added {
				dup := false
				for _, x := range s.subs {
					if x == f {
						dup = true
					}
				}
				if !dup {
					s.subs = append(s.subs, f)
				}
			}
			s.mu.Unlock()
			s.send(encode(typeSuback, 0, u16(id), codes))
			if len(added) > 0 {
				b.logger().Debug("mqtt subscribe", "client", clientID, "topics", strings.Join(added, " "))
			}
		case typeUnsubscribe:
			rd := &reader{b: p.body}
			id := rd.uint16()
			var gone []string
			for len(rd.b) > 0 && rd.err == nil {
				gone = append(gone, rd.string())
			}
			s.mu.Lock()
			keep := s.subs[:0]
			for _, x := range s.subs {
				drop := false
				for _, g := range gone {
					if g == x {
						drop = true
					}
				}
				if !drop {
					keep = append(keep, x)
				}
			}
			s.subs = keep
			s.mu.Unlock()
			s.send(encode(typeUnsuback, 0, u16(id)))
		case typePingreq:
			s.send(encode(typePingresp, 0))
		case typeDisconnect:
			return
		case typePuback, typePubrec, typePubcomp:
		default:
			return
		}
	}
}
