package server

import (
	"crypto/sha256"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/takproto"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/xmltree"
)

func decodeDatagram(b []byte) []*cot.Event {
	if len(b) == 0 {
		return nil
	}
	if b[0] == takproto.Magic {
		if payload, ok := takproto.ParseMesh(b); ok {
			if e, err := takproto.UnmarshalEvent(payload); err == nil {
				return []*cot.Event{e}
			}
		}
		return nil
	}
	nodes, _ := xmltree.ParseFragment(b)
	var out []*cot.Event
	for _, n := range nodes {
		if e, err := cot.FromNode(n); err == nil {
			out = append(out, e)
		}
	}
	return out
}

type dedupe struct {
	mu   sync.Mutex
	seen map[[16]byte]time.Time
}

func newDedupe() *dedupe { return &dedupe{seen: map[[16]byte]time.Time{}} }

func fingerprint(e *cot.Event) [16]byte {
	h := sha256.Sum256([]byte(e.UID + "|" + e.Type + "|" + cot.FormatTime(e.Time) + "|" + cot.FormatFloat(e.Point.Lat) + "|" + cot.FormatFloat(e.Point.Lon)))
	var k [16]byte
	copy(k[:], h[:16])
	return k
}

func (d *dedupe) mark(e *cot.Event) {
	d.mu.Lock()
	d.seen[fingerprint(e)] = time.Now()
	if len(d.seen) > 20000 {
		cut := time.Now().Add(-30 * time.Second)
		for k, t := range d.seen {
			if t.Before(cut) {
				delete(d.seen, k)
			}
		}
	}
	d.mu.Unlock()
}

func (d *dedupe) recent(e *cot.Event) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	t, ok := d.seen[fingerprint(e)]
	return ok && time.Since(t) < 30*time.Second
}

func (s *Server) relayClient(kind, name, remote string, groups []string) *Client {
	id := s.dir.Anonymous()
	if len(groups) > 0 {
		m := s.dir.Mask(groups)
		if !m.Empty() {
			id = &Identity{Via: kind, In: m, Out: m, Anon: true}
		}
	}
	c := s.hub.NewClient(kind, remote, id)
	c.Name = name
	c.authed.Store(true)
	return c
}

func (s *Server) startUDP() error {
	cfg := s.Config()
	if cfg.Ports.UDP <= 0 {
		return nil
	}
	addr := s.addr(cfg.Ports.UDP)
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return portError("udp", addr, err)
	}
	s.track(pc)
	c := s.relayClient(KindUDP, "UDP input", addr, nil)
	c.filter = func(*Message) bool { return false }
	s.hub.Add(c)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.hub.Remove(c)
		buf := make([]byte, 65536)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) || s.ctx.Err() != nil {
					return
				}
				continue
			}
			if !s.Config().AllowAnonymous {
				continue
			}
			for _, e := range decodeDatagram(append([]byte(nil), buf[:n]...)) {
				c.touch()
				s.ingestRelay(c, e, from.String())
			}
		}
	}()
	return nil
}

func (s *Server) ingestRelay(c *Client, e *cot.Event, from string) {
	if e.IsPing() || consumedTypes[e.Type] || strings.HasPrefix(e.Type, "t-x-takp") {
		return
	}
	if e.FlowTag(s.FlowKey()) != "" {
		return
	}
	m := NewMessage(e, c, c.InMask())
	s.hub.Identify(c, m)
	s.hub.Publish(m)
}

type meshGroup struct {
	addr *net.UDPAddr
	conn *net.UDPConn
	out  *net.UDPConn
	chat bool
}

func (s *Server) startMesh() error {
	cfg := s.Config()
	if !cfg.Mesh.Enabled || len(cfg.Mesh.Groups) == 0 {
		return nil
	}
	var ifi *net.Interface
	if cfg.Mesh.Interface != "" {
		i, err := net.InterfaceByName(cfg.Mesh.Interface)
		if err != nil {
			s.log.Warn("mesh interface not found; using the default", "interface", cfg.Mesh.Interface, "err", err)
		} else {
			ifi = i
		}
	}
	var groups []*meshGroup
	for _, g := range cfg.Mesh.Groups {
		addr, err := net.ResolveUDPAddr("udp4", g)
		if err != nil || !addr.IP.IsMulticast() {
			s.log.Warn("ignoring invalid mesh group", "group", g)
			continue
		}
		conn, err := net.ListenMulticastUDP("udp4", ifi, addr)
		if err != nil {
			s.log.Warn("mesh group unavailable on this network", "group", g, "err", err)
			continue
		}
		conn.SetReadBuffer(1 << 20)
		s.track(conn)
		mg := &meshGroup{addr: addr, conn: conn, chat: addr.Port == 17012}
		if cfg.Mesh.Send {
			out, err := net.DialUDP("udp4", nil, addr)
			if err == nil {
				s.track(out)
				mg.out = out
			}
		}
		groups = append(groups, mg)
	}
	if len(groups) == 0 {
		return nil
	}
	dd := newDedupe()
	c := s.relayClient(KindMesh, "Mesh (multicast)", "multicast", nil)
	if !cfg.Mesh.Send {
		c.filter = func(*Message) bool { return false }
	} else {
		c.filter = func(m *Message) bool { return m.Source == nil || m.Source.Kind != KindMesh }
	}
	s.hub.Add(c)
	for _, mg := range groups {
		mg := mg
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			buf := make([]byte, 65536)
			for {
				n, from, err := mg.conn.ReadFromUDP(buf)
				if err != nil {
					if errors.Is(err, net.ErrClosed) || s.ctx.Err() != nil {
						return
					}
					continue
				}
				if !s.Config().AllowAnonymous {
					continue
				}
				for _, e := range decodeDatagram(append([]byte(nil), buf[:n]...)) {
					if dd.recent(e) {
						continue
					}
					dd.mark(e)
					c.touch()
					s.ingestRelay(c, e, from.String())
				}
			}
		}()
	}
	if cfg.Mesh.Send {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for {
				select {
				case <-c.closed:
					return
				case <-s.ctx.Done():
					return
				case m := <-c.out:
					e := m.Event
					if e.IsControl() && !e.IsDelete() {
						continue
					}
					var payload []byte
					if cfg.Mesh.Protobuf {
						payload = takproto.MeshFrame(m.Proto())
					} else {
						payload = m.XML()
					}
					if len(payload) > 65000 {
						continue
					}
					dd.mark(e)
					for _, mg := range groups {
						if mg.out == nil || mg.chat != e.IsChat() {
							continue
						}
						mg.out.Write(payload)
						c.Sent()
					}
				}
			}
		}()
	}
	var names []string
	for _, mg := range groups {
		names = append(names, mg.addr.String())
	}
	s.log.Info("mesh bridge listening", "groups", strings.Join(names, " "), "sending", cfg.Mesh.Send)
	return nil
}

func SendUDP(target string, e *cot.Event, proto bool) error {
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	var b []byte
	if proto {
		b = takproto.MeshFrame(takproto.Marshal(e))
	} else {
		b = e.XML()
	}
	_, err = conn.Write(b)
	return err
}
