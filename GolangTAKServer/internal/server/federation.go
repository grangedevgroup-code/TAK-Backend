package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/pki"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/takproto"
)

type FederateStatus struct {
	Name      string    `json:"name"`
	Remote    string    `json:"remote"`
	Direction string    `json:"direction"`
	Since     time.Time `json:"since"`
	Contacts  int       `json:"contacts"`
	Rx        uint64    `json:"rx"`
	Tx        uint64    `json:"tx"`
	Version   string    `json:"version"`
}

type fedConn struct {
	c       *Client
	name    string
	dir     string
	since   time.Time
	version string
}

type Federation struct {
	s     *Server
	mu    sync.Mutex
	conns map[*Client]*fedConn
}

func newFederation(s *Server) *Federation {
	return &Federation{s: s, conns: map[*Client]*fedConn{}}
}

func (f *Federation) add(fc *fedConn) {
	f.mu.Lock()
	f.conns[fc.c] = fc
	f.mu.Unlock()
}

func (f *Federation) remove(c *Client) {
	f.mu.Lock()
	delete(f.conns, c)
	f.mu.Unlock()
}

func (f *Federation) clients() []*fedConn {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*fedConn, 0, len(f.conns))
	for _, fc := range f.conns {
		out = append(out, fc)
	}
	return out
}

func (s *Server) federationStatus() map[string]any {
	cfg := s.Config()
	list := []FederateStatus{}
	if s.fed != nil {
		for _, fc := range s.fed.clients() {
			fc.c.mu.Lock()
			n := len(fc.c.remote)
			fc.c.mu.Unlock()
			list = append(list, FederateStatus{Name: fc.name, Remote: fc.c.Remote, Direction: fc.dir, Since: fc.since, Contacts: n, Rx: fc.c.rx.Load(), Tx: fc.c.tx.Load(), Version: fc.version})
		}
	}
	return map[string]any{"enabled": cfg.Federation.Enabled, "port": cfg.Ports.Federation, "portV2": cfg.Ports.FederationV2, "groups": cfg.Federation.Groups, "trusted": len(cfg.Federation.TrustPEM), "federates": list}
}

func (s *Server) federationTrust() *x509.CertPool {
	pool := s.pki.ClientPool()
	for _, entry := range s.Config().Federation.TrustPEM {
		data := []byte(entry)
		if !strings.Contains(entry, "-----BEGIN") {
			b, err := os.ReadFile(strings.TrimSpace(entry))
			if err != nil {
				s.log.Warn("federation trust file unreadable", "file", entry, "err", err)
				continue
			}
			data = b
		}
		if certs, err := pki.ParseCertPEM(data); err == nil {
			for _, c := range certs {
				pool.AddCert(c)
			}
		} else if p, err := pki.DecodePKCS12(data, s.Config().Certificates.Password); err == nil {
			for _, c := range p.Certs {
				pool.AddCert(c)
			}
		}
	}
	return pool
}

func (s *Server) startFederation() error {
	cfg := s.Config()
	if !cfg.Federation.Enabled || cfg.Ports.Federation <= 0 {
		return nil
	}
	ln, err := s.listenTCP(cfg.Ports.Federation)
	if err != nil {
		return err
	}
	tcfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.pki.ServerCert(), nil
		},
	}
	tcfg.ClientCAs = s.federationTrust()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) || s.ctx.Err() != nil {
					return
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}
			go func() {
				fresh := tcfg.Clone()
				fresh.ClientCAs = s.federationTrust()
				tc := tls.Server(conn, fresh)
				tc.SetDeadline(time.Now().Add(20 * time.Second))
				if err := tc.Handshake(); err != nil {
					s.log.Warn("federate handshake failed", "remote", conn.RemoteAddr(), "err", err)
					conn.Close()
					return
				}
				tc.SetDeadline(time.Time{})
				name := conn.RemoteAddr().String()
				if pc := tc.ConnectionState().PeerCertificates; len(pc) > 0 {
					name = pc[0].Subject.CommonName
					if len(pc[0].Issuer.CommonName) > 0 {
						name += " (" + pc[0].Issuer.CommonName + ")"
					}
				}
				err := s.serveFederate(s.ctx, tc, name, "inbound", nil)
				s.log.Info("federate disconnected", "federate", name, "err", errString(err))
			}()
		}
	}()
	s.log.Info("federation listening", "port", cfg.Ports.Federation)
	return nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (s *Server) connectFederation(ctx context.Context, l *peerLink, u *url.URL) error {
	host := u.Hostname()
	port := firstNonEmpty(u.Port(), "9000")
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: s.federationTrust()}
	if l.cfg.CertFile != "" {
		cert, _, err := loadCertFile(l.cfg.CertFile, firstNonEmpty(l.cfg.CertPass, s.Config().Certificates.Password))
		if err != nil {
			return err
		}
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
	} else {
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return s.pki.ServerCert(), nil }
	}
	if l.cfg.TrustFile != "" {
		pool, err := loadTrust(l.cfg.TrustFile, firstNonEmpty(l.cfg.CertPass, s.Config().Certificates.Password))
		if err != nil {
			return err
		}
		cfg.RootCAs = pool
	}
	if l.cfg.Insecure {
		cfg.InsecureSkipVerify = true
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}, Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return err
	}
	l.set("connected", "")
	s.log.Info("federation link connected", "federate", l.cfg.Name, "remote", conn.RemoteAddr())
	return s.serveFederate(ctx, conn, l.cfg.Name, "outbound", l)
}

func (s *Server) fedGroups(m *Message, allowed []string) []string {
	if m.Everyone {
		return allowed
	}
	var out []string
	for _, g := range s.dir.Names(m.Groups) {
		if slices.Contains(allowed, g) {
			out = append(out, g)
		}
	}
	return out
}

func (s *Server) serveFederate(ctx context.Context, conn net.Conn, name, dir string, l *peerLink) error {
	defer conn.Close()
	cfg := s.Config()
	allowed := cfg.Federation.Groups
	if l != nil && len(l.cfg.Groups) > 0 {
		allowed = l.cfg.Groups
	}
	c := s.relayClient(KindFederation, name, conn.RemoteAddr().String(), allowed)
	c.onClose = func() { conn.Close() }
	if l != nil && strings.EqualFold(l.cfg.Direction, "in") {
		c.filter = func(*Message) bool { return false }
	}
	if l != nil {
		s.applyLinkArea(c, l.cfg.Area)
	}
	s.hub.Add(c)
	fc := &fedConn{c: c, name: name, dir: dir, since: time.Now(), version: "v1"}
	s.fed.add(fc)
	if l != nil {
		l.mu.Lock()
		l.client = c
		l.mu.Unlock()
	}
	defer func() {
		s.fed.remove(c)
		s.hub.Remove(c)
		if l != nil {
			l.mu.Lock()
			l.client = nil
			l.mu.Unlock()
		}
	}()
	s.log.Info("federate connected", "federate", name, "direction", dir, "remote", conn.RemoteAddr())
	bw := bufio.NewWriterSize(conn, 64<<10)
	var wmu sync.Mutex
	send := func(f takproto.FedEvent) error {
		b := takproto.FedFrame(takproto.MarshalFed(f))
		wmu.Lock()
		defer wmu.Unlock()
		conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
		if _, err := bw.Write(b); err != nil {
			return err
		}
		return bw.Flush()
	}
	if err := s.fedInitial(c, allowed, send); err != nil {
		return err
	}
	errc := make(chan error, 2)
	go func() {
		for {
			select {
			case <-ctx.Done():
				errc <- ctx.Err()
				return
			case <-c.closed:
				errc <- errors.New("federate closed")
				return
			case m := <-c.out:
				f, ok := s.fedOutEvent(m, allowed)
				if !ok {
					continue
				}
				if err := send(f); err != nil {
					errc <- err
					return
				}
				c.Sent()
			}
		}
	}()
	go func() {
		br := bufio.NewReaderSize(conn, 64<<10)
		max := uint32(cfg.Limits.MaxMessageBytes)
		hdr := make([]byte, 4)
		for {
			conn.SetReadDeadline(time.Now().Add(10 * time.Minute))
			if _, err := io.ReadFull(br, hdr); err != nil {
				errc <- err
				return
			}
			n := binary.BigEndian.Uint32(hdr)
			if n > max {
				errc <- fmt.Errorf("federated message of %d bytes exceeds the limit", n)
				return
			}
			buf := make([]byte, n)
			if _, err := io.ReadFull(br, buf); err != nil {
				errc <- err
				return
			}
			f, err := takproto.UnmarshalFed(buf)
			if err != nil {
				s.log.Debug("bad federated message", "federate", name, "err", err)
				continue
			}
			c.touch()
			s.federatedIn(c, f, allowed)
		}
	}()
	err := <-errc
	c.Close()
	if err == io.EOF {
		return errors.New("federate closed the connection")
	}
	return err
}

func (s *Server) fedInitial(c *Client, allowed []string, send func(takproto.FedEvent) error) error {
	for _, lc := range s.hub.Clients() {
		if lc.Relay || !lc.InMask().Intersects(c.OutMask()) {
			continue
		}
		info := lc.Info()
		if info.UID == "" {
			continue
		}
		groups := intersectNames(s.dir.Names(lc.InMask()), allowed)
		if err := send(takproto.FedEvent{Contact: &takproto.ContactEntry{Operation: takproto.CRUDCreate, UID: info.UID, Callsign: info.Callsign}, Groups: groups}); err != nil {
			return err
		}
	}
	s.hub.Replay(c, "sa", s.Config().Limits.ReplayLimit)
	return nil
}

func (s *Server) fedOutEvent(m *Message, allowed []string) (takproto.FedEvent, bool) {
	if m.ForceXML || m.SwitchProto {
		return takproto.FedEvent{}, false
	}
	cfg := s.Config()
	groups := s.fedGroups(m, allowed)
	if m.Disconnect {
		links := m.Event.Links()
		if len(links) == 0 {
			return takproto.FedEvent{}, false
		}
		return takproto.FedEvent{Contact: &takproto.ContactEntry{Operation: takproto.CRUDDelete, UID: links[0].UID, Callsign: links[0].Type}, Groups: groups}, true
	}
	if m.Announce != "" {
		return takproto.FedEvent{Contact: &takproto.ContactEntry{Operation: takproto.CRUDCreate, UID: m.Event.UID, Callsign: m.Announce}, Groups: groups}, true
	}
	e := m.Event.Clone()
	e.AddFlowTag(s.FlowKey(), time.Now())
	f := takproto.FedEvent{Event: e, Groups: groups, Provenance: []takproto.Provenance{{ServerID: cfg.NodeID, ServerName: cfg.Name}}, MaxHops: int64(cfg.Federation.MaxHops), CurrentHops: 1}
	if m.Hops > 0 {
		f.CurrentHops = m.Hops + 1
	}
	if f.CurrentHops > f.MaxHops {
		return takproto.FedEvent{}, false
	}
	return f, true
}

func intersectNames(a, b []string) []string {
	var out []string
	for _, x := range a {
		if slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

func (s *Server) federatedIn(c *Client, f *takproto.FedEvent, allowed []string) {
	for _, p := range f.Provenance {
		if p.ServerID == s.Config().NodeID {
			return
		}
	}
	mask := c.InMask()
	if len(f.Groups) > 0 {
		var mapped []string
		for _, g := range f.Groups {
			if slices.Contains(allowed, g) {
				if _, ok := s.dir.Group(g); ok {
					mapped = append(mapped, g)
				}
			}
		}
		if len(mapped) > 0 {
			mask = s.dir.Mask(mapped)
		}
	}
	if ct := f.Contact; ct != nil {
		switch ct.Operation {
		case takproto.CRUDDelete:
			if last := s.hub.RemoveRemote(c, ct.UID); last != nil || ct.UID != "" {
				typ := ct.Callsign
				if last != nil {
					typ = last.Event.Type
				}
				e := cot.DeleteFor(ct.UID, typ)
				m := NewMessage(e, c, mask)
				m.NoReplay = true
				s.hub.Publish(m)
			}
		default:
			s.hub.AddRemote(c, ct.UID, ct.Callsign)
		}
	}
	if f.Event != nil {
		e := f.Event
		if e.FlowTag(s.FlowKey()) != "" || e.UID == s.UID() {
			return
		}
		m := NewMessage(e, c, mask)
		m.Hops = f.CurrentHops
		s.hub.Identify(c, m)
		s.hub.Publish(m)
	}
}

func (s *Server) announceLocalContact(lc *Client) {
	if s.fed == nil {
		return
	}
	info := lc.Info()
	if info.UID == "" {
		return
	}
	for _, fc := range s.fed.clients() {
		if !lc.InMask().Intersects(fc.c.OutMask()) {
			continue
		}
		e := cot.New(info.UID, "a-f-G-U-C", "h-g-i-g-o", time.Minute)
		m := NewMessage(e, lc, lc.InMask())
		m.Announce = info.Callsign
		m.NoReplay = true
		fc.c.Send(m)
	}
}
