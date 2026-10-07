package server

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/takproto"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/xmltree"
)

type clientState struct {
	incognito bool
}

func (s *Server) streamTLSConfig(requireCert bool) *tls.Config {
	auth := tls.VerifyClientCertIfGiven
	if requireCert {
		auth = tls.RequireAndVerifyClientCert
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: auth,
		ClientCAs:  s.pki.ClientPool(),
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.pki.ServerCert(), nil
		},
		VerifyPeerCertificate: func(_ [][]byte, chains [][]*x509.Certificate) error {
			for _, chain := range chains {
				if len(chain) > 0 && s.dir.IsRevoked(chain[0].SerialNumber.Text(16)) {
					return errors.New("certificate has been revoked")
				}
			}
			return nil
		},
	}
}

func (s *Server) identityFromCert(cert *x509.Certificate) (*Identity, error) {
	cn := cert.Subject.CommonName
	if cn == SelfTestUser {
		id := s.dir.Anonymous()
		id.Name, id.Via, id.Anon, id.Cert = SelfTestUser, "cert", false, cert
		return id, nil
	}
	if cn == "" {
		return nil, errors.New("certificate has no common name")
	}
	if !ValidUserName(cn) {
		id := s.dir.Anonymous()
		id.Name, id.Via, id.Anon, id.Cert = cn, "cert", false, cert
		return id, nil
	}
	if _, ok := s.dir.User(cn); !ok {
		s.dir.EnsureExternalUser(cn)
	}
	id, err := s.dir.Identity(cn, "cert")
	if err != nil {
		return nil, err
	}
	id.Cert = cert
	return id, nil
}

func (s *Server) acceptLoop(ln net.Listener, kind string, tlsCfg *tls.Config) {
	defer s.wg.Done()
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || s.ctx.Err() != nil {
				return
			}
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else if delay < time.Second {
				delay *= 2
			}
			time.Sleep(delay)
			continue
		}
		delay = 0
		if tlsCfg != nil {
			conn = tls.Server(conn, tlsCfg)
		}
		go s.serveStream(conn, kind)
	}
}

func (s *Server) serveStream(conn net.Conn, kind string) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("stream handler panic", "err", r, "stack", string(debug.Stack()))
			conn.Close()
		}
	}()
	cfg := s.Config()
	remote := conn.RemoteAddr().String()
	ip := remoteIP(remote)
	if cfg.Limits.MaxPerIP > 0 && s.hub.CountFrom(ip) >= cfg.Limits.MaxPerIP {
		s.log.Warn("connection refused: too many connections from address", "remote", remote)
		conn.Close()
		return
	}
	var id *Identity
	if tc, ok := conn.(*tls.Conn); ok {
		tc.SetDeadline(time.Now().Add(20 * time.Second))
		if err := tc.Handshake(); err != nil {
			s.log.Debug("tls handshake failed", "remote", remote, "err", err)
			conn.Close()
			return
		}
		tc.SetDeadline(time.Time{})
		if pc := tc.ConnectionState().PeerCertificates; len(pc) > 0 {
			var err error
			id, err = s.identityFromCert(pc[0])
			if err != nil {
				s.log.Warn("certificate rejected", "remote", remote, "cn", pc[0].Subject.CommonName, "err", err)
				conn.Close()
				return
			}
		}
	}
	c := s.hub.NewClient(kind, remote, id)
	c.onClose = func() { conn.Close() }
	st := &clientState{}
	if id != nil {
		c.authed.Store(true)
	} else if cfg.AllowAnonymous {
		c.SetIdentity(s.dir.Anonymous())
		c.authed.Store(true)
	}
	if !s.hub.Add(c) {
		s.log.Warn("connection refused: client limit reached", "remote", remote)
		conn.Close()
		return
	}
	s.log.Info("client connected", "kind", kind, "remote", remote, "user", c.User())
	go s.streamWriter(c, conn)
	if cfg.Protobuf {
		c.Send(s.controlMessage(protocolAnnouncement(s.Version), true, false))
	}
	if c.authed.Load() {
		s.afterAuth(c)
	}
	authDeadline := time.Now().Add(30 * time.Second)
	idle := time.Duration(cfg.Limits.IdleTimeoutSec) * time.Second
	r := takproto.NewReader(conn, cfg.Limits.MaxMessageBytes)
	var readErr error
	for {
		deadline := time.Now().Add(idle)
		if !c.authed.Load() && authDeadline.Before(deadline) {
			deadline = authDeadline
		}
		conn.SetReadDeadline(deadline)
		f, err := r.Next()
		if err != nil {
			readErr = err
			break
		}
		if err := s.handleFrame(c, st, f); err != nil {
			readErr = err
			break
		}
	}
	s.hub.Remove(c)
	reason := "closed"
	if readErr != nil && readErr != io.EOF && !errors.Is(readErr, net.ErrClosed) {
		reason = readErr.Error()
	}
	if !c.authed.Load() {
		reason = "no authentication received"
	}
	s.log.Info("client disconnected", "kind", kind, "remote", remote, "user", c.User(), "callsign", c.Callsign(), "reason", reason)
}

func (s *Server) afterAuth(c *Client) {
	cfg := s.Config()
	n := s.hub.Replay(c, cfg.Replay, cfg.Limits.ReplayLimit)
	if n > 0 {
		s.log.Debug("replayed cached events", "remote", c.Remote, "count", n)
	}
}

func (s *Server) streamWriter(c *Client, conn net.Conn) {
	bw := bufio.NewWriterSize(conn, 64<<10)
	write := func(m *Message) error {
		var b []byte
		if m.ForceXML || !c.UseProto() {
			b = m.XML()
		} else {
			b = m.StreamFrame()
		}
		_, err := bw.Write(b)
		if err == nil {
			c.Sent()
			s.hub.Bytes.Add(uint64(len(b)))
			if m.SwitchProto {
				if err = bw.Flush(); err == nil {
					c.SetProto(true)
				}
			}
		}
		return err
	}
	for {
		select {
		case <-c.closed:
			return
		case m := <-c.out:
			conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
			err := write(m)
			for more := err == nil; more; {
				select {
				case m2 := <-c.out:
					err = write(m2)
					more = err == nil && bw.Buffered() < 512<<10
				default:
					more = false
				}
			}
			if err == nil {
				err = bw.Flush()
			}
			if err != nil {
				c.Close()
				return
			}
		}
	}
}

func (s *Server) handleFrame(c *Client, st *clientState, f takproto.Frame) error {
	var e *cot.Event
	if f.Proto {
		msg, err := takproto.Unmarshal(f.Data)
		if err != nil {
			s.log.Debug("bad protobuf message", "remote", c.Remote, "err", err)
			return nil
		}
		if msg.Event == nil {
			return nil
		}
		e = msg.Event
	} else {
		n, err := xmltree.Parse(f.Data)
		if err != nil {
			s.log.Debug("bad xml message", "remote", c.Remote, "err", err)
			return nil
		}
		if n.Name == "auth" {
			return s.handleAuth(c, n)
		}
		e, err = cot.FromNode(n)
		if err != nil {
			s.log.Debug("bad cot event", "remote", c.Remote, "err", err)
			return nil
		}
	}
	c.touch()
	return s.handleEvent(c, st, e)
}

func (s *Server) handleAuth(c *Client, n *xmltree.Node) error {
	ac := n.Child("cot")
	if ac == nil {
		return nil
	}
	user, pass := ac.Attr("username"), ac.Attr("password")
	if c.authed.Load() {
		if id := c.Identity(); id != nil && !id.Anon {
			return nil
		}
		if user == "" {
			return nil
		}
	}
	id, err := s.dir.CheckPassword(remoteIP(c.Remote), user, pass)
	if err != nil {
		s.log.Warn("stream sign-in failed", "remote", c.Remote, "user", user, "err", err)
		time.Sleep(time.Second)
		return errors.New("authentication failed")
	}
	wasAuthed := c.authed.Load()
	c.SetIdentity(id)
	c.authed.Store(true)
	s.log.Info("client signed in", "remote", c.Remote, "user", user)
	if !wasAuthed {
		s.afterAuth(c)
	}
	return nil
}

func (s *Server) controlMessage(e *cot.Event, forceXML, switchProto bool) *Message {
	m := NewMessage(e, nil, nil)
	m.ForceXML = forceXML
	m.SwitchProto = switchProto
	m.NoReplay = true
	return m
}

func protocolAnnouncement(version string) *cot.Event {
	e := cot.New(cot.NewUID(), "t-x-takp-v", "m-g", time.Minute)
	e.Point.Hae, e.Point.Ce, e.Point.Le = 0, 999999, 999999
	tc := e.Detail.AddNew("TakControl")
	tc.AddNew("TakProtocolSupport", "version", "1")
	tc.AddNew("TakServerVersionInfo", "serverVersion", "GolangTAK "+version, "apiVersion", "3")
	return e
}

func protocolResponse(uid string, ok bool) *cot.Event {
	e := cot.New(uid, "t-x-takp-r", "m-g", time.Minute)
	e.Point.Hae, e.Point.Ce, e.Point.Le = 0, 999999, 999999
	e.Detail.AddNew("TakControl").AddNew("TakResponse", "status", strconv.FormatBool(ok))
	return e
}

func pongEvent() *cot.Event {
	e := cot.New("takPong", "t-x-c-t-r", "h-g-i-g-o", 20*time.Second)
	e.Point.Hae = 0
	return e
}

var consumedTypes = map[string]bool{
	"t-b": true, "t-b-a": true, "t-b-c": true, "t-b-q": true, "t-x-c-t-r": true, "t-x-takp-v": true, "t-x-takp-r": true,
}

func (s *Server) handleEvent(c *Client, st *clientState, e *cot.Event) error {
	switch e.Type {
	case "t-x-c-t":
		c.Send(NewMessage(pongEvent(), nil, nil))
		return nil
	case "t-x-takp-q":
		version := ""
		if r := e.D("TakControl", "TakRequest"); r != nil {
			version = r.Attr("version")
		}
		ok := s.Config().Protobuf && version == "1"
		c.Send(s.controlMessage(protocolResponse(e.UID, ok), true, ok))
		if ok {
			s.log.Debug("client switched to TAK protocol 1", "remote", c.Remote)
		}
		return nil
	case "t-x-c-f":
		g := &geoFilter{}
		if gf := e.D("subscription", "geospatialFilter"); gf != nil {
			g.allTAK = strings.EqualFold(gf.Attr("filterTAKClients"), "false")
			for _, b := range gf.All("boundingBox") {
				g.boxes = append(g.boxes, bbox{
					minLat: parseF(b.Attr("minLatitude")), minLon: parseF(b.Attr("minLongitude")),
					maxLat: parseF(b.Attr("maxLatitude")), maxLon: parseF(b.Attr("maxLongitude")),
				})
			}
		}
		if len(g.boxes) == 0 {
			g = nil
		}
		c.geo.Store(g)
		return nil
	case "t-x-c-m":
		if stats := e.D("stats"); stats != nil {
			m := map[string]string{}
			for _, a := range stats.Attrs {
				m[a.Name] = a.Value
			}
			c.mu.Lock()
			c.metrics = m
			if b := m["battery"]; b != "" {
				c.info.Battery = b
			}
			c.mu.Unlock()
		}
		return nil
	case "t-x-c-i-e":
		st.incognito = true
		return nil
	case "t-x-c-i-d":
		st.incognito = false
		return nil
	}
	if consumedTypes[e.Type] {
		return nil
	}
	if !c.authed.Load() {
		return nil
	}
	if e.FlowTag(s.FlowKey()) != "" {
		return nil
	}
	if st.incognito && !e.IsControl() && len(e.Dests()) == 0 {
		return nil
	}
	m := NewMessage(e, c, c.InMask())
	s.hub.Identify(c, m)
	s.hub.Publish(m)
	return nil
}

func (s *Server) FlowKey() string { return "GolangTAK-" + s.Config().NodeID }
