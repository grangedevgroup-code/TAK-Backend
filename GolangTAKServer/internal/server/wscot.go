package server

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/takproto"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/websocket"
)

func (s *Server) wsIdentity(r *http.Request) (*Identity, error) {
	ip := requestIP(r)
	if t := r.URL.Query().Get("token"); t != "" {
		return s.dir.CheckToken(ip, t)
	}
	if u, p, ok := r.BasicAuth(); ok {
		return s.dir.CheckPassword(ip, u, p)
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return s.dir.CheckToken(ip, strings.TrimSpace(h[7:]))
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && len(r.TLS.VerifiedChains) > 0 {
		return s.identityFromCert(r.TLS.PeerCertificates[0])
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		if sess, ok := s.dir.SessionFor(c.Value); ok {
			return s.dir.Identity(sess.User, "session")
		}
	}
	return nil, nil
}

func (s *Server) serveWebSocketPort(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/takproto/1" {
		s.serveTakProtoWebSocket(w, r)
		return
	}
	s.serveCoTWebSocket(w, r)
}

func (s *Server) serveCoTWebSocket(w http.ResponseWriter, r *http.Request) {
	if !websocket.IsUpgrade(r) {
		cfg := s.Config()
		writeText(w, http.StatusOK, "GolangTAKServer CoT WebSocket endpoint. Connect a WebSocket client to ws://"+HostForURL(s.hostOf(r))+":"+itoa(cfg.Ports.WebSocket)+"/ and exchange CoT XML, one event per message.\n")
		return
	}
	s.serveWebSocket(w, r, false)
}

func (s *Server) serveTakProtoWebSocket(w http.ResponseWriter, r *http.Request) {
	if !websocket.IsUpgrade(r) {
		writeText(w, http.StatusUpgradeRequired, "TAK protocol WebSocket endpoint: upgrade to a WebSocket and exchange binary TAK protobuf messages.\n")
		return
	}
	s.serveWebSocket(w, r, true)
}

func (s *Server) serveWebSocket(w http.ResponseWriter, r *http.Request, proto bool) {
	id, err := s.wsIdentity(r)
	if err != nil {
		challenge(w, "invalid credentials")
		return
	}
	if id == nil {
		if !s.Config().AllowAnonymous {
			challenge(w, "sign in with a user name and password or ?token=")
			return
		}
		id = s.dir.Anonymous()
	}
	remote := r.RemoteAddr
	if ip := requestIP(r); ip != remoteIP(r.RemoteAddr) {
		remote = ip
	}
	if max := s.Config().Limits.MaxPerIP; max > 0 && s.hub.CountFrom(remoteIP(remote)) >= max {
		writeText(w, http.StatusTooManyRequests, "too many connections from your address")
		return
	}
	var subprotocols []string
	if !proto {
		subprotocols = []string{"cot", "tak"}
	}
	conn, err := websocket.Accept(w, r, subprotocols)
	if err != nil {
		return
	}
	conn.MaxMessage = int64(s.Config().Limits.MaxMessageBytes)
	c := s.hub.NewClient(KindWebSocket, remote, id)
	c.authed.Store(true)
	c.SetProto(proto)
	c.onClose = func() { conn.CloseNow() }
	if !s.hub.Add(c) {
		conn.Close(websocket.CloseTryAgainLater, "server at capacity")
		return
	}
	s.log.Info("client connected", "kind", KindWebSocket, "remote", remote, "user", c.User(), "takproto", proto)
	go s.wsWriter(c, conn, proto)
	s.afterAuth(c)
	st := &clientState{}
	idle := time.Duration(s.Config().Limits.IdleTimeoutSec) * time.Second
	for {
		conn.SetReadDeadline(time.Now().Add(idle))
		op, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if proto && op == websocket.OpText {
			conn.Close(websocket.CloseUnsupportedData, "Text messages not supported")
			break
		}
		if proto && len(data) > 0 && data[0] != takproto.Magic && data[0] != '<' {
			if err := s.handleFrame(c, st, takproto.Frame{Proto: true, Data: data}); err != nil {
				break
			}
			continue
		}
		fr := takproto.NewReader(bytes.NewReader(data), s.Config().Limits.MaxMessageBytes)
		failed := false
		for {
			f, err := fr.Next()
			if err != nil {
				if err != io.EOF {
					failed = err == takproto.ErrTooLarge
				}
				break
			}
			if err := s.handleFrame(c, st, f); err != nil {
				failed = true
				break
			}
		}
		if failed {
			break
		}
	}
	s.hub.Remove(c)
	s.log.Info("client disconnected", "kind", KindWebSocket, "remote", remote, "user", c.User(), "callsign", c.Callsign())
}

func (s *Server) wsWriter(c *Client, conn *websocket.Conn, proto bool) {
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-ping.C:
			conn.SetWriteDeadline(time.Now().Add(20 * time.Second))
			if err := conn.Ping(nil); err != nil {
				c.Close()
				return
			}
		case m := <-c.out:
			if m.SwitchProto || (proto && m.ForceXML) {
				continue
			}
			conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			b := m.XML()
			if proto {
				b = m.StreamFrame()
			}
			if err := conn.WriteBinary(b); err != nil {
				c.Close()
				return
			}
			c.Sent()
			s.hub.Bytes.Add(uint64(len(b)))
		}
	}
}
