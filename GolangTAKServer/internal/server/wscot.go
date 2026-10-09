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

func (s *Server) serveCoTWebSocket(w http.ResponseWriter, r *http.Request) {
	if !websocket.IsUpgrade(r) {
		cfg := s.Config()
		writeText(w, http.StatusOK, "GolangTAKServer CoT WebSocket endpoint. Connect a WebSocket client to ws://"+HostForURL(s.hostOf(r))+":"+itoa(cfg.Ports.WebSocket)+"/ and exchange CoT XML, one event per message.\n")
		return
	}
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
	conn, err := websocket.Accept(w, r, []string{"cot", "tak"})
	if err != nil {
		return
	}
	conn.MaxMessage = int64(s.Config().Limits.MaxMessageBytes)
	c := s.hub.NewClient(KindWebSocket, remote, id)
	c.authed.Store(true)
	c.onClose = func() { conn.CloseNow() }
	if !s.hub.Add(c) {
		conn.Close(websocket.CloseTryAgainLater, "server at capacity")
		return
	}
	s.log.Info("client connected", "kind", KindWebSocket, "remote", remote, "user", c.User())
	go s.wsWriter(c, conn)
	s.afterAuth(c)
	st := &clientState{}
	idle := time.Duration(s.Config().Limits.IdleTimeoutSec) * time.Second
	for {
		conn.SetReadDeadline(time.Now().Add(idle))
		_, data, err := conn.ReadMessage()
		if err != nil {
			break
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

func (s *Server) wsWriter(c *Client, conn *websocket.Conn) {
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
			if m.SwitchProto {
				continue
			}
			conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			b := m.XML()
			if err := conn.WriteBinary(b); err != nil {
				c.Close()
				return
			}
			c.Sent()
			s.hub.Bytes.Add(uint64(len(b)))
		}
	}
}
