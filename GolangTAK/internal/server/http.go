package server

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

type ctxKey int

const (
	keyIdentity ctxKey = iota
	keyListener
	keySession
)

const sessionCookie = "golangtak_session"

func (s *Server) newHTTPServer(h http.Handler, tlsCfg *tls.Config) *http.Server {
	hs := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 20 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          log.New(io.Discard, "", 0),
		TLSConfig:         tlsCfg,
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
		BaseContext:       func(net.Listener) context.Context { return s.ctx },
	}
	s.lmu.Lock()
	s.https = append(s.https, hs)
	s.lmu.Unlock()
	return hs
}

func (s *Server) serveHTTP(port int, name string, h http.Handler, tlsCfg *tls.Config) error {
	if port <= 0 {
		return nil
	}
	ln, err := s.listenTCP(port)
	if err != nil {
		return err
	}
	tagged := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyListener, name)))
	})
	hs := s.newHTTPServer(s.recoverer(tagged), tlsCfg)
	if tlsCfg != nil {
		tlsCfg.NextProtos = []string{"http/1.1"}
		ln = tls.NewListener(ln, tlsCfg)
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		hs.Serve(ln)
	}()
	return nil
}

func (s *Server) enrollTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c := s.acmeCertFor(hello); c != nil {
				return c, nil
			}
			return s.pki.ServerCert(), nil
		},
	}
}

func (s *Server) startHTTP() error {
	cfg := s.Config()
	mux := s.routes()
	if err := s.serveHTTP(cfg.Ports.HTTP, "http", mux, nil); err != nil {
		return err
	}
	if err := s.serveHTTP(cfg.Ports.HTTPS, "https", mux, s.streamTLSConfig(false)); err != nil {
		return err
	}
	if err := s.serveHTTP(cfg.Ports.Enroll, "enroll", mux, s.enrollTLSConfig()); err != nil {
		return err
	}
	if cfg.Ports.API > 0 {
		if err := s.serveHTTP(cfg.Ports.API, "api", s.apiPortRoutes(mux), nil); err != nil {
			return err
		}
	}
	if cfg.Ports.WebSocket > 0 {
		if err := s.serveHTTP(cfg.Ports.WebSocket, "websocket", http.HandlerFunc(s.serveCoTWebSocket), nil); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) recoverer(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				s.log.Error("http handler panic", "path", r.URL.Path, "err", rec, "stack", string(debug.Stack()))
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		h.ServeHTTP(w, r)
	})
}

func listenerName(r *http.Request) string {
	if v, ok := r.Context().Value(keyListener).(string); ok {
		return v
	}
	return ""
}

func (s *Server) resolveIdentity(r *http.Request) (*Identity, *Session, error) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && len(r.TLS.VerifiedChains) > 0 {
		id, err := s.identityFromCert(r.TLS.PeerCertificates[0])
		return id, nil, err
	}
	ip := requestIP(r)
	if h := r.Header.Get("Authorization"); h != "" {
		scheme, cred, _ := strings.Cut(h, " ")
		cred = strings.TrimSpace(cred)
		switch strings.ToLower(scheme) {
		case "bearer":
			if s.isControlToken(cred, r) {
				return s.controlIdentity(), nil, nil
			}
			if s.isMissionToken(cred) {
				break
			}
			if c, err := s.parseOAuthToken(cred); err == nil {
				id, err := s.dir.Identity(c.Sub, "oauth")
				return id, nil, err
			}
			id, err := s.dir.CheckToken(ip, cred)
			return id, nil, err
		case "basic":
			if u, p, ok := r.BasicAuth(); ok {
				id, err := s.dir.CheckPassword(ip, u, p)
				return id, nil, err
			}
			return nil, nil, errors.New("malformed basic authorization")
		}
	}
	if t := r.URL.Query().Get("token"); t != "" && strings.HasPrefix(r.URL.Path, "/api/") {
		id, err := s.dir.CheckToken(ip, t)
		return id, nil, err
	}
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		if sess, ok := s.dir.SessionFor(c.Value); ok {
			id, err := s.dir.Identity(sess.User, "session")
			if err != nil {
				return nil, nil, err
			}
			return id, sess, nil
		}
	}
	return nil, nil, nil
}

func identityOf(r *http.Request) *Identity {
	if id, ok := r.Context().Value(keyIdentity).(*Identity); ok {
		return id
	}
	return nil
}

func sessionOf(r *http.Request) *Session {
	if s, ok := r.Context().Value(keySession).(*Session); ok {
		return s
	}
	return nil
}

func deny(w http.ResponseWriter, r *http.Request, msg string) {
	if r.Header.Get("X-Requested-With") != "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": msg})
		return
	}
	challenge(w, msg)
}

func challenge(w http.ResponseWriter, msg string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="GolangTAK", charset="UTF-8"`)
	writeText(w, http.StatusUnauthorized, msg)
}

type access int

const (
	accessAny access = iota
	accessMarti
	accessUser
	accessAdmin
)

func (s *Server) guard(level access, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, sess, err := s.resolveIdentity(r)
		if err != nil {
			if errors.Is(err, ErrThrottled) {
				writeText(w, http.StatusTooManyRequests, err.Error())
				return
			}
			s.log.Warn("http sign-in failed", "remote", requestIP(r), "path", r.URL.Path, "err", err)
			deny(w, r, "sign in with your user name and password")
			return
		}
		if id == nil && level <= accessMarti && s.Config().AllowAnonymous {
			id = s.dir.Anonymous()
		}
		switch level {
		case accessMarti:
			if id == nil {
				deny(w, r, "sign in with your user name and password")
				return
			}
		case accessUser:
			if id == nil || id.Anon {
				deny(w, r, "sign in with your user name and password")
				return
			}
		case accessAdmin:
			if id == nil || id.Anon {
				deny(w, r, "sign in as an administrator")
				return
			}
			if !id.Admin {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "administrator access required"})
				return
			}
		}
		if sess != nil && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			tok := r.Header.Get("X-CSRF-Token")
			if subtle.ConstantTimeCompare([]byte(tok), []byte(sess.CSRF)) != 1 {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing or invalid CSRF token"})
				return
			}
		}
		ctx := r.Context()
		if id != nil {
			ctx = context.WithValue(ctx, keyIdentity, id)
		}
		if sess != nil {
			ctx = context.WithValue(ctx, keySession, sess)
		}
		h(w, r.WithContext(ctx))
	}
}

func (s *Server) baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		cfg := s.Config()
		port := cfg.Ports.HTTP
		if r.TLS != nil {
			port = cfg.Ports.HTTPS
		}
		host = net.JoinHostPort(cfg.Address, strconv.Itoa(port))
	}
	if listenerName(r) == "enroll" {
		cfg := s.Config()
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = net.JoinHostPort(h, strconv.Itoa(cfg.Ports.HTTPS))
		} else {
			host = net.JoinHostPort(host, strconv.Itoa(cfg.Ports.HTTPS))
		}
	}
	return scheme + "://" + host
}

func (s *Server) hostOf(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		host = s.Config().Address
	}
	return host
}

func martiEnvelope(typ string, data any) map[string]any {
	return map[string]any{"version": "3", "type": typ, "data": data, "messages": []string{}, "nodeId": ""}
}

func (s *Server) envelope(typ string, data any) map[string]any {
	e := martiEnvelope(typ, data)
	e["nodeId"] = s.Config().NodeID
	return e
}
