package server

import (
	"crypto/subtle"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func ControlTokenPath(dataDir string) string { return filepath.Join(dataDir, "control.token") }

func (s *Server) writeControlToken() {
	s.control = NewSecret(32)
	if err := writeFileAtomic(ControlTokenPath(s.DataDir), []byte(s.control), 0o600); err != nil {
		s.log.Warn("could not write the local control token", "err", err)
	}
}

func (s *Server) removeControlToken() {
	if s.control == "" {
		return
	}
	if b, err := os.ReadFile(ControlTokenPath(s.DataDir)); err == nil && strings.TrimSpace(string(b)) == s.control {
		os.Remove(ControlTokenPath(s.DataDir))
	}
}

func isLocalAddress(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	if p.IsLoopback() {
		return true
	}
	for _, l := range LocalIPs() {
		if l == ip {
			return true
		}
	}
	return false
}

func (s *Server) isControlToken(tok string, r *http.Request) bool {
	if s.control == "" || len(tok) != len(s.control) {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(tok), []byte(s.control)) != 1 {
		return false
	}
	return isLocalAddress(remoteIP(r.RemoteAddr))
}

func (s *Server) controlIdentity() *Identity {
	var names []string
	for _, g := range s.dir.Groups() {
		names = append(names, g.Name)
	}
	m := s.dir.Mask(names)
	return &Identity{Name: "local-admin", Admin: true, Via: "control", In: m, Out: m}
}
