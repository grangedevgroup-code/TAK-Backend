package server

import (
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/mumble"
)

type VoiceConfig struct {
	Enabled   bool   `json:"enabled"`
	Port      int    `json:"port"`
	Anonymous bool   `json:"anonymous"`
	MaxUsers  int    `json:"maxUsers"`
	Welcome   string `json:"welcome"`
}

func (s *Server) startVoice() {
	vc := s.Config().Voice
	if !vc.Enabled || vc.Port <= 0 {
		return
	}
	ms := mumble.NewServer(s.Config().Name)
	ms.Log = s.log
	ms.MaxUsers = vc.MaxUsers
	ms.Welcome = vc.Welcome
	ms.Auth = s.voiceAuth
	ln, err := s.listenTCP(vc.Port)
	if err != nil {
		s.log.Error("voice server could not start; change its port under Settings", "port", vc.Port, "err", err)
		return
	}
	tcfg := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return s.pki.ServerCert(), nil }, ClientAuth: tls.RequestClientCert}
	host := s.Config().Bind
	if uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host), Port: vc.Port}); err != nil {
		s.log.Warn("voice UDP unavailable, clients use TCP", "port", vc.Port, "err", err)
	} else {
		ms.ListenUDP(uc)
	}
	s.voice = ms
	s.refreshVoiceChannels()
	go ms.Serve(tls.NewListener(ln, tcfg))
	s.track(closerFunc(func() error {
		ms.Close()
		return nil
	}))
	s.log.Info("voice server listening", "port", vc.Port)
}

func (s *Server) voiceAuth(user, pass, remote string) (*mumble.Identity, error) {
	if pass == "" {
		if s.Config().Voice.Anonymous {
			if _, taken := s.dir.User(user); taken {
				return nil, mumble.ErrRejected
			}
			return &mumble.Identity{Name: user, Groups: s.dir.Names(s.dir.Anonymous().In)}, nil
		}
		return nil, mumble.ErrRejected
	}
	id, err := s.dir.CheckPassword(remoteIP(remote), user, pass)
	if err != nil {
		return nil, mumble.ErrRejected
	}
	return &mumble.Identity{Name: id.Name, Groups: s.identityGroups(id), Admin: id.Admin}, nil
}

func (s *Server) refreshVoiceChannels() {
	if s.voice == nil {
		return
	}
	var list []mumble.Channel
	for i, g := range s.dir.Groups() {
		list = append(list, mumble.Channel{Name: g.Name, Description: g.Description, Group: g.Name, Position: i})
	}
	s.voice.SetChannels(list)
}

func (s *Server) apiVoice(w http.ResponseWriter, r *http.Request) {
	vc := s.Config().Voice
	out := map[string]any{"enabled": vc.Enabled && s.voice != nil, "port": vc.Port, "users": []mumble.UserInfo{}}
	host := s.Config().Address
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		host = h
	}
	out["address"] = host
	out["url"] = "mumble://" + net.JoinHostPort(host, strconv.Itoa(vc.Port)) + "/"
	if s.voice != nil {
		if u := s.voice.Users(); u != nil {
			out["users"] = u
		}
		out["packets"] = s.voice.VoicePackets.Load()
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiVoiceKick(w http.ResponseWriter, r *http.Request) {
	if s.voice == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "the voice server is off"})
		return
	}
	n, err := strconv.ParseUint(r.PathValue("session"), 10, 32)
	if err != nil || !s.voice.Kick(uint32(n), "disconnected by "+strings.TrimSpace(identityOf(r).Name)) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no voice user with that session"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
