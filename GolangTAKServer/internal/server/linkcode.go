package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/pki"
)

const linkCodePrefix = "golangtakserver-link:"

type linkCode struct {
	Version int    `json:"v"`
	Server  string `json:"server"`
	URL     string `json:"url"`
	Cert    string `json:"cert"`
	CA      string `json:"ca"`
}

var slugRe = regexp.MustCompile(`[^a-z0-9._-]+`)

func linkSlug(s string) string {
	s = slugRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "-")
	s = strings.Trim(s, "-._")
	if len(s) > 40 {
		s = strings.Trim(s[:40], "-._")
	}
	return s
}

type LinkInvite struct {
	Code    string    `json:"code"`
	User    string    `json:"user"`
	URL     string    `json:"url"`
	Expires time.Time `json:"expires"`
}

func (s *Server) CreateLinkInvite(name string, groups []string) (LinkInvite, error) {
	cfg := s.Config()
	slug := linkSlug(name)
	if slug == "" {
		return LinkInvite{}, errors.New("give the other server a name, for example hq or partner-team")
	}
	if cfg.Ports.TLS <= 0 {
		return LinkInvite{}, errors.New("the TAK SSL port is turned off; turn it on under Settings, Ports first")
	}
	addr := strings.TrimSpace(cfg.Address)
	if addr == "" {
		return LinkInvite{}, errors.New("set the public address of this server under Settings, General first, so the other server can reach it")
	}
	user := "link-" + slug
	if u, ok := s.dir.User(user); ok && !u.Link {
		return LinkInvite{}, fmt.Errorf("a user named %s already exists and is not a server link; choose another name", user)
	}
	if _, ok := s.dir.User(user); !ok {
		if _, err := s.dir.AddUser(user, NewSecret(24), false, groups); err != nil {
			return LinkInvite{}, err
		}
	}
	if _, err := s.dir.UpdateUser(user, func(u *User) error {
		u.Link = true
		u.Note = "Server link for " + strings.TrimSpace(name)
		if len(groups) > 0 {
			u.In, u.Out = groups, groups
		}
		return nil
	}); err != nil {
		return LinkInvite{}, err
	}
	days := cfg.Certificates.ClientDays
	if days <= 0 {
		days = 365
	}
	certPEM, keyPEM, cert, err := s.pki.NewClientPEM(user, time.Duration(days)*24*time.Hour)
	if err != nil {
		return LinkInvite{}, err
	}
	if err := s.dir.RecordCert(user, newCertRecord(cert, "", "link")); err != nil {
		return LinkInvite{}, err
	}
	u := "tls://" + net.JoinHostPort(addr, strconv.Itoa(cfg.Ports.TLS))
	body, err := json.Marshal(linkCode{Version: 1, Server: cfg.Name, URL: u, Cert: string(certPEM) + string(keyPEM), CA: string(pki.CertPEM(s.pki.CA.Cert))})
	if err != nil {
		return LinkInvite{}, err
	}
	s.log.Info("server link code created", "user", user, "url", u)
	return LinkInvite{Code: linkCodePrefix + base64.RawURLEncoding.EncodeToString(body), User: user, URL: u, Expires: cert.NotAfter}, nil
}

func parseLinkCode(code string) (linkCode, error) {
	var lc linkCode
	code = strings.Join(strings.Fields(code), "")
	body, ok := trimLinkPrefix(code)
	if !ok {
		return lc, fmt.Errorf("this is not a GolangTAKServer link code (it should start with %s)", linkCodePrefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return lc, errors.New("the link code is damaged; copy it again in full")
	}
	if err := json.Unmarshal(raw, &lc); err != nil {
		return lc, errors.New("the link code is damaged; copy it again in full")
	}
	if lc.Version != 1 || lc.URL == "" || lc.Cert == "" || lc.CA == "" {
		return lc, errors.New("the link code is incomplete or from a newer version of GolangTAKServer")
	}
	if _, err := pki.ParseCertPEM([]byte(lc.CA)); err != nil {
		return lc, errors.New("the link code's certificate authority is not valid")
	}
	if _, err := pki.ParseCertPEM([]byte(lc.Cert)); err != nil {
		return lc, errors.New("the link code's certificate is not valid")
	}
	if _, err := pki.ParseKeyPEM([]byte(lc.Cert), ""); err != nil {
		return lc, errors.New("the link code's key is not valid")
	}
	return lc, nil
}

func (s *Server) JoinLink(code, name string, groups []string) (PeerConfig, error) {
	lc, err := parseLinkCode(code)
	if err != nil {
		return PeerConfig{}, err
	}
	base := linkSlug(firstNonEmpty(name, lc.Server))
	if base == "" {
		base = "link"
	}
	cfg := s.Config()
	taken := func(n string) bool {
		for _, p := range cfg.Peers {
			if strings.EqualFold(p.Name, n) {
				return true
			}
		}
		return false
	}
	peerName := base
	for i := 2; taken(peerName); i++ {
		peerName = base + "-" + strconv.Itoa(i)
	}
	dir := filepath.Join(s.DataDir, "links")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return PeerConfig{}, err
	}
	certFile := filepath.Join(dir, peerName+".pem")
	caFile := filepath.Join(dir, peerName+"-ca.pem")
	if err := writeFileAtomic(certFile, []byte(lc.Cert), 0o600); err != nil {
		return PeerConfig{}, err
	}
	if err := writeFileAtomic(caFile, []byte(lc.CA), 0o644); err != nil {
		return PeerConfig{}, err
	}
	p := PeerConfig{Name: peerName, URL: lc.URL, Enabled: true, Direction: "both", Groups: groups, CertFile: certFile, TrustFile: caFile}
	if _, err := s.UpdateConfig(func(c *Config) error {
		c.Peers = append(c.Peers, p)
		return validateConfig(c)
	}); err != nil {
		return PeerConfig{}, err
	}
	s.reloadPeers()
	s.log.Info("server link added from a link code", "peer", peerName, "url", lc.URL)
	return p, nil
}

func (s *Server) apiLinkInvite(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name   string   `json:"name"`
		Groups []string `json:"groups"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	inv, err := s.CreateLinkInvite(in.Name, in.Groups)
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, inv)
}

func (s *Server) apiLinkJoin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code   string   `json:"code"`
		Name   string   `json:"name"`
		Groups []string `json:"groups"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	p, err := s.JoinLink(in.Code, in.Name, in.Groups)
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": p.Name, "url": p.URL})
}
