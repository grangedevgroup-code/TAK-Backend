package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/acme"
)

type ACMEConfig struct {
	Enabled       bool     `json:"enabled"`
	Email         string   `json:"email"`
	Domains       []string `json:"domains"`
	Directory     string   `json:"directory,omitempty"`
	ChallengePort int      `json:"challengePort"`
	Off           bool     `json:"off,omitempty"`
}

type acmeState struct {
	cert       atomic.Pointer[tls.Certificate]
	challenges sync.Map
	kick       chan struct{}
	mu         sync.Mutex
	lastErr    string
	lastTry    time.Time
	running    bool
}

func (s *Server) autoACME() bool {
	ac := s.Config().ACME
	if ac.Enabled || ac.Off || len(s.publicNames()) == 0 {
		return false
	}
	if s.pubCert != nil && s.refreshPublicCert(false) != nil {
		return false
	}
	return true
}

func (s *Server) acmeTargets() []string {
	if d := s.acmeDomains(); len(d) > 0 || s.Config().ACME.Enabled {
		return d
	}
	return s.publicNames()
}

func (s *Server) acmeDomains() []string {
	var out []string
	for _, d := range s.Config().ACME.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" && net.ParseIP(d) == nil && !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out
}

func (s *Server) acmePaths() (string, string, string) {
	dir := certDir(s.DataDir)
	return filepath.Join(dir, "acme.pem"), filepath.Join(dir, "acme.key"), filepath.Join(dir, "acme-account.key")
}

func (s *Server) loadACMECert() {
	certFile, keyFile, _ := s.acmePaths()
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return
	}
	if leaf, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
		c.Leaf = leaf
		s.acme.cert.Store(&c)
	}
}

func (s *Server) acmeCertFor(hello *tls.ClientHelloInfo) *tls.Certificate {
	if s.acme == nil || hello == nil || hello.ServerName == "" {
		return nil
	}
	c := s.acme.cert.Load()
	if c == nil || c.Leaf == nil || time.Now().After(c.Leaf.NotAfter) {
		return nil
	}
	if c.Leaf.VerifyHostname(hello.ServerName) != nil {
		return nil
	}
	return c
}

func loadOrCreateECKey(path string) (*ecdsa.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		if blk, _ := pem.Decode(b); blk != nil {
			if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
				return k, nil
			}
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, _ := x509.MarshalECPrivateKey(k)
	if err := writeFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

func (s *Server) acmeChallenge(w http.ResponseWriter, r *http.Request) {
	if s.acme == nil {
		http.NotFound(w, r)
		return
	}
	v, ok := s.acme.challenges.Load(r.PathValue("token"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(v.(string)))
}

func (s *Server) startACME() {
	s.acme = &acmeState{kick: make(chan struct{}, 1)}
	s.loadACMECert()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTicker(12 * time.Hour)
		defer t.Stop()
		delay := time.Duration(0)
		for {
			if s.Config().ACME.Enabled || s.autoACME() {
				var err error
				s.runJobFn("letsencrypt", false, func() error {
					err = s.renewACME(false)
					return err
				})
				if err != nil {
					delay = min(max(delay*2, 10*time.Minute), 6*time.Hour)
				} else {
					delay = 0
				}
			}
			wait := (<-chan time.Time)(t.C)
			if delay > 0 {
				wait = time.After(delay)
			}
			select {
			case <-s.ctx.Done():
				return
			case <-wait:
			case <-s.acme.kick:
			}
		}
	}()
}

func (s *Server) needsACME() bool {
	c := s.acme.cert.Load()
	if c == nil || c.Leaf == nil || time.Until(c.Leaf.NotAfter) < 30*24*time.Hour {
		return true
	}
	for _, d := range s.acmeTargets() {
		if c.Leaf.VerifyHostname(d) != nil {
			return true
		}
	}
	return false
}

func (s *Server) renewACME(force bool) error {
	ac := s.Config().ACME
	domains := s.acmeTargets()
	if len(domains) == 0 {
		return s.acmeFail(errors.New("add at least one DNS name that points at this server"))
	}
	if !force && !s.needsACME() {
		return nil
	}
	s.acme.mu.Lock()
	if s.acme.running {
		s.acme.mu.Unlock()
		return nil
	}
	s.acme.running, s.acme.lastTry = true, time.Now()
	s.acme.mu.Unlock()
	defer func() {
		s.acme.mu.Lock()
		s.acme.running = false
		s.acme.mu.Unlock()
	}()
	certFile, keyFile, accountFile := s.acmePaths()
	acctKey, err := loadOrCreateECKey(accountFile)
	if err != nil {
		return s.acmeFail(err)
	}
	var stop func()
	port := ac.ChallengePort
	if port == 0 {
		port = 80
	}
	if port != s.Config().Ports.HTTP {
		ln, err := s.listenTCP(port)
		if err != nil {
			if !ac.Enabled {
				s.log.Debug("automatic Let's Encrypt skipped: port is in use", "port", port)
				return nil
			}
			return s.acmeFail(errors.New("port " + strconv.Itoa(port) + " is needed for Let's Encrypt validation: " + err.Error()))
		}
		mux := http.NewServeMux()
		mux.HandleFunc("GET /.well-known/acme-challenge/{token}", s.acmeChallenge)
		hs := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go hs.Serve(ln)
		stop = func() { hs.Close() }
	}
	if stop != nil {
		defer stop()
	}
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return s.acmeFail(err)
	}
	dir := firstNonEmpty(ac.Directory, acme.LetsEncrypt)
	c := &acme.Client{Directory: dir, Key: acctKey, Email: ac.Email}
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Minute)
	defer cancel()
	s.log.Info("requesting a certificate from Let's Encrypt", "domains", strings.Join(domains, ","))
	chain, err := c.Obtain(ctx, domains, certKey, func(token, keyAuth string) func() {
		s.acme.challenges.Store(token, keyAuth)
		return func() { s.acme.challenges.Delete(token) }
	})
	if err != nil {
		return s.acmeFail(err)
	}
	der, _ := x509.MarshalECPrivateKey(certKey)
	if err := writeFileAtomic(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return s.acmeFail(err)
	}
	if err := writeFileAtomic(certFile, chain, 0o644); err != nil {
		return s.acmeFail(err)
	}
	s.loadACMECert()
	s.acme.mu.Lock()
	s.acme.lastErr = ""
	s.acme.mu.Unlock()
	if cc := s.acme.cert.Load(); cc != nil && cc.Leaf != nil {
		s.log.Info("Let's Encrypt certificate installed", "domains", strings.Join(domains, ","), "expires", cc.Leaf.NotAfter.Format(time.DateOnly))
	}
	return nil
}

func (s *Server) acmeFail(err error) error {
	s.acme.mu.Lock()
	s.acme.lastErr = err.Error()
	s.acme.mu.Unlock()
	s.log.Error("Let's Encrypt certificate request failed", "err", err)
	return err
}

func (s *Server) apiACME(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !s.Config().ACME.Enabled {
			apiError(w, http.StatusBadRequest, errors.New("turn on Let's Encrypt first"))
			return
		}
		go s.renewACME(true)
		writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
		return
	}
	out := map[string]any{"enabled": s.Config().ACME.Enabled, "domains": s.acmeDomains()}
	if s.acme != nil {
		s.acme.mu.Lock()
		out["error"], out["running"] = s.acme.lastErr, s.acme.running
		if !s.acme.lastTry.IsZero() {
			out["lastTry"] = s.acme.lastTry
		}
		s.acme.mu.Unlock()
		if c := s.acme.cert.Load(); c != nil && c.Leaf != nil {
			out["expires"], out["names"], out["issuer"] = c.Leaf.NotAfter, c.Leaf.DNSNames, c.Leaf.Issuer.CommonName
		}
	}
	writeJSON(w, http.StatusOK, out)
}
