package server

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type publicCert struct {
	cert   *tls.Certificate
	source string
}

type publicCertState struct {
	mu      sync.Mutex
	current atomic.Pointer[publicCert]
	checked time.Time
}

func (s *Server) publicNames() []string {
	cfg := s.Config()
	var out []string
	for _, n := range append([]string{cfg.Address, cfg.ACMEDomain}, cfg.ExtraNames...) {
		n = strings.ToLower(strings.TrimSpace(strings.Trim(n, "[]")))
		if n == "" || net.ParseIP(n) != nil || !strings.Contains(n, ".") || strings.HasSuffix(n, ".local") || slices.Contains(out, n) {
			continue
		}
		out = append(out, n)
	}
	return out
}

func caddyStores() []string {
	var roots []string
	switch runtime.GOOS {
	case "windows":
		if v := os.Getenv("AppData"); v != "" {
			roots = append(roots, filepath.Join(v, "Caddy"))
		}
	case "darwin":
		if h, err := os.UserHomeDir(); err == nil {
			roots = append(roots, filepath.Join(h, "Library", "Application Support", "Caddy"))
		}
	default:
		roots = append(roots, "/var/lib/caddy/.local/share/caddy", "/root/.local/share/caddy", "/data/caddy")
		if m, _ := filepath.Glob("/home/*/.local/share/caddy"); len(m) > 0 {
			roots = append(roots, m...)
		}
		if m, _ := filepath.Glob("/var/lib/docker/volumes/*/_data/caddy"); len(m) > 0 {
			roots = append(roots, m...)
		}
		if m, _ := filepath.Glob("/var/lib/containers/storage/volumes/*/_data/caddy"); len(m) > 0 {
			roots = append(roots, m...)
		}
	}
	return roots
}

func (s *Server) publicCertCandidates() [][3]string {
	cfg := s.Config().Certificates
	var out [][3]string
	if cfg.PublicCertFile != "" && cfg.PublicKeyFile != "" {
		out = append(out, [3]string{cfg.PublicCertFile, cfg.PublicKeyFile, "configured certificate"})
	}
	for _, n := range s.publicNames() {
		out = append(out, [3]string{filepath.Join("/etc/letsencrypt/live", n, "fullchain.pem"), filepath.Join("/etc/letsencrypt/live", n, "privkey.pem"), "certbot"})
		for _, root := range caddyStores() {
			dirs, _ := filepath.Glob(filepath.Join(root, "certificates", "*", n))
			for _, d := range dirs {
				out = append(out, [3]string{filepath.Join(d, n+".crt"), filepath.Join(d, n+".key"), "Caddy"})
			}
		}
	}
	return out
}

func trustedLeaf(c *tls.Certificate) (*x509.Certificate, bool) {
	if c == nil || len(c.Certificate) == 0 {
		return nil, false
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return nil, false
	}
	inter := x509.NewCertPool()
	for _, der := range c.Certificate[1:] {
		if ic, err := x509.ParseCertificate(der); err == nil {
			inter.AddCert(ic)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, false
	}
	return leaf, true
}

func (s *Server) findPublicCert() *publicCert {
	names := s.publicNames()
	var best *publicCert
	var bestUntil time.Time
	for _, c := range s.publicCertCandidates() {
		pair, err := tls.LoadX509KeyPair(c[0], c[1])
		if err != nil {
			continue
		}
		leaf, ok := trustedLeaf(&pair)
		if !ok || time.Until(leaf.NotAfter) < time.Hour {
			continue
		}
		matches := c[2] == "configured certificate"
		for _, n := range names {
			if leaf.VerifyHostname(n) == nil {
				matches = true
			}
		}
		if !matches {
			continue
		}
		pair.Leaf = leaf
		if best == nil || leaf.NotAfter.After(bestUntil) {
			best, bestUntil = &publicCert{cert: &pair, source: c[2]}, leaf.NotAfter
		}
	}
	return best
}

func (s *Server) refreshPublicCert(force bool) *publicCert {
	st := s.pubCert
	st.mu.Lock()
	defer st.mu.Unlock()
	if !force && time.Since(st.checked) < 10*time.Minute {
		return st.current.Load()
	}
	st.checked = time.Now()
	prev := st.current.Load()
	next := s.findPublicCert()
	if next == nil {
		st.current.Store(nil)
		return nil
	}
	if prev == nil || prev.source != next.source || !prev.cert.Leaf.NotAfter.Equal(next.cert.Leaf.NotAfter) {
		s.log.Info("using a publicly trusted certificate for the dashboard and enrollment port", "source", next.source, "names", strings.Join(next.cert.Leaf.DNSNames, ","), "expires", next.cert.Leaf.NotAfter.Format(time.DateOnly))
	}
	st.current.Store(next)
	return next
}

func (s *Server) publicCertFor(hello *tls.ClientHelloInfo) *tls.Certificate {
	if c := s.acmeCertFor(hello); c != nil {
		return c
	}
	if s.pubCert == nil {
		return nil
	}
	pc := s.refreshPublicCert(false)
	if pc == nil {
		return nil
	}
	if hello != nil && hello.ServerName != "" && pc.cert.Leaf.VerifyHostname(hello.ServerName) != nil {
		return nil
	}
	if hello != nil && hello.ServerName == "" {
		return nil
	}
	return pc.cert
}

func (s *Server) EnrollTrust() (bool, string) {
	if s.acme != nil {
		if c := s.acme.cert.Load(); c != nil && c.Leaf != nil && time.Now().Before(c.Leaf.NotAfter) {
			for _, n := range s.publicNames() {
				if c.Leaf.VerifyHostname(n) == nil {
					return true, "Let's Encrypt"
				}
			}
		}
	}
	if s.pubCert != nil {
		if pc := s.refreshPublicCert(false); pc != nil {
			return true, pc.source
		}
	}
	return false, ""
}
