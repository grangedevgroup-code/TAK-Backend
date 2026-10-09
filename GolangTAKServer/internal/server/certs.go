package server

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/pki"
)

type PKI struct {
	dir     string
	CA      *pki.CA
	mu      sync.RWMutex
	cert    *tls.Certificate
	leaf    *x509.Certificate
	trust   []byte
	trustPw string
}

func certDir(dataDir string) string { return filepath.Join(dataDir, "certs") }

func OpenPKI(dataDir string, cfg Config) (*PKI, error) {
	dir := certDir(dataDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	p := &PKI{dir: dir, trustPw: cfg.Certificates.Password}
	certPEM, err1 := os.ReadFile(filepath.Join(dir, "ca.pem"))
	keyPEM, err2 := os.ReadFile(filepath.Join(dir, "ca.key"))
	switch {
	case err1 == nil && err2 == nil:
		ca, err := pki.LoadCA(certPEM, keyPEM, "")
		if err != nil {
			return nil, fmt.Errorf("certificate authority in %s is unreadable: %w", dir, err)
		}
		p.CA = ca
	case errors.Is(err1, os.ErrNotExist) && errors.Is(err2, os.ErrNotExist):
		host, _ := os.Hostname()
		cn := "GolangTAKServer CA " + strings.ToUpper(NewSecret(4))
		if host != "" {
			cn = "GolangTAKServer CA " + safeCN(host)
		}
		ca, err := pki.NewCA(pkix.Name{CommonName: cn, Organization: []string{cfg.Certificates.Organization}, OrganizationalUnit: []string{cfg.Certificates.Unit}}, cfg.Certificates.KeyBits, 10)
		if err != nil {
			return nil, err
		}
		kp, err := pki.KeyPEM(ca.Key)
		if err != nil {
			return nil, err
		}
		if err := writeFileAtomic(filepath.Join(dir, "ca.key"), kp, 0o600); err != nil {
			return nil, err
		}
		if err := writeFileAtomic(filepath.Join(dir, "ca.pem"), ca.CertPEM, 0o644); err != nil {
			return nil, err
		}
		p.CA = ca
	default:
		return nil, fmt.Errorf("certificate authority in %s is incomplete: ca.pem and ca.key must both exist (restore them from backup or remove both to start over)", dir)
	}
	if err := p.EnsureServer(cfg); err != nil {
		return nil, err
	}
	return p, nil
}

func safeCN(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return -1
		}
		return r
	}, s)
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

func ServerNames(cfg Config) []string {
	names := []string{cfg.Address}
	names = append(names, cfg.ExtraNames...)
	if cfg.ACMEDomain != "" {
		names = append(names, cfg.ACMEDomain)
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		names = append(names, h)
		if !strings.Contains(h, ".") {
			names = append(names, h+".local")
		}
	}
	names = append(names, "localhost", "127.0.0.1", "::1")
	names = append(names, LocalIPs()...)
	return names
}

func hasNames(c *x509.Certificate, names []string) bool {
	dns, ips := pki.NormalizeNames(names)
	for _, d := range dns {
		if !slices.ContainsFunc(c.DNSNames, func(x string) bool { return strings.EqualFold(x, d) }) {
			return false
		}
	}
	for _, ip := range ips {
		if !slices.ContainsFunc(c.IPAddresses, func(x net.IP) bool { return ip.Equal(x) }) {
			return false
		}
	}
	return true
}

func (p *PKI) EnsureServer(cfg Config) error {
	names := ServerNames(cfg)
	certPEM, err1 := os.ReadFile(filepath.Join(p.dir, "server.pem"))
	keyPEM, err2 := os.ReadFile(filepath.Join(p.dir, "server.key"))
	if err1 == nil && err2 == nil {
		certs, err := pki.ParseCertPEM(certPEM)
		key, kerr := pki.ParseKeyPEM(keyPEM, "")
		if err == nil && kerr == nil && len(certs) > 0 {
			leaf := certs[0]
			if leaf.CheckSignatureFrom(p.CA.Cert) == nil && hasNames(leaf, names) &&
				time.Now().Add(30*24*time.Hour).Before(leaf.NotAfter) && pki.PublicKeysEqual(leaf.PublicKey, key.Public()) {
				p.setServer(leaf, key)
				return nil
			}
		}
	}
	var key crypto.Signer
	if k, err := pki.ParseKeyPEM(keyPEM, ""); err2 == nil && err == nil {
		key = k
	} else {
		nk, err := pki.NewKey(cfg.Certificates.KeyBits)
		if err != nil {
			return err
		}
		key = nk
	}
	cn := cfg.Address
	if cn == "" {
		cn = "golangtakserver"
	}
	leaf, err := p.CA.IssueServer(cn, names, key, time.Duration(cfg.Certificates.ServerDays)*24*time.Hour)
	if err != nil {
		return err
	}
	kp, err := pki.KeyPEM(key)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(p.dir, "server.key"), kp, 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(p.dir, "server.pem"), pki.CertPEM(leaf), 0o644); err != nil {
		return err
	}
	p.setServer(leaf, key)
	return nil
}

func (p *PKI) setServer(leaf *x509.Certificate, key crypto.Signer) {
	c := &tls.Certificate{Certificate: [][]byte{leaf.Raw, p.CA.Cert.Raw}, PrivateKey: key, Leaf: leaf}
	p.mu.Lock()
	p.cert = c
	p.leaf = leaf
	p.mu.Unlock()
}

func (p *PKI) ServerCert() *tls.Certificate {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cert
}

func (p *PKI) ServerLeaf() *x509.Certificate {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.leaf
}

func (p *PKI) TrustStore() ([]byte, error) {
	p.mu.RLock()
	t := p.trust
	p.mu.RUnlock()
	if t != nil {
		return t, nil
	}
	t, err := pki.EncodeTrustStore([]*x509.Certificate{p.CA.Cert}, p.trustPw, "golangtakserver-ca")
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.trust = t
	p.mu.Unlock()
	return t, nil
}

func (p *PKI) ClientPool() *x509.CertPool { return p.CA.Pool() }

func (p *PKI) NewClientP12(cn string, validity time.Duration, channels bool) ([]byte, *x509.Certificate, error) {
	key, err := pki.NewKey(2048)
	if err != nil {
		return nil, nil, err
	}
	cert, err := p.CA.IssueClient(cn, &key.PublicKey, channels, validity)
	if err != nil {
		return nil, nil, err
	}
	data, err := pki.EncodePKCS12(key, cert, []*x509.Certificate{p.CA.Cert}, p.trustPw, cn)
	if err != nil {
		return nil, nil, err
	}
	return data, cert, nil
}

func (p *PKI) NewClientPEM(cn string, validity time.Duration) (certPEM, keyPEM []byte, cert *x509.Certificate, err error) {
	key, err := pki.NewKey(2048)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err = p.CA.IssueClient(cn, &key.PublicKey, false, validity)
	if err != nil {
		return nil, nil, nil, err
	}
	kp, err := pki.KeyPEM(key)
	if err != nil {
		return nil, nil, nil, err
	}
	return pki.CertPEM(cert), kp, cert, nil
}

func (p *PKI) SelfTestCert() (tls.Certificate, error) {
	cp := filepath.Join(p.dir, "selftest.pem")
	kp := filepath.Join(p.dir, "selftest.key")
	certPEM, err1 := os.ReadFile(cp)
	keyPEM, err2 := os.ReadFile(kp)
	if err1 == nil && err2 == nil {
		if c, err := tls.X509KeyPair(certPEM, keyPEM); err == nil {
			if leaf, err := x509.ParseCertificate(c.Certificate[0]); err == nil && leaf.Subject.CommonName == SelfTestUser && leaf.CheckSignatureFrom(p.CA.Cert) == nil && time.Now().Add(7*24*time.Hour).Before(leaf.NotAfter) {
				return c, nil
			}
		}
	}
	certPEM, keyPEM, _, err := p.NewClientPEM(SelfTestUser, 365*24*time.Hour)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := writeFileAtomic(kp, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := writeFileAtomic(cp, certPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

const SelfTestUser = "golangtakserver-selftest"

func ImportCA(dataDir string, certPEM, keyPEM []byte, password string) (*x509.Certificate, error) {
	ca, err := pki.LoadCA(certPEM, keyPEM, password)
	if err != nil {
		return nil, err
	}
	dir := certDir(dataDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	kp, err := pki.KeyPEM(ca.Key)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(dir, "ca.key"), kp, 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(dir, "ca.pem"), ca.CertPEM, 0o644); err != nil {
		return nil, err
	}
	for _, f := range []string{"server.pem", "server.key", "selftest.pem", "selftest.key"} {
		os.Remove(filepath.Join(dir, f))
	}
	return ca.Cert, nil
}
