package server

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/pki"
)

func federateHandshake(t *testing.T, s *Server, cert tls.Certificate) error {
	t.Helper()
	cfg := &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{cert}} // #nosec G402 -- test client; only the server side verification is under test
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", "127.0.0.1:"+strconv.Itoa(s.Config().Ports.Federation), cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	_, err = conn.Read(make([]byte, 64))
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return nil
	}
	if err == nil {
		return nil
	}
	return err
}

func TestFederationCRLRejectsRevokedFederate(t *testing.T) {
	other, err := pki.NewCA(x509Name("Partner CA"), 2048, 1)
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t, func(c *Config) {
		c.Federation.Enabled = true
		c.Ports.Federation = freePort(t)
		c.Federation.TrustPEM = []string{string(other.CertPEM)}
	})
	issue := func(cn string) (tls.Certificate, *x509.Certificate) {
		k, _ := pki.NewKey(2048)
		cert, err := other.IssueClient(cn, &k.PublicKey, false, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: k}, cert
	}
	goodTLS, _ := issue("partner-good")
	badTLS, bad := issue("partner-bad")
	if err := federateHandshake(t, s, badTLS); err != nil {
		t.Fatalf("federate rejected before any revocation list was loaded: %v", err)
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: bad.SerialNumber, RevocationTime: time.Now()}}}, other.Cert, other.Key)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(s.DataDir, "partner.crl"), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0o600)
	os.WriteFile(filepath.Join(s.DataDir, "junk.crl"), []byte("not a crl"), 0o600)
	admin := adminHeaders(t, s)
	if st, b := doReq(t, http.DefaultClient, "PUT", plainURL(s, "/api/settings"), strings.NewReader(`{"certificates":{"revocation":{"crlFiles":["junk.crl"]}}}`), admin); st != http.StatusBadRequest {
		t.Fatalf("unparseable CRL accepted: %d %s", st, b)
	}
	if st, b := doReq(t, http.DefaultClient, "PUT", plainURL(s, "/api/settings"), strings.NewReader(`{"certificates":{"revocation":{"ocsp":true,"ocspResponder":"ftp://x"}}}`), admin); st != http.StatusBadRequest {
		t.Fatalf("bad OCSP responder accepted: %d %s", st, b)
	}
	if st, b := doReq(t, http.DefaultClient, "PUT", plainURL(s, "/api/settings"), strings.NewReader(`{"certificates":{"revocation":{"crlFiles":["partner.crl"]}}}`), admin); st != http.StatusOK {
		t.Fatalf("settings %d %s", st, b)
	}
	if err := federateHandshake(t, s, badTLS); err == nil {
		t.Fatal("revoked federate certificate accepted")
	}
	if err := federateHandshake(t, s, goodTLS); err != nil {
		t.Fatalf("good federate rejected: %v", err)
	}
	st, b := doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/certs/revocation"), nil, admin)
	if st != http.StatusOK {
		t.Fatalf("status %d %s", st, b)
	}
	var info struct {
		CRLFiles []string `json:"crlFiles"`
		CRLs     []struct {
			Issuer  string `json:"issuer"`
			Revoked int    `json:"revoked"`
			Loaded  bool   `json:"loaded"`
		} `json:"crls"`
	}
	json.Unmarshal(b, &info)
	if len(info.CRLs) != 1 || !info.CRLs[0].Loaded || info.CRLs[0].Revoked != 1 || !strings.Contains(info.CRLs[0].Issuer, "Partner CA") {
		t.Fatalf("revocation status %s", b)
	}
	certPEM, keyPEM, _, err := s.pki.NewClientPEM("own-user", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	own, _ := tls.X509KeyPair(certPEM, keyPEM)
	if _, err := s.UpdateConfig(func(c *Config) error { c.Certificates.Revocation.Strict = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := federateHandshake(t, s, own); err != nil {
		t.Fatalf("certificate from the server's own CA rejected in strict mode: %v", err)
	}
}
