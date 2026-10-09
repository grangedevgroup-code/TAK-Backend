package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestLetsEncryptCertificateUse(t *testing.T) {
	s := newTestServer(t, nil)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "tak.example.org"}, DNSNames: []string{"tak.example.org"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(60 * 24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	certFile, keyFile, _ := s.acmePaths()
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	kd, _ := x509.MarshalECPrivateKey(k)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)
	s.loadACMECert()

	addr := "127.0.0.1:" + strconv.Itoa(s.Config().Ports.Enroll)
	peer := func(name string) *x509.Certificate {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{ServerName: name, InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0]
	}
	if c := peer("tak.example.org"); c.Subject.CommonName != "tak.example.org" {
		t.Fatalf("by name: %s", c.Subject.CommonName)
	}
	if c := peer("127.0.0.1"); c.Subject.CommonName == "tak.example.org" {
		t.Fatal("the public certificate was used for an IP address")
	}
	if c := peer("other.example.org"); c.Subject.CommonName == "tak.example.org" {
		t.Fatal("the public certificate was used for another name")
	}

	s.acme.challenges.Store("abc", "abc.thumb")
	st, body := doReq(t, http.DefaultClient, "GET", plainURL(s, "/.well-known/acme-challenge/abc"), nil, nil)
	if st != 200 || string(body) != "abc.thumb" {
		t.Fatalf("challenge: %d %s", st, body)
	}
	if st, _ := doReq(t, http.DefaultClient, "GET", plainURL(s, "/.well-known/acme-challenge/nope"), nil, nil); st != 404 {
		t.Fatal("unknown challenge answered")
	}
	if s.needsACME() {
		t.Fatal("a certificate valid for 60 days should not be renewed yet")
	}
}
