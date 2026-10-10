package server

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/pki"
)

func TestRevokedCertCannotResumeTLSSession(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			s := newTestServer(t, func(c *Config) { c.AllowAnonymous = false })
			if _, err := s.dir.AddUser("red1", "password1", false, nil); err != nil {
				t.Fatal(err)
			}
			certPEM, keyPEM, cert, err := s.pki.NewClientPEM("red1", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			serial := pki.SerialHex(cert)
			s.dir.RecordCert("red1", CertRecord{Serial: serial, Created: time.Now()})
			pair, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				t.Fatal(err)
			}
			cfg := &tls.Config{
				RootCAs:            s.pki.ClientPool(),
				ServerName:         "127.0.0.1",
				Certificates:       []tls.Certificate{pair},
				ClientSessionCache: tls.NewLRUClientSessionCache(4),
				MinVersion:         version,
				MaxVersion:         version,
			}
			addr := "127.0.0.1:" + strconv.Itoa(s.Config().Ports.TLS)
			dial := func() (*tls.Conn, error) {
				return tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, cfg)
			}
			accepted := func(c *tls.Conn) bool {
				_ = c.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
				_, err := c.Read(make([]byte, 1))
				var ne net.Error
				return err == nil || errors.As(err, &ne) && ne.Timeout()
			}

			first, err := dial()
			if err != nil {
				t.Fatal(err)
			}
			if !accepted(first) {
				t.Fatal("a valid certificate was refused")
			}
			first.Close()

			if err := s.dir.RevokeCert(serial); err != nil {
				t.Fatal(err)
			}
			second, err := dial()
			if err != nil {
				return
			}
			defer second.Close()
			if !second.ConnectionState().DidResume {
				t.Fatal("the second connection did not resume, so resumption was not exercised")
			}
			if accepted(second) {
				t.Fatal("a revoked certificate was accepted by resuming an earlier TLS session")
			}
		})
	}
}

func TestTAKCertificateAPIRevokeClosesLiveConnection(t *testing.T) {
	s := newTestServer(t, func(c *Config) { c.AllowAnonymous = false })
	admin := adminToken(t, s)
	if _, err := s.dir.AddUser("red1", "password1", false, nil); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, cert, err := s.pki.NewClientPEM("red1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	serial := pki.SerialHex(cert)
	s.dir.RecordCert("red1", CertRecord{Serial: serial, Created: time.Now()})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{RootCAs: s.pki.ClientPool(), ServerName: "127.0.0.1", Certificates: []tls.Certificate{pair}}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", "127.0.0.1:"+strconv.Itoa(s.Config().Ports.TLS), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	live := func() bool {
		for _, c := range s.hub.Clients() {
			if id := c.Identity(); id != nil && id.Cert != nil && pki.SerialHex(id.Cert) == serial {
				return true
			}
		}
		return false
	}
	for deadline := time.Now().Add(5 * time.Second); !live(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the client never joined")
		}
	}

	if st, body := doReq(t, http.DefaultClient, "DELETE", plainURL(s, "/Marti/api/certadmin/cert/revoke/"+serial), nil, admin); st != http.StatusOK {
		t.Fatalf("revoke: %d %s", st, body)
	}
	if !s.dir.IsRevoked(serial) {
		t.Fatal("the certificate was not revoked")
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	for {
		_, err := conn.Read(buf)
		if err == nil {
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatal("the revoked client stayed connected")
		}
		break
	}
}
