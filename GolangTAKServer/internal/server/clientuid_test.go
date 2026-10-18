package server

import (
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/pki"
)

func ownSA(uid string) string {
	now := time.Now().UTC()
	return fmt.Sprintf(`<event version="2.0" uid="%s" type="a-f-G-U-C" how="m-g" time="%s" start="%s" stale="%s"><point lat="1" lon="1" hae="0" ce="9" le="9"/><detail><takv device="Pixel" platform="ATAK-CIV" os="34" version="5.5"/><contact callsign="%s" endpoint="*:-1:stcp"/><__group name="Red" role="Team Member"/></detail></event>`,
		uid, now.Format(time.RFC3339), now.Format(time.RFC3339), now.Add(time.Minute).Format(time.RFC3339), uid)
}

func TestValidateClientUIDAgainstEnrollment(t *testing.T) {
	s := newTestServer(t, func(c *Config) {
		c.AllowAnonymous = false
		c.Filters.ValidateUID = true
	})
	s.dir.EnsureGroup("Red", "", false)
	s.dir.AddUser("red1", "password1", false, []string{"Red"})
	s.dir.AddUser("red2", "password2", false, []string{"Red"})
	certFor := func(user, clientUID string) tls.Certificate {
		certPEM, keyPEM, cert, err := s.pki.NewClientPEM(user, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		s.dir.RecordCert(user, CertRecord{Serial: pki.SerialHex(cert), Created: time.Now(), ClientUID: clientUID})
		pair, _ := tls.X509KeyPair(certPEM, keyPEM)
		return pair
	}
	c1, c2 := certFor("red1", "ANDROID-1"), certFor("red2", "")
	a, err := dialTLS(t, s, &c1)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := dialTLS(t, s, &c2)
	time.Sleep(150 * time.Millisecond)
	a.send(ownSA("ANDROID-1"))
	b.expect(uidIs("ANDROID-1"), "position report from the enrolled device")
	a.send(saXML("MARKER-1", "MARKER", 1, 1))
	b.expect(uidIs("MARKER-1"), "a marker with another uid")
	b.send(ownSA("ANY-UID"))
	time.Sleep(200 * time.Millisecond)
	a.send(ownSA("SPOOFED"))
	b.expectNone(uidIs("SPOOFED"), "position report with a uid the certificate was not enrolled for", 500*time.Millisecond)
	a.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		if _, err := a.r.Next(); err != nil {
			break
		}
	}
	if !a.closedSoon(t) {
		t.Fatal("the impersonating connection stayed open")
	}
}

func (c *testClient) closedSoon(t *testing.T) bool {
	c.conn.SetWriteDeadline(time.Now().Add(time.Second))
	for i := 0; i < 20; i++ {
		if _, err := c.conn.Write([]byte(" ")); err != nil {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}
