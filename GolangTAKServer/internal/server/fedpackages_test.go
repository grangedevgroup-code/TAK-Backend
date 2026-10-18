package server

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
)

func sendPackageTo(t *testing.T, from *testClient, s *Server, toUID, name string) string {
	t.Helper()
	hash := uploadPackage(t, s, name, []byte("package "+name+" "+time.Now().String()), "SENDER")
	e := cot.New(cot.NewUID(), "b-f-t-r", "h-e", time.Minute)
	e.Detail.AddNew("fileshare", "filename", name+".zip", "senderUrl", s.clientContentURL(hash), "sizeInBytes", "10", "sha256", hash, "senderUid", "SENDER", "senderCallsign", "SENDER", "name", name)
	e.SetDests([]cot.Dest{{UID: toUID}})
	from.send(e.String())
	return hash
}

func expectPackage(t *testing.T, rx *testClient, s *Server, hash string) {
	t.Helper()
	got := rx.expect(func(e *cot.Event) bool {
		fs := e.D("fileshare")
		return e.Type == "b-f-t-r" && fs != nil && strings.EqualFold(fs.Attr("sha256"), hash)
	}, "federated data package announcement")
	if url := got.D("fileshare").Attr("senderUrl"); !strings.HasPrefix(url, s.clientContentURL(hash)[:strings.Index(s.clientContentURL(hash), "/Marti")]) {
		t.Fatalf("senderUrl not rewritten to the receiving server: %s", url)
	}
	waitFor(t, "the package to be stored on the receiving server", 5*time.Second, func() bool {
		res, ok := s.res.Get(hash)
		return ok && s.res.blobs.Exists(res.Hash)
	})
}

func TestFederatedDataPackagesV2(t *testing.T) {
	a, b := fed2Pair(t, nil)
	cb := dialTCP(t, b)
	ca := dialTCP(t, a)
	cb.send(saXML("B-RX", "BRX", 1, 1))
	ca.expect(uidIs("B-RX"), "remote contact")
	hash := sendPackageTo(t, ca, a, "B-RX", "plan-v2")
	expectPackage(t, cb, b, hash)
}

func TestFederatedDataPackagesV1(t *testing.T) {
	a := newTestServer(t, nil)
	fport := freePort(t)
	b := newTestServer(t, func(c *Config) {
		c.Federation.Enabled = true
		c.Ports.Federation = freePort(t)
		c.Federation.HTTPSPort = fport
	})
	if _, err := b.UpdateConfig(func(c *Config) error {
		c.Federation.TrustPEM = []string{string(a.pki.CA.CertPEM)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.UpdateConfig(func(c *Config) error {
		c.Federation.TrustPEM = []string{string(b.pki.CA.CertPEM)}
		c.Federation.HTTPSPort = fport
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	trust := filepath.Join(t.TempDir(), "b-ca.pem")
	os.WriteFile(trust, b.pki.CA.CertPEM, 0o600)
	addPeer(t, a, PeerConfig{Name: "fed-b", URL: "fed://127.0.0.1:" + strconv.Itoa(b.Config().Ports.Federation), Enabled: true, Direction: "both", TrustFile: trust})
	waitPeer(t, a, "fed-b")
	cb := dialTCP(t, b)
	ca := dialTCP(t, a)
	cb.send(saXML("B-RX1", "BRX1", 1, 1))
	ca.expect(uidIs("B-RX1"), "remote contact")
	hash := sendPackageTo(t, ca, a, "B-RX1", "plan-v1")
	expectPackage(t, cb, b, hash)
}
