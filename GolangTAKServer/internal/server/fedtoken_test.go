package server

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fedTokenServer(t *testing.T) (*Server, string) {
	t.Helper()
	b := newTestServer(t, func(c *Config) {
		c.Federation.Enabled = true
		c.Ports.FederationV2 = freePort(t)
		c.Federation.Token = FedTokenConfig{Enabled: true, Port: freePort(t)}
	})
	trust := filepath.Join(t.TempDir(), "b-ca.pem")
	if err := os.WriteFile(trust, b.pki.CA.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return b, trust
}

func TestFederationTokenManual(t *testing.T) {
	b, trust := fedTokenServer(t)
	a := newTestServer(t, nil)
	h := adminHeaders(t, b)
	st, body := doReq(t, http.DefaultClient, "POST", plainURL(b, "/Marti/api/generateAndSaveFederationJwtToken"), strings.NewReader(`{"expiration":-1,"attributes":{"name":"partner-a"}}`), h)
	if st != 200 {
		t.Fatalf("generate token: %d %s", st, body)
	}
	tok := strings.TrimSuffix(strings.SplitN(strings.SplitN(string(body), `"data":"`, 2)[1], `"`, 2)[0], `"`)
	if !looksLikeJWT(tok) {
		t.Fatalf("no token in %s", body)
	}
	addPeer(t, a, PeerConfig{Name: "tok-b", URL: "fed2://127.0.0.1:" + strconv.Itoa(b.Config().Federation.Token.Port), Enabled: true, Direction: "both", TrustFile: trust, Token: tok})
	waitPeer(t, a, "tok-b")
	checkBothWays(t, a, b, "fedtoken")
	if _, err := b.UpdateConfig(func(c *Config) error { c.Federation.Federates = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := b.fig2.tokenSession(&http.Request{Header: http.Header{"Authorization": {"Bearer " + tok}}, RemoteAddr: "x"}); err == nil {
		t.Fatal("token accepted after the federate was removed")
	}
}

func TestFederationTokenAutomatic(t *testing.T) {
	b, trust := fedTokenServer(t)
	a := newTestServer(t, nil)
	if _, err := b.UpdateConfig(func(c *Config) error {
		c.Federation.TrustPEM = []string{string(a.pki.CA.CertPEM)}
		c.Federation.CAs = []FederateCAConfig{{Fingerprint: certFingerprint(a.pki.CA.Cert), AllowTokenAuth: true, TokenAuthDays: 1}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	addPeer(t, a, PeerConfig{Name: "auto-b", URL: "fed2://127.0.0.1:" + strconv.Itoa(b.Config().Federation.Token.Port), Enabled: true, Direction: "both", TrustFile: trust, Token: "auto"})
	waitPeer(t, a, "auto-b")
	checkBothWays(t, a, b, "fedauto")
	waitFor(t, "token federate listed", 5*time.Second, func() bool {
		for _, f := range b.fed.clients() {
			if f.version == "v2 token" {
				return true
			}
		}
		return false
	})
}
