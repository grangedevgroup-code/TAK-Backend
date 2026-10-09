package server

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/pki"
)

func fakeCertsrv(t *testing.T, ca *pki.CA) *httptest.Server {
	var mu sync.Mutex
	issued := map[string][]byte{}
	n := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "CORP\\takserver" || p != "ca-password" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/certsrv/certfnsh.asp" && r.Method == http.MethodPost:
			r.ParseForm()
			if r.Form.Get("CertAttrib") != "CertificateTemplate:TAKUser" {
				fmt.Fprint(w, "<html>Your certificate request was Denied</html>")
				return
			}
			blk, _ := pem.Decode([]byte(r.Form.Get("CertRequest")))
			csr, err := x509.ParseCertificateRequest(blk.Bytes)
			if err != nil {
				w.WriteHeader(400)
				return
			}
			cert, err := ca.IssueClient(csr.Subject.CommonName, csr.PublicKey, false, 24*time.Hour)
			if err != nil {
				w.WriteHeader(500)
				return
			}
			mu.Lock()
			n++
			id := fmt.Sprint(n)
			issued[id] = pki.CertPEM(cert)
			mu.Unlock()
			fmt.Fprintf(w, `<html><a href="certnew.cer?ReqID=%s&amp;Enc=b64">Download certificate</a></html>`, id)
		case r.URL.Path == "/certsrv/certnew.cer":
			id := r.URL.Query().Get("ReqID")
			if id == "CACert" {
				w.Write(ca.CertPEM)
				return
			}
			mu.Lock()
			c := issued[id]
			mu.Unlock()
			w.Write(c)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestExternalCAWithCertsrv(t *testing.T) {
	corp, err := pki.NewCA(pkix.Name{CommonName: "Corp Issuing CA"}, 2048, 1)
	if err != nil {
		t.Fatal(err)
	}
	cs := fakeCertsrv(t, corp)
	s := newTestServer(t, func(c *Config) {
		c.Certificates.External = ExternalCAConfig{Mode: "certsrv", URL: cs.URL, Template: "TAKUser", Username: "CORP\\takserver", Password: "ca-password", Insecure: true}
	})
	s.dir.AddUser("corp-user", "corp-user-pw", false, []string{"Blue"})
	c := httpsClient(s, nil)
	enroll := "https://127.0.0.1:" + fmt.Sprint(s.Config().Ports.Enroll)
	key, csr := newCSR(t, "corp-user")
	st, body := doReq(t, c, "POST", enroll+"/Marti/api/tls/signClient/v2?clientUid=ANDROID-corp", strings.NewReader(csr), map[string]string{"basic": "corp-user:corp-user-pw", "Accept": "application/json"})
	if st != 200 {
		t.Fatalf("enroll: %d %s", st, body)
	}
	var res map[string]string
	json.Unmarshal(body, &res)
	der, _ := pemOrBase64(res["signedCert"])
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Issuer.CommonName != "Corp Issuing CA" {
		t.Fatalf("issued by %q", leaf.Issuer.CommonName)
	}
	tc, err := dialTLS(t, s, &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key})
	if err != nil {
		t.Fatalf("certificate from the external CA was refused: %v", err)
	}
	tc.send(saXML("corp-device", "CORP", 1, 1))
	time.Sleep(300 * time.Millisecond)
	found := false
	for _, cl := range s.hub.Clients() {
		if cl.UID() == "corp-device" && cl.User() == "corp-user" {
			found = true
		}
	}
	if !found {
		t.Fatal("device with the external certificate was not signed in as its user")
	}

	p12, cert, err := s.pki.NewClientP12("corp-user", time.Hour, false)
	if err != nil || len(p12) == 0 || cert.Issuer.CommonName != "Corp Issuing CA" {
		t.Fatalf("data package certificate: %v %v", cert, err)
	}

	s.UpdateConfig(func(c *Config) error {
		c.Certificates.External.Template = "Wrong"
		return nil
	})
	if _, _, _, err := s.pki.NewClientPEM("corp-user", time.Hour); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("denied request: %v", err)
	}
}

func pemOrBase64(v string) ([]byte, error) {
	if blk, _ := pem.Decode([]byte(v)); blk != nil {
		return blk.Bytes, nil
	}
	return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(v), ""))
}

func TestExternalSignerHelper(t *testing.T) {
	dir := os.Getenv("GOLANGTAKSERVER_TEST_SIGNER")
	if dir == "" {
		t.Skip()
	}
	certPEM, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
	keyPEM, _ := os.ReadFile(filepath.Join(dir, "ca.key"))
	ca, err := pki.LoadCA(certPEM, keyPEM, "")
	if err != nil {
		os.Exit(3)
	}
	in, _ := io.ReadAll(os.Stdin)
	blk, _ := pem.Decode(in)
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || csr.Subject.CommonName != os.Getenv("GOLANGTAKSERVER_CN") {
		os.Exit(4)
	}
	cert, _ := ca.IssueClient(csr.Subject.CommonName, csr.PublicKey, false, time.Hour)
	os.Stdout.Write(pki.CertPEM(cert))
	os.Stdout.Write(ca.CertPEM)
	os.Exit(0)
}

func TestExternalCAWithCommand(t *testing.T) {
	corp, _ := pki.NewCA(pkix.Name{CommonName: "Command CA"}, 2048, 1)
	dir := t.TempDir()
	kp, _ := pki.KeyPEM(corp.Key)
	os.WriteFile(filepath.Join(dir, "ca.pem"), corp.CertPEM, 0o644)
	os.WriteFile(filepath.Join(dir, "ca.key"), kp, 0o600)
	t.Setenv("GOLANGTAKSERVER_TEST_SIGNER", dir)
	exe, _ := os.Executable()
	s := newTestServer(t, func(c *Config) {
		c.Certificates.External = ExternalCAConfig{Mode: "command", Command: exe, Args: []string{"-test.run=^TestExternalSignerHelper$"}}
	})
	_, _, cert, err := s.pki.NewClientPEM("cmd-user", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Issuer.CommonName != "Command CA" || cert.Subject.CommonName != "cmd-user" {
		t.Fatalf("issued %s by %s", cert.Subject.CommonName, cert.Issuer.CommonName)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: s.pki.ClientPool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("returned chain not trusted: %v", err)
	}
}
