package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testCA *CA

func ca(t *testing.T) *CA {
	t.Helper()
	if testCA == nil {
		c, err := NewCA(pkix.Name{CommonName: "Test CA", Organization: []string{"TAK"}, OrganizationalUnit: []string{"TAK"}}, 2048, 10)
		if err != nil {
			t.Fatal(err)
		}
		testCA = c
	}
	return testCA
}

func TestServerAndClientCerts(t *testing.T) {
	c := ca(t)
	key, _ := NewKey(2048)
	srv, err := c.IssueServer("tak.example.com", []string{"tak.example.com", "192.168.1.10", "[::1]", "localhost", "bad name!"}, key, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(srv.DNSNames) != 2 || len(srv.IPAddresses) != 2 {
		t.Fatalf("names %v %v", srv.DNSNames, srv.IPAddresses)
	}
	opts := x509.VerifyOptions{Roots: c.Pool(), DNSName: "tak.example.com", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if _, err := srv.Verify(opts); err != nil {
		t.Fatal(err)
	}
	ckey, _ := rsa.GenerateKey(rand.Reader, 2048)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "alice", Organization: []string{"TAK"}}}, ckey)
	variants := [][]byte{
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		[]byte(base64.StdEncoding.EncodeToString(csrDER)),
		[]byte(strings.Join(chunk(base64.StdEncoding.EncodeToString(csrDER), 64), "\r\n")),
		[]byte("-----BEGIN CERTIFICATE REQUEST-----" + base64.StdEncoding.EncodeToString(csrDER) + "-----END CERTIFICATE REQUEST-----"),
		csrDER,
	}
	for i, v := range variants {
		csr, err := ParseCSR(v)
		if err != nil {
			t.Fatalf("variant %d: %v", i, err)
		}
		if csr.Subject.CommonName != "alice" {
			t.Fatalf("variant %d cn", i)
		}
	}
	csr, _ := ParseCSR(variants[0])
	cl, err := c.IssueClient("alice", csr.PublicKey, true, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Verify(x509.VerifyOptions{Roots: c.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, u := range cl.UnknownExtKeyUsage {
		if u.Equal(OIDChannels) {
			found = true
		}
	}
	if !found {
		t.Fatal("channels EKU missing")
	}
	if _, err := ParseCSR([]byte("not a csr")); err == nil {
		t.Fatal("garbage accepted")
	}
	tampered := append([]byte(nil), csrDER...)
	tampered[len(tampered)-5] ^= 0xff
	if _, err := ParseCSR(tampered); err == nil {
		t.Fatal("bad signature accepted")
	}
}

func chunk(s string, n int) []string {
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	return append(out, s)
}

func TestPKCS12RoundTrip(t *testing.T) {
	c := ca(t)
	key, _ := NewKey(2048)
	cert, err := c.IssueClient("bob", &key.PublicKey, false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p12, err := EncodePKCS12(key, cert, []*x509.Certificate{c.Cert}, "atakatak", "bob")
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodePKCS12(p12, "atakatak")
	if err != nil {
		t.Fatal(err)
	}
	if got.Cert == nil || got.Cert.SerialNumber.Cmp(cert.SerialNumber) != 0 || len(got.Certs) != 2 {
		t.Fatalf("decoded: %+v", got)
	}
	if !PublicKeysEqual(got.Key.(*rsa.PrivateKey).Public(), &key.PublicKey) {
		t.Fatal("key mismatch")
	}
	if _, err := DecodePKCS12(p12, "wrong"); err != ErrWrongPassword {
		t.Fatalf("want ErrWrongPassword got %v", err)
	}
	ts, err := EncodeTrustStore([]*x509.Certificate{c.Cert}, "atakatak", "root")
	if err != nil {
		t.Fatal(err)
	}
	tsd, err := DecodePKCS12(ts, "atakatak")
	if err != nil || len(tsd.Certs) != 1 || tsd.Key != nil {
		t.Fatalf("truststore: %+v %v", tsd, err)
	}
}

func TestKDFVector(t *testing.T) {
	got := sha1KDF(bmpPassword("smeg"), []byte{0x0A, 0x58, 0xCF, 0x64, 0x53, 0x0D, 0x82, 0x3F}, 1, 1, 24)
	want := []byte{0x8A, 0xAA, 0xE6, 0x29, 0x7B, 0x6C, 0xB0, 0x46, 0x42, 0xAB, 0x5B, 0x07, 0x78, 0x51, 0x28, 0x4E, 0xB7, 0x12, 0x8F, 0x1A, 0x2A, 0x7F, 0xBC, 0xA3}
	if string(got) != string(want) {
		t.Fatalf("kdf %x", got)
	}
}

func openssl(t *testing.T) string {
	p, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed")
	}
	return p
}

func TestOpenSSLReadsOurPKCS12(t *testing.T) {
	bin := openssl(t)
	c := ca(t)
	key, _ := NewKey(2048)
	cert, _ := c.IssueClient("carol", &key.PublicKey, false, time.Hour)
	p12, _ := EncodePKCS12(key, cert, []*x509.Certificate{c.Cert}, "atakatak", "carol")
	ts, _ := EncodeTrustStore([]*x509.Certificate{c.Cert}, "atakatak")
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "user.p12"), p12, 0o600)
	os.WriteFile(filepath.Join(dir, "trust.p12"), ts, 0o600)
	out, err := exec.Command(bin, "pkcs12", "-in", filepath.Join(dir, "user.p12"), "-passin", "pass:atakatak", "-passout", "pass:x", "-info").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl rejected user.p12: %v\n%s", err, out)
	}
	s := string(out)
	if !strings.Contains(s, "pbeWithSHA1And3-KeyTripleDES-CBC") || !strings.Contains(s, "MAC: sha1") || !strings.Contains(s, "BEGIN ENCRYPTED PRIVATE KEY") {
		t.Fatalf("unexpected openssl output:\n%s", s)
	}
	out, err = exec.Command(bin, "pkcs12", "-in", filepath.Join(dir, "trust.p12"), "-passin", "pass:atakatak", "-nokeys").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "BEGIN CERTIFICATE") {
		t.Fatalf("openssl rejected trust.p12: %v\n%s", err, out)
	}
}

func TestWeReadOpenSSLPKCS12AndKeys(t *testing.T) {
	bin := openssl(t)
	c := ca(t)
	key, _ := NewKey(2048)
	cert, _ := c.IssueClient("dave", &key.PublicKey, false, time.Hour)
	dir := t.TempDir()
	kp, _ := KeyPEM(key)
	os.WriteFile(filepath.Join(dir, "k.pem"), kp, 0o600)
	os.WriteFile(filepath.Join(dir, "c.pem"), CertPEM(cert), 0o600)
	os.WriteFile(filepath.Join(dir, "ca.pem"), c.CertPEM, 0o600)
	out, err := exec.Command(bin, "pkcs12", "-export", "-inkey", filepath.Join(dir, "k.pem"), "-in", filepath.Join(dir, "c.pem"), "-certfile", filepath.Join(dir, "ca.pem"), "-passout", "pass:secret", "-out", filepath.Join(dir, "o.p12")).CombinedOutput()
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "o.p12"))
	got, err := DecodePKCS12(data, "secret")
	if err != nil {
		t.Fatalf("decode openssl default p12: %v", err)
	}
	if got.Cert == nil || got.Cert.Subject.CommonName != "dave" || len(got.Certs) != 2 {
		t.Fatalf("decoded %+v", got)
	}
	out, err = exec.Command(bin, "rsa", "-in", filepath.Join(dir, "k.pem"), "-des3", "-traditional", "-passout", "pass:atakatak", "-out", filepath.Join(dir, "legacy.key")).CombinedOutput()
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	out, err = exec.Command(bin, "pkcs8", "-topk8", "-in", filepath.Join(dir, "k.pem"), "-passout", "pass:atakatak", "-out", filepath.Join(dir, "pk8.key")).CombinedOutput()
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	for _, f := range []string{"legacy.key", "pk8.key"} {
		b, _ := os.ReadFile(filepath.Join(dir, f))
		k, err := ParseKeyPEM(b, "atakatak")
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if !PublicKeysEqual(k.Public(), &key.PublicKey) {
			t.Fatalf("%s: key mismatch", f)
		}
		if _, err := ParseKeyPEM(b, "nope"); err == nil {
			t.Fatalf("%s: wrong password accepted", f)
		}
	}
	caKey, _ := KeyPEM(c.Key)
	if _, err := LoadCA(c.CertPEM, caKey, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCA(c.CertPEM, kp, ""); err == nil {
		t.Fatal("mismatched CA key accepted")
	}
}
