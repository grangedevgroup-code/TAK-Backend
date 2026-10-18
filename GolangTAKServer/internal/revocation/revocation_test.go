package revocation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func newCA(t *testing.T, cn string) *testCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: k}
}

func (ca *testCA) issue(t *testing.T, cn string, serial int64, ocspURL string, eku ...x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if len(eku) == 0 {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), ExtKeyUsage: eku}
	if ocspURL != "" {
		tmpl.OCSPServer = []string{ocspURL}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &k.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func (ca *testCA) crl(t *testing.T, next time.Time, serials ...int64) []byte {
	t.Helper()
	var entries []x509.RevocationListEntry
	for _, s := range serials {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: big.NewInt(s), RevocationTime: time.Now().Add(-time.Minute)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(time.Now().UnixNano()), ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: next, RevokedCertificateEntries: entries}, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}

func TestCRLRevokesAndReloads(t *testing.T) {
	ca := newCA(t, "CA")
	good, bad := ca.issue(t, "good", 10, ""), ca.issue(t, "bad", 11, "")
	path := filepath.Join(t.TempDir(), "ca.crl")
	os.WriteFile(path, ca.crl(t, time.Now().Add(time.Hour), 11), 0o600)
	c := New()
	now := time.Now()
	c.Now = func() time.Time { return now }
	if errs := c.Configure(Config{CRLFiles: []string{path}}); len(errs) > 0 {
		t.Fatal(errs)
	}
	if err := c.Check(context.Background(), [][]*x509.Certificate{{good, ca.cert}}); err != nil {
		t.Fatalf("good: %v", err)
	}
	if err := c.Check(context.Background(), [][]*x509.Certificate{{bad, ca.cert}}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("bad: %v", err)
	}
	os.WriteFile(path, ca.crl(t, time.Now().Add(time.Hour), 10, 11, 12), 0o600)
	now = now.Add(31 * time.Second)
	if err := c.Check(context.Background(), [][]*x509.Certificate{{good, ca.cert}}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("after reload: %v", err)
	}
	if info := c.CRLs(); len(info) != 1 || info[0].Revoked != 3 || !info[0].Loaded {
		t.Fatalf("crl info %+v", info)
	}
}

func (ca *testCA) crlV1(t *testing.T, serials ...int64) []byte {
	t.Helper()
	type entry struct {
		SerialNumber   *big.Int
		RevocationDate time.Time
	}
	type tbs struct {
		Signature  pkix.AlgorithmIdentifier
		Issuer     asn1.RawValue
		ThisUpdate time.Time
		NextUpdate time.Time
		Revoked    []entry
	}
	alg := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}}
	var revoked []entry
	for _, s := range serials {
		revoked = append(revoked, entry{big.NewInt(s), time.Now().Add(-time.Minute).UTC().Truncate(time.Second)})
	}
	body, err := asn1.Marshal(tbs{Signature: alg, Issuer: asn1.RawValue{FullBytes: ca.cert.RawSubject}, ThisUpdate: time.Now().Add(-time.Minute).UTC().Truncate(time.Second), NextUpdate: time.Now().Add(time.Hour).UTC().Truncate(time.Second), Revoked: revoked})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	sig, err := ca.key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(certificateList{TBS: asn1.RawValue{FullBytes: body}, SignatureAlgorithm: alg, Signature: asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestVersion1CRLFromTAKScripts(t *testing.T) {
	ca := newCA(t, "TAK CA")
	good, bad := ca.issue(t, "good", 50, ""), ca.issue(t, "bad", 51, "")
	der := ca.crlV1(t, 51)
	if _, err := x509.ParseRevocationList(der); err == nil {
		t.Log("stdlib now accepts v1 CRLs")
	}
	l, err := ParseCRL(der)
	if err != nil || l.Version != 1 || l.Revoked() != 1 || l.CheckSignatureFrom(ca.cert) != nil {
		t.Fatalf("v1 crl %+v %v", l, err)
	}
	path := filepath.Join(t.TempDir(), "ca.crl")
	os.WriteFile(path, der, 0o600)
	c := New()
	if errs := c.Configure(Config{CRLFiles: []string{path}, Strict: true}); len(errs) > 0 {
		t.Fatal(errs)
	}
	if err := c.Check(context.Background(), [][]*x509.Certificate{{good, ca.cert}}); err != nil {
		t.Fatalf("good: %v", err)
	}
	if err := c.Check(context.Background(), [][]*x509.Certificate{{bad, ca.cert}}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("bad: %v", err)
	}
	other := newCA(t, "TAK CA")
	if err := l.CheckSignatureFrom(other.cert); err == nil {
		t.Fatal("crl signature accepted from a different key with the same name")
	}
}

func TestCRLFromOtherIssuerIgnoredUnlessStrict(t *testing.T) {
	ca, other := newCA(t, "CA"), newCA(t, "Other")
	leaf := ca.issue(t, "leaf", 11, "")
	path := filepath.Join(t.TempDir(), "other.crl")
	os.WriteFile(path, other.crl(t, time.Now().Add(time.Hour), 11), 0o600)
	c := New()
	c.Configure(Config{CRLFiles: []string{path}})
	if err := c.Check(context.Background(), [][]*x509.Certificate{{leaf, ca.cert}}); err != nil {
		t.Fatalf("lenient: %v", err)
	}
	c.Configure(Config{CRLFiles: []string{path}, Strict: true})
	if err := c.Check(context.Background(), [][]*x509.Certificate{{leaf, ca.cert}}); !errors.Is(err, ErrUndetermined) {
		t.Fatalf("strict: %v", err)
	}
	expired := filepath.Join(t.TempDir(), "expired.crl")
	os.WriteFile(expired, ca.crl(t, time.Now().Add(-time.Minute)), 0o600)
	c.Configure(Config{CRLFiles: []string{expired}, Strict: true})
	if err := c.Check(context.Background(), [][]*x509.Certificate{{leaf, ca.cert}}); !errors.Is(err, ErrUndetermined) {
		t.Fatalf("expired crl in strict mode: %v", err)
	}
	c.Skip = func(x *x509.Certificate) bool { return x.SerialNumber.Int64() == 11 }
	if err := c.Check(context.Background(), [][]*x509.Certificate{{leaf, ca.cert}}); err != nil {
		t.Fatalf("skipped issuer: %v", err)
	}
}

func ocspServer(t *testing.T, ca *testCA, responder *x509.Certificate, rkey crypto.Signer, revoked map[int64]bool, hits *atomic.Int64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		serial, nh, kh, oid, err := ParseRequest(body)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		st := Good
		if revoked[serial.Int64()] {
			st = Revoked
		}
		resp, err := CreateResponse(ca.cert, responder, rkey, serial, nh, kh, oid, ResponseTemplate{Status: st, ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour), RevokedAt: time.Now().Add(-time.Hour)})
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(resp)
	}))
}

func TestOCSPGoodRevokedAndCache(t *testing.T) {
	ca := newCA(t, "CA")
	var hits atomic.Int64
	srv := ocspServer(t, ca, ca.cert, ca.key, map[int64]bool{21: true}, &hits)
	defer srv.Close()
	good, bad := ca.issue(t, "good", 20, srv.URL), ca.issue(t, "bad", 21, srv.URL)
	c := New()
	c.Configure(Config{OCSP: true, Strict: true})
	if err := c.Check(context.Background(), [][]*x509.Certificate{{good, ca.cert}}); err != nil {
		t.Fatalf("good: %v", err)
	}
	if err := c.Check(context.Background(), [][]*x509.Certificate{{bad, ca.cert}}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("bad: %v", err)
	}
	c.Check(context.Background(), [][]*x509.Certificate{{good, ca.cert}})
	if hits.Load() != 2 {
		t.Fatalf("expected cached responses, responder hit %d times", hits.Load())
	}
}

func TestOCSPDelegatedResponderAndOverride(t *testing.T) {
	ca, other := newCA(t, "CA"), newCA(t, "Other")
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "ocsp"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &rk.PublicKey, ca.key)
	responder, _ := x509.ParseCertificate(der)
	var hits atomic.Int64
	srv := ocspServer(t, ca, responder, rk, map[int64]bool{31: true}, &hits)
	defer srv.Close()
	leaf := ca.issue(t, "leaf", 31, "")
	c := New()
	c.Configure(Config{OCSP: true, Responder: srv.URL})
	if err := c.Check(context.Background(), [][]*x509.Certificate{{leaf, ca.cert}}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("delegated: %v", err)
	}
	ok := ca.issue(t, "ok", 32, "")
	if err := c.Check(context.Background(), [][]*x509.Certificate{{ok, ca.cert}}); err != nil {
		t.Fatalf("delegated good: %v", err)
	}
	var hits2 atomic.Int64
	forged := ocspServer(t, ca, other.cert, other.key, map[int64]bool{}, &hits2)
	defer forged.Close()
	c.Configure(Config{OCSP: true, Responder: forged.URL, Strict: true})
	if err := c.Check(context.Background(), [][]*x509.Certificate{{ok, ca.cert}}); !errors.Is(err, ErrUndetermined) {
		t.Fatalf("forged responder accepted: %v", err)
	}
}

func TestOCSPUnreachableSoftAndStrict(t *testing.T) {
	ca := newCA(t, "CA")
	leaf := ca.issue(t, "leaf", 40, "http://127.0.0.1:1/ocsp")
	c := New()
	c.Client = &http.Client{Timeout: time.Second}
	c.Configure(Config{OCSP: true})
	if err := c.Check(context.Background(), [][]*x509.Certificate{{leaf, ca.cert}}); err != nil {
		t.Fatalf("soft fail: %v", err)
	}
	c.Configure(Config{OCSP: true, Strict: true})
	if err := c.Check(context.Background(), [][]*x509.Certificate{{leaf, ca.cert}}); !errors.Is(err, ErrUndetermined) {
		t.Fatalf("strict: %v", err)
	}
}

func TestDisabledCheckerAllows(t *testing.T) {
	c := New()
	if c.Enabled() {
		t.Fatal("enabled without config")
	}
	if err := c.Check(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}
