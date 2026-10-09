package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeCA struct {
	t        *testing.T
	srv      *httptest.Server
	key      *ecdsa.PrivateKey
	cert     *x509.Certificate
	mu       sync.Mutex
	nonces   map[string]bool
	accounts map[string]*ecdsa.PublicKey
	thumb    map[string]string
	token    string
	status   string
	issued   []byte
	solveURL string
}

func decodeB64(s string) []byte {
	b, _ := base64.RawURLEncoding.DecodeString(s)
	return b
}

func (f *fakeCA) verify(r *http.Request) (map[string]any, []byte, string) {
	var jws struct{ Protected, Payload, Signature string }
	json.NewDecoder(r.Body).Decode(&jws)
	var prot map[string]any
	json.Unmarshal(decodeB64(jws.Protected), &prot)
	f.mu.Lock()
	defer f.mu.Unlock()
	nonce, _ := prot["nonce"].(string)
	if !f.nonces[nonce] {
		f.t.Errorf("bad or reused nonce")
		return nil, nil, ""
	}
	delete(f.nonces, nonce)
	var pub *ecdsa.PublicKey
	kid, _ := prot["kid"].(string)
	if kid != "" {
		pub = f.accounts[kid]
	} else if jwk, ok := prot["jwk"].(map[string]any); ok {
		pub = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(decodeB64(jwk["x"].(string))), Y: new(big.Int).SetBytes(decodeB64(jwk["y"].(string)))}
		kid = "acct-" + jwk["x"].(string)[:8]
		f.accounts[f.srv.URL+"/"+kid] = pub
		canon := `{"crv":"P-256","kty":"EC","x":"` + jwk["x"].(string) + `","y":"` + jwk["y"].(string) + `"}`
		sum := sha256.Sum256([]byte(canon))
		f.thumb[f.srv.URL+"/"+kid] = base64.RawURLEncoding.EncodeToString(sum[:])
		kid = f.srv.URL + "/" + kid
	}
	sig := decodeB64(jws.Signature)
	sum := sha256.Sum256([]byte(jws.Protected + "." + jws.Payload))
	if pub == nil || len(sig) != 64 || !ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		f.t.Errorf("bad JWS signature")
		return nil, nil, ""
	}
	if prot["url"] != f.srv.URL+r.URL.Path {
		f.t.Errorf("url %v does not match %s", prot["url"], r.URL.Path)
	}
	return prot, decodeB64(jws.Payload), kid
}

func (f *fakeCA) nonce(w http.ResponseWriter) {
	b := make([]byte, 8)
	rand.Read(b)
	n := base64.RawURLEncoding.EncodeToString(b)
	f.mu.Lock()
	f.nonces[n] = true
	f.mu.Unlock()
	w.Header().Set("Replay-Nonce", n)
}

func newFakeCA(t *testing.T) *fakeCA {
	f := &fakeCA{t: t, nonces: map[string]bool{}, accounts: map[string]*ecdsa.PublicKey{}, thumb: map[string]string{}, token: "tok123", status: "pending"}
	f.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fake ACME CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &f.key.PublicKey, f.key)
	f.cert, _ = x509.ParseCertificate(der)
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	base := f.srv.URL
	mux.HandleFunc("/dir", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"newNonce": base + "/nonce", "newAccount": base + "/account", "newOrder": base + "/order"})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) { f.nonce(w) })
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		_, payload, kid := f.verify(r)
		if !strings.Contains(string(payload), "termsOfServiceAgreed") {
			t.Error("terms not agreed")
		}
		f.nonce(w)
		w.Header().Set("Location", kid)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"status":"valid"}`))
	})
	var kidUsed string
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		prot, _, _ := f.verify(r)
		kidUsed, _ = prot["kid"].(string)
		f.nonce(w)
		w.Header().Set("Location", base+"/order/1")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"status": "pending", "authorizations": []string{base + "/authz/1"}, "finalize": base + "/finalize/1"})
	})
	mux.HandleFunc("/authz/1", func(w http.ResponseWriter, r *http.Request) {
		f.verify(r)
		f.nonce(w)
		f.mu.Lock()
		st := f.status
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"status": st, "identifier": map[string]string{"value": "tak.example.org"}, "challenges": []map[string]string{{"type": "dns-01", "url": base + "/chal/dns", "token": "x"}, {"type": "http-01", "url": base + "/chal/1", "token": f.token, "status": st}}})
	})
	mux.HandleFunc("/chal/1", func(w http.ResponseWriter, r *http.Request) {
		f.verify(r)
		f.nonce(w)
		resp, err := http.Get(f.solveURL + "/.well-known/acme-challenge/" + f.token)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) == f.token+"."+f.thumb[kidUsed] {
				f.mu.Lock()
				f.status = "valid"
				f.mu.Unlock()
			} else {
				t.Errorf("challenge answer %q", body)
			}
		}
		w.Write([]byte(`{"status":"processing"}`))
	})
	mux.HandleFunc("/finalize/1", func(w http.ResponseWriter, r *http.Request) {
		_, payload, _ := f.verify(r)
		var body struct{ CSR string }
		json.Unmarshal(payload, &body)
		csr, err := x509.ParseCertificateRequest(decodeB64(body.CSR))
		if err != nil || csr.CheckSignature() != nil || len(csr.DNSNames) != 1 || csr.DNSNames[0] != "tak.example.org" {
			t.Errorf("bad csr: %v", err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "tak.example.org"}, DNSNames: csr.DNSNames, NotBefore: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, f.cert, csr.PublicKey, f.key)
		f.issued = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		f.nonce(w)
		json.NewEncoder(w).Encode(map[string]any{"status": "processing", "finalize": base + "/finalize/1"})
	})
	mux.HandleFunc("/order/1", func(w http.ResponseWriter, r *http.Request) {
		f.verify(r)
		f.nonce(w)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid", "certificate": base + "/cert/1", "finalize": base + "/finalize/1"})
	})
	mux.HandleFunc("/cert/1", func(w http.ResponseWriter, r *http.Request) {
		f.verify(r)
		f.nonce(w)
		w.Write(f.issued)
		w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.cert.Raw}))
	})
	return f
}

func TestObtainCertificate(t *testing.T) {
	f := newFakeCA(t)
	answers := map[string]string{}
	var mu sync.Mutex
	solver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		a, ok := answers[strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(a))
	}))
	defer solver.Close()
	f.solveURL = solver.URL
	acct, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := &Client{Directory: f.srv.URL + "/dir", Key: acct, Email: "ops@example.org"}
	cleaned := false
	pemData, err := c.Obtain(context.Background(), []string{"tak.example.org"}, certKey, func(token, keyAuth string) func() {
		mu.Lock()
		answers[token] = keyAuth
		mu.Unlock()
		return func() { cleaned = true }
	})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemData)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || cert.DNSNames[0] != "tak.example.org" || !cleaned {
		t.Fatalf("certificate: %v %v", err, cleaned)
	}
}
