package server

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/pki"
)

func httpsClient(s *Server, cert *tls.Certificate) *http.Client {
	cfg := &tls.Config{RootCAs: s.pki.ClientPool(), ServerName: "127.0.0.1"}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, Proxy: nil}}
}

func plainURL(s *Server, path string) string {
	return "http://127.0.0.1:" + strconv.Itoa(s.Config().Ports.HTTP) + path
}

func doReq(t *testing.T, c *http.Client, method, url string, body io.Reader, hdr map[string]string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		if k == "basic" {
			u, p, _ := strings.Cut(v, ":")
			req.SetBasicAuth(u, p)
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func newCSR(t *testing.T, cn string) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn, Organization: []string{"TAK"}, OrganizationalUnit: []string{"TAK"}}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, base64.StdEncoding.EncodeToString(der)
}

func TestEnrollmentAndCertificateLogin(t *testing.T) {
	s := newTestServer(t, nil)
	if _, err := s.dir.AddUser("alice", "correct-horse", false, []string{"Red"}); err != nil {
		t.Fatal(err)
	}
	c := httpsClient(s, nil)
	enroll := "https://127.0.0.1:" + strconv.Itoa(s.Config().Ports.Enroll)

	st, body := doReq(t, c, "GET", enroll+"/Marti/api/tls/config", nil, nil)
	if st != 200 || !strings.Contains(string(body), "nameEntry") {
		t.Fatalf("tls config: %d %s", st, body)
	}

	key, csr := newCSR(t, "alice")
	st, _ = doReq(t, c, "POST", enroll+"/Marti/api/tls/signClient/v2?clientUid=ANDROID-alice&version=3", strings.NewReader(csr), map[string]string{"basic": "alice:wrong-password", "Accept": "application/json"})
	if st != http.StatusUnauthorized {
		t.Fatalf("wrong password accepted: %d", st)
	}
	_, otherCSR := newCSR(t, "mallory")
	st, _ = doReq(t, c, "POST", enroll+"/Marti/api/tls/signClient/v2", strings.NewReader(otherCSR), map[string]string{"basic": "alice:correct-horse"})
	if st != http.StatusBadRequest {
		t.Fatalf("certificate request for another name accepted: %d", st)
	}

	st, body = doReq(t, c, "POST", enroll+"/Marti/api/tls/signClient/v2?clientUid=ANDROID-alice&version=3", strings.NewReader(csr), map[string]string{"basic": "alice:correct-horse", "Accept": "application/json"})
	if st != 200 {
		t.Fatalf("signClient v2: %d %s", st, body)
	}
	var signed struct {
		SignedCert string `json:"signedCert"`
		CA0        string `json:"ca0"`
	}
	if err := json.Unmarshal(body, &signed); err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(signed.SignedCert)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "alice" {
		t.Fatalf("common name %q", cert.Subject.CommonName)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: s.pki.ClientPool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("signed certificate does not chain to the CA: %v", err)
	}
	caDER, _ := base64.StdEncoding.DecodeString(signed.CA0)
	if !bytes.Equal(caDER, s.pki.CA.Cert.Raw) {
		t.Fatal("ca0 is not the server CA")
	}

	st, body = doReq(t, c, "POST", enroll+"/Marti/api/tls/signClient/v2", strings.NewReader(csr), map[string]string{"basic": "alice:correct-horse", "Accept": "application/xml"})
	if st != 200 || !strings.Contains(string(body), "<signedCert>") {
		t.Fatalf("xml enrollment: %d %s", st, body)
	}
	st, body = doReq(t, c, "POST", enroll+"/Marti/api/tls/signClient", strings.NewReader(csr), map[string]string{"basic": "alice:correct-horse"})
	if st != 200 {
		t.Fatalf("signClient v1: %d", st)
	}
	ks, err := pki.DecodePKCS12(body, s.Config().Certificates.Password)
	if err != nil {
		t.Fatalf("v1 keystore: %v", err)
	}
	if len(ks.Certs)+boolInt(ks.Cert != nil) < 2 {
		t.Fatalf("v1 keystore has %d certificates", len(ks.Certs))
	}

	tc := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	cl, err := dialTLS(t, s, &tc)
	if err != nil {
		t.Fatal(err)
	}
	cl.send(saXML("ANDROID-alice", "ALICE", 1, 2))
	cl.send(cot.Ping("ANDROID-alice-ping").String())
	cl.expect(func(e *cot.Event) bool { return e.Type == "t-x-c-t-r" }, "pong over enrolled certificate")

	hc := httpsClient(s, &tc)
	st, body = doReq(t, hc, "GET", "https://127.0.0.1:"+strconv.Itoa(s.Config().Ports.HTTPS)+"/Marti/api/util/user/roles", nil, nil)
	if st != 200 {
		t.Fatalf("certificate sign-in on HTTPS: %d %s", st, body)
	}

	u, _ := s.dir.User("alice")
	if len(u.Certs) < 3 {
		t.Fatalf("issued certificates not recorded: %d", len(u.Certs))
	}
	if n := s.dir.RevokeAll("alice"); n == 0 {
		t.Fatal("nothing revoked")
	}
	if cl2, err := dialTLS(t, s, &tc); err == nil {
		cl2.send(cot.Ping("again").String())
		if _, err := cl2.next(2 * time.Second); err == nil {
			t.Fatal("revoked certificate still accepted")
		}
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestConnectionPackages(t *testing.T) {
	s := newTestServer(t, func(c *Config) { c.Name = "Pkg, Test" })
	if _, err := s.dir.AddUser("bob", "password-123", false, nil); err != nil {
		t.Fatal(err)
	}
	pw := s.Config().Certificates.Password
	for _, kind := range []PackageKind{PackageCert, PackageEnroll, PackageTCP} {
		data, name, err := s.BuildPackage(kind, "bob", "tak.example.org")
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if !strings.HasSuffix(name, ".zip") {
			t.Fatalf("%s: package name %q", kind, name)
		}
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		files := map[string][]byte{}
		for _, f := range zr.File {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(rc)
			rc.Close()
			files[f.Name] = b
		}
		manifest := string(files["MANIFEST/manifest.xml"])
		if !strings.Contains(manifest, "<MissionPackageManifest") {
			t.Fatalf("%s: manifest missing: %v", kind, keys(files))
		}
		var pref, trust, user []byte
		for n, b := range files {
			switch {
			case strings.HasSuffix(n, ".pref"):
				pref = b
			case strings.Contains(n, "truststore"):
				trust = b
			case strings.HasSuffix(n, ".p12"):
				user = b
			}
			if n != "MANIFEST/manifest.xml" && !strings.Contains(manifest, n) {
				t.Fatalf("%s: %s not listed in the manifest", kind, n)
			}
		}
		if pref == nil {
			t.Fatalf("%s: no preference file", kind)
		}
		switch kind {
		case PackageTCP:
			if !strings.Contains(string(pref), "tak.example.org:"+strconv.Itoa(s.Config().Ports.TCP)+":tcp") {
				t.Fatalf("tcp pref: %s", pref)
			}
			if trust != nil || user != nil {
				t.Fatal("tcp package contains certificates")
			}
			continue
		case PackageEnroll:
			if !strings.Contains(string(pref), "enrollForCertificateWithTrust0") || user != nil {
				t.Fatalf("enroll pref: %s", pref)
			}
		case PackageCert:
			if user == nil {
				t.Fatal("certificate package has no client certificate")
			}
			ks, err := pki.DecodePKCS12(user, pw)
			if err != nil {
				t.Fatalf("client p12: %v", err)
			}
			if ks.Key == nil || ks.Cert == nil || ks.Cert.Subject.CommonName != "bob" {
				t.Fatal("client p12 does not hold bob's key and certificate")
			}
		}
		if !strings.Contains(string(pref), "tak.example.org:"+strconv.Itoa(s.Config().Ports.TLS)+":ssl") {
			t.Fatalf("%s pref: %s", kind, pref)
		}
		ts, err := pki.DecodePKCS12(trust, pw)
		if err != nil {
			t.Fatalf("truststore: %v", err)
		}
		found := ts.Cert != nil && bytes.Equal(ts.Cert.Raw, s.pki.CA.Cert.Raw)
		for _, c := range ts.Certs {
			found = found || bytes.Equal(c.Raw, s.pki.CA.Cert.Raw)
		}
		if !found {
			t.Fatal("truststore does not contain the CA")
		}
	}
	if !strings.HasPrefix(s.ITAKString("10.1.2.3", false), "Pkg  Test,10.1.2.3,") {
		t.Fatalf("iTAK string %q", s.ITAKString("10.1.2.3", false))
	}
	if u := s.ATAKEnrollURI("10.1.2.3", "bob", "tok"); !strings.HasPrefix(u, "tak://com.atakmap.app/enroll?") || !strings.Contains(u, "username=bob") {
		t.Fatalf("enroll uri %q", u)
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func uploadPackage(t *testing.T, s *Server, name string, content []byte, creator string) string {
	t.Helper()
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("assetfile", name)
	fw.Write(content)
	mw.Close()
	st, body := doReq(t, http.DefaultClient, "POST", plainURL(s, "/Marti/sync/missionupload?hash="+hash+"&filename="+name+"&creatorUid="+creator), &buf, map[string]string{"Content-Type": mw.FormDataContentType()})
	if st != 200 || !strings.Contains(string(body), "/Marti/sync/content?hash=") {
		t.Fatalf("upload: %d %s", st, body)
	}
	return hash
}

func TestDataPackageFlow(t *testing.T) {
	s := newTestServer(t, nil)
	content := []byte("PK fake data package " + time.Now().String())
	recv := dialTCP(t, s)
	recv.send(saXML("ANDROID-recv", "RECV", 1, 1))
	time.Sleep(200 * time.Millisecond)
	hash := uploadPackage(t, s, "orders", content, "ANDROID-up")

	st, body := doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/sync/missionquery?hash="+hash), nil, nil)
	if st != 200 || !strings.Contains(string(body), hash) {
		t.Fatalf("missionquery: %d %s", st, body)
	}
	st, body = doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/sync/content?hash="+hash), nil, nil)
	if st != 200 || !bytes.Equal(body, content) {
		t.Fatalf("content: %d %q", st, body)
	}
	st, body = doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/sync/search?keywords=missionpackage"), nil, nil)
	if st != 200 || !strings.Contains(string(body), hash) || !strings.Contains(string(body), "orders.zip") {
		t.Fatalf("search: %d %s", st, body)
	}
	st, _ = doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/sync/content?hash="+strings.Repeat("0", 64)), nil, nil)
	if st != http.StatusNotFound {
		t.Fatalf("missing content returned %d", st)
	}
	share := cot.New(cot.NewUID(), "b-f-t-r", "h-e", time.Minute)
	share.Detail.AddNew("fileshare", "filename", "orders.zip", "senderUrl", plainURL(s, "/Marti/sync/content?hash="+hash), "sizeInBytes", strconv.Itoa(len(content)), "sha256", hash, "senderUid", "ANDROID-up", "senderCallsign", "UP", "name", "orders")
	share.SetDests([]cot.Dest{{Callsign: "RECV"}})
	up := dialTCP(t, s)
	up.send(saXML("ANDROID-up", "UP", 1, 1))
	up.send(share.String())
	got := recv.expect(func(e *cot.Event) bool { return e.Type == "b-f-t-r" }, "file transfer request")
	if fs := got.D("fileshare"); fs == nil || fs.Attr("sha256") != hash {
		t.Fatalf("file share detail lost: %s", got)
	}
}

func TestMissionLifecycle(t *testing.T) {
	s := newTestServer(t, nil)
	member := dialTCP(t, s)
	member.send(saXML("ANDROID-m1", "M1", 1, 1))
	time.Sleep(200 * time.Millisecond)
	base := plainURL(s, "/Marti/api/missions/ops")

	st, body := doReq(t, http.DefaultClient, "PUT", base+"?creatorUid=ANDROID-m1&tool=public&description=Operations", nil, nil)
	if st >= 300 {
		t.Fatalf("create: %d %s", st, body)
	}
	st, body = doReq(t, http.DefaultClient, "PUT", base+"/subscription?uid=ANDROID-m1", nil, nil)
	if st >= 300 || !strings.Contains(string(body), "token") {
		t.Fatalf("subscribe: %d %s", st, body)
	}
	hash := uploadPackage(t, s, "plan", []byte("mission file "+time.Now().String()), "ANDROID-m1")
	st, body = doReq(t, http.DefaultClient, "PUT", base+"/contents?creatorUid=ANDROID-m1", strings.NewReader(`{"hashes":["`+hash+`"]}`), map[string]string{"Content-Type": "application/json"})
	if st >= 300 {
		t.Fatalf("add contents: %d %s", st, body)
	}
	member.expect(func(e *cot.Event) bool { return strings.HasPrefix(e.Type, "t-x-m-c") }, "mission change notification")

	marker := cot.New("mission-marker-1", "a-h-G", "h-e", 10*time.Minute)
	marker.Point = cot.Point{Lat: 10, Lon: 20, Hae: 0, Ce: 1, Le: 1}
	marker.Detail.AddNew("contact", "callsign", "Target")
	marker.SetDests([]cot.Dest{{Mission: "ops"}})
	member.send(marker.String())
	time.Sleep(300 * time.Millisecond)

	st, body = doReq(t, http.DefaultClient, "GET", base, nil, nil)
	if st != 200 || !strings.Contains(string(body), hash) || !strings.Contains(string(body), "mission-marker-1") {
		t.Fatalf("mission contents: %d %s", st, body)
	}
	st, body = doReq(t, http.DefaultClient, "GET", base+"/changes", nil, nil)
	if st != 200 || !strings.Contains(string(body), "ADD_CONTENT") {
		t.Fatalf("changes: %d %s", st, body)
	}
	st, body = doReq(t, http.DefaultClient, "GET", base+"/cot", nil, nil)
	if st != 200 || !strings.Contains(string(body), "mission-marker-1") {
		t.Fatalf("mission cot: %d %s", st, body)
	}
	st, body = doReq(t, http.DefaultClient, "DELETE", base+"?creatorUid=ANDROID-m1", nil, nil)
	if st >= 300 {
		t.Fatalf("delete: %d %s", st, body)
	}
	st, _ = doReq(t, http.DefaultClient, "GET", base, nil, nil)
	if st != http.StatusNotFound {
		t.Fatalf("deleted mission still returned %d", st)
	}
}

func addPeer(t *testing.T, s *Server, p PeerConfig) {
	t.Helper()
	if _, err := s.UpdateConfig(func(c *Config) error {
		c.Peers = append(c.Peers, p)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.reloadPeers()
}

func waitPeer(t *testing.T, s *Server, name string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, p := range s.peerStatus() {
			if p.Name == name && p.State == "connected" {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("link %s did not connect: %+v", name, s.peerStatus())
}

func checkBothWays(t *testing.T, a, b *Server, tag string) {
	t.Helper()
	ca := dialTCP(t, a)
	cb := dialTCP(t, b)
	ca.send(saXML("A-"+tag, "A-"+tag, 1, 1))
	cb.send(saXML("B-"+tag, "B-"+tag, 2, 2))
	cb.expect(uidIs("A-"+tag), "event from server A on server B ("+tag+")")
	ca.expect(uidIs("B-"+tag), "event from server B on server A ("+tag+")")
	ca.expectNone(uidIs("A-"+tag), "own event echoed back", 800*time.Millisecond)
}

func TestPeerLinksBothWays(t *testing.T) {
	b := newTestServer(t, nil)
	a := newTestServer(t, nil)
	addPeer(t, a, PeerConfig{Name: "b-tcp", URL: "tcp://127.0.0.1:" + strconv.Itoa(b.Config().Ports.TCP), Enabled: true, Direction: "both"})
	waitPeer(t, a, "b-tcp")
	checkBothWays(t, a, b, "tcp")

	c := newTestServer(t, nil)
	addPeer(t, c, PeerConfig{Name: "b-ws", URL: "ws://127.0.0.1:" + strconv.Itoa(b.Config().Ports.WebSocket) + "/", Enabled: true, Direction: "both"})
	waitPeer(t, c, "b-ws")
	checkBothWays(t, c, b, "ws")

	d := newTestServer(t, nil)
	if _, err := b.dir.AddUser("linkuser", "link-password", false, nil); err != nil {
		t.Fatal(err)
	}
	trust := filepath.Join(t.TempDir(), "b-ca.pem")
	if err := os.WriteFile(trust, b.pki.CA.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	addPeer(t, d, PeerConfig{Name: "b-tls", URL: "tls://127.0.0.1:" + strconv.Itoa(b.Config().Ports.TLS), Enabled: true, Direction: "both", Username: "linkuser", Password: "link-password", TrustFile: trust})
	waitPeer(t, d, "b-tls")
	checkBothWays(t, d, b, "tls")
}

func TestFederationBothWays(t *testing.T) {
	a := newTestServer(t, nil)
	b := newTestServer(t, func(c *Config) {
		c.Federation.Enabled = true
		c.Ports.Federation = freePort(t)
	})
	if _, err := b.UpdateConfig(func(c *Config) error {
		c.Federation.TrustPEM = []string{string(a.pki.CA.CertPEM)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	trust := filepath.Join(t.TempDir(), "b-ca.pem")
	if err := os.WriteFile(trust, b.pki.CA.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	addPeer(t, a, PeerConfig{Name: "fed-b", URL: "fed://127.0.0.1:" + strconv.Itoa(b.Config().Ports.Federation), Enabled: true, Direction: "both", TrustFile: trust})
	waitPeer(t, a, "fed-b")
	checkBothWays(t, a, b, "fed")
}

func TestHistoryRespectsGroups(t *testing.T) {
	s := newTestServer(t, func(c *Config) { c.AllowAnonymous = false })
	if _, err := s.dir.AddUser("red1", "password-red", false, []string{"Red"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.dir.AddUser("blue1", "password-blue", false, []string{"Blue"}); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, _, err := s.pki.NewClientPEM("red1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := dialTLS(t, s, &kp)
	if err != nil {
		t.Fatal(err)
	}
	cl.send(saXML("RED-UNIT", "RED", 5, 5))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && s.history.Written.Load() == 0 {
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	get := func(user, pass string) string {
		_, body := doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/cot/history?uid=RED-UNIT&secago=600"), nil, map[string]string{"basic": user + ":" + pass, "X-Requested-With": "test"})
		return string(body)
	}
	if !strings.Contains(get("red1", "password-red"), "RED-UNIT") {
		t.Fatal("member of the group cannot see its own history")
	}
	if strings.Contains(get("blue1", "password-blue"), "RED-UNIT") {
		t.Fatal("history leaked to another group")
	}
}

func TestFreeTAKCompatibleAPI(t *testing.T) {
	s := newTestServer(t, nil)
	secret, _, err := s.dir.CreateToken(func() string {
		s.dir.AddUser("ftsadmin", "fts-password", true, nil)
		return "ftsadmin"
	}(), "api", "test", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	recv := dialTCP(t, s)
	recv.send(saXML("ANDROID-fts", "FTS", 38.9, -77.0))
	time.Sleep(200 * time.Millisecond)
	api := "http://127.0.0.1:" + strconv.Itoa(s.Config().Ports.API)
	st, body := doReq(t, http.DefaultClient, "GET", api+"/Alive", nil, nil)
	if st != 200 {
		t.Fatalf("alive: %d %s", st, body)
	}
	st, _ = doReq(t, http.DefaultClient, "POST", api+"/ManageGeoObject/postGeoObject", strings.NewReader(`{"latitude":38.9,"longitude":-77.0,"attitude":"hostile","geoObject":"Ground","name":"Tango"}`), map[string]string{"Content-Type": "application/json"})
	if st != http.StatusUnauthorized {
		t.Fatalf("unauthenticated FTS call returned %d", st)
	}
	st, body = doReq(t, http.DefaultClient, "POST", api+"/ManageGeoObject/postGeoObject", strings.NewReader(`{"latitude":38.9,"longitude":-77.0,"attitude":"hostile","geoObject":"Ground","how":"nonCoT","name":"Tango","timeout":600}`), map[string]string{"Content-Type": "application/json", "Authorization": "Bearer " + secret})
	if st != 200 {
		t.Fatalf("postGeoObject: %d %s", st, body)
	}
	e := recv.expect(func(e *cot.Event) bool { return e.Callsign() == "Tango" }, "geo object")
	if e.Type != "a-h-G" {
		t.Fatalf("geo object type %q", e.Type)
	}
	st, body = doReq(t, http.DefaultClient, "POST", api+"/ManageChat/postChatToAll", strings.NewReader(`{"message":"hello from the api","sender":"API"}`), map[string]string{"Content-Type": "application/json", "Authorization": "Bearer " + secret})
	if st != 200 {
		t.Fatalf("chat: %d %s", st, body)
	}
	recv.expect(func(e *cot.Event) bool { return e.IsChat() && e.Remarks() == "hello from the api" }, "chat from the API")
}
