package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/pki"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/takproto"
)

var (
	portMu   sync.Mutex
	portNext = 20000 + int(time.Now().UnixNano()%6000)
	portUsed = map[int]bool{}
)

func freePort(t *testing.T) int {
	t.Helper()
	portMu.Lock()
	defer portMu.Unlock()
	for range 12000 {
		p := portNext
		portNext++
		if portNext >= 32000 {
			portNext = 20000
		}
		if portUsed[p] {
			continue
		}
		l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if err != nil {
			continue
		}
		l.Close()
		portUsed[p] = true
		return p
	}
	t.Fatal("no free port between 20000 and 32000")
	return 0
}

func newTestServer(t *testing.T, mutate func(*Config)) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.Address = "127.0.0.1"
	cfg.Bind = "127.0.0.1"
	cfg.Ports = Ports{TCP: freePort(t), TLS: freePort(t), UDP: 0, HTTP: freePort(t), HTTPS: freePort(t), Enroll: freePort(t), WebSocket: freePort(t), API: freePort(t)}
	cfg.Ports.TCPAlt = cfg.Ports.TCP
	cfg.Mesh.Enabled = false
	cfg.Video.Enabled = false
	cfg.Certificates.KeyBits = 2048
	cfg.LogLevel = "debug"
	if mutate != nil {
		mutate(&cfg)
	}
	cfg.fill()
	if err := SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	s, err := New(dir, Options{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	return s
}

type testClient struct {
	t    *testing.T
	conn net.Conn
	r    *takproto.Reader
}

func dialTCP(t *testing.T, s *Server) *testClient {
	t.Helper()
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(s.Config().Ports.TCP), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &testClient{t: t, conn: c, r: takproto.NewReader(c, 1<<22)}
}

func dialTLS(t *testing.T, s *Server, cert *tls.Certificate) (*testClient, error) {
	t.Helper()
	cfg := &tls.Config{RootCAs: s.pki.ClientPool(), ServerName: "127.0.0.1"}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", "127.0.0.1:"+strconv.Itoa(s.Config().Ports.TLS), cfg)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { c.Close() })
	return &testClient{t: t, conn: c, r: takproto.NewReader(c, 1<<22)}, nil
}

func (c *testClient) send(s string) {
	c.t.Helper()
	if _, err := c.conn.Write([]byte(s)); err != nil {
		c.t.Fatal(err)
	}
}

func (c *testClient) next(timeout time.Duration) (*cot.Event, error) {
	c.conn.SetReadDeadline(time.Now().Add(timeout))
	f, err := c.r.Next()
	if err != nil {
		return nil, err
	}
	if f.Proto {
		return takproto.UnmarshalEvent(f.Data)
	}
	return cot.Parse(f.Data)
}

func (c *testClient) expect(pred func(*cot.Event) bool, what string) *cot.Event {
	c.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		e, err := c.next(time.Until(deadline))
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			if err == io.EOF {
				c.t.Fatalf("connection closed while waiting for %s", what)
			}
			continue
		}
		if pred(e) {
			return e
		}
	}
	c.t.Fatalf("did not receive %s", what)
	return nil
}

func (c *testClient) expectNone(pred func(*cot.Event) bool, what string, wait time.Duration) {
	c.t.Helper()
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		e, err := c.next(time.Until(deadline))
		if err != nil {
			return
		}
		if pred(e) {
			c.t.Fatalf("unexpectedly received %s: %s", what, e)
		}
	}
}

func saXML(uid, callsign string, lat, lon float64) string {
	now := time.Now().UTC()
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><event version="2.0" uid="%s" type="a-f-G-U-C" how="m-g" time="%s" start="%s" stale="%s"><point lat="%f" lon="%f" hae="10" ce="5" le="5"/><detail><takv os="34" version="5.4.0" device="TEST" platform="ATAK-CIV"/><contact endpoint="*:-1:stcp" callsign="%s"/><__group name="Cyan" role="Team Member"/><status battery="90"/></detail></event>`,
		uid, cot.FormatTime(now), cot.FormatTime(now), cot.FormatTime(now.Add(2*time.Minute)), lat, lon, callsign)
}

func chatXML(fromUID, fromCS, toCS, toUID, text string) string {
	e := cot.Chat(fromUID, fromCS, toCS, toUID, text, []cot.Dest{{Callsign: toCS}})
	return e.String()
}

func uidIs(uid string) func(*cot.Event) bool {
	return func(e *cot.Event) bool { return e.UID == uid }
}

func TestStreamRouting(t *testing.T) {
	s := newTestServer(t, nil)
	a := dialTCP(t, s)
	b := dialTCP(t, s)
	a.expect(func(e *cot.Event) bool { return e.Type == "t-x-takp-v" }, "protocol announcement")
	a.send(saXML("ANDROID-A", "ALPHA", 40, -105))
	b.expect(uidIs("ANDROID-A"), "A's position at B")
	b.send(saXML("ANDROID-B", "BRAVO", 41, -106))
	a.expect(uidIs("ANDROID-B"), "B's position at A")
	c := dialTCP(t, s)
	c.send(saXML("ANDROID-C", "CHARLIE", 42, -107))
	got := map[string]bool{}
	for len(got) < 2 {
		e := c.expect(func(e *cot.Event) bool { return e.UID == "ANDROID-A" || e.UID == "ANDROID-B" }, "replayed positions")
		got[e.UID] = true
	}
	a.send(chatXML("ANDROID-A", "ALPHA", "BRAVO", "ANDROID-B", "secret-for-bravo"))
	b.expect(func(e *cot.Event) bool { return e.IsChat() && e.Remarks() == "secret-for-bravo" }, "direct message")
	c.expectNone(func(e *cot.Event) bool { return e.IsChat() }, "direct message leak", 500*time.Millisecond)
	a.send(cot.Ping("ANDROID-A-ping").String())
	a.expect(func(e *cot.Event) bool { return e.Type == "t-x-c-t-r" }, "pong")
	c.expectNone(func(e *cot.Event) bool { return e.Type == "t-x-c-t" }, "ping broadcast", 300*time.Millisecond)
	b.conn.Close()
	a.expect(func(e *cot.Event) bool {
		return e.IsDelete() && len(e.Links()) == 1 && e.Links()[0].UID == "ANDROID-B"
	}, "disconnect notice for B")
	if s.hub.ByUID("ANDROID-B") != nil {
		t.Fatal("B still registered")
	}
	if cl := s.hub.ByUID("ANDROID-A"); cl == nil || cl.Info().Callsign != "ALPHA" || cl.Info().Platform != "ATAK-CIV" || cl.Info().Battery != "90" {
		t.Fatalf("identity not tracked: %+v", cl)
	}
}

func TestProtobufNegotiation(t *testing.T) {
	s := newTestServer(t, nil)
	a := dialTCP(t, s)
	b := dialTCP(t, s)
	ann := a.expect(func(e *cot.Event) bool { return e.Type == "t-x-takp-v" }, "announcement")
	if ann.D("TakControl", "TakProtocolSupport").Attr("version") != "1" {
		t.Fatal("bad announcement")
	}
	req := cot.New("neg-1", "t-x-takp-q", "m-g", time.Minute)
	req.Detail.AddNew("TakControl").AddNew("TakRequest", "version", "1")
	a.send(req.String())
	resp := a.expect(func(e *cot.Event) bool { return e.Type == "t-x-takp-r" }, "negotiation response")
	if resp.D("TakControl", "TakResponse").Attr("status") != "true" {
		t.Fatal("negotiation refused")
	}
	b.send(saXML("IOS-B", "BRAVO", 1, 2))
	a.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	f, err := a.r.Next()
	for err == nil && !f.Proto {
		f, err = a.r.Next()
	}
	if err != nil || !f.Proto {
		t.Fatalf("expected protobuf frame after negotiation: %v", err)
	}
	e, err := takproto.UnmarshalEvent(f.Data)
	if err != nil || e.UID != "IOS-B" || e.Callsign() != "BRAVO" {
		t.Fatalf("protobuf decode: %v %v", e, err)
	}
	ev, _ := cot.Parse([]byte(saXML("ANDROID-A", "ALPHA", 3, 4)))
	a.conn.Write(takproto.AppendStreamFrame(nil, takproto.Marshal(ev)))
	got := b.expect(uidIs("ANDROID-A"), "protobuf sender's position as XML")
	if got.Callsign() != "ALPHA" {
		t.Fatal("callsign lost through protobuf")
	}
}

func TestTLSCertsGroupsAndRevocation(t *testing.T) {
	s := newTestServer(t, func(c *Config) { c.AllowAnonymous = false })
	s.dir.EnsureGroup("Red", "", false)
	s.dir.EnsureGroup("Blue", "", false)
	if _, err := s.dir.AddUser("red1", "password1", false, []string{"Red"}); err != nil {
		t.Fatal(err)
	}
	s.dir.AddUser("red2", "password2", false, []string{"Red"})
	s.dir.AddUser("blue1", "password3", false, []string{"Blue"})
	certFor := func(user string) tls.Certificate {
		certPEM, keyPEM, cert, err := s.pki.NewClientPEM(user, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		s.dir.RecordCert(user, CertRecord{Serial: pki.SerialHex(cert), Created: time.Now()})
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return pair
	}
	r1c, r2c, b1c := certFor("red1"), certFor("red2"), certFor("blue1")
	r1, err := dialTLS(t, s, &r1c)
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := dialTLS(t, s, &r2c)
	b1, _ := dialTLS(t, s, &b1c)
	r1.send(saXML("R1", "RED1", 1, 1))
	r2.expect(uidIs("R1"), "same-group delivery")
	b1.expectNone(uidIs("R1"), "cross-group leak", 500*time.Millisecond)
	tcp := dialTCP(t, s)
	tcp.send(saXML("ANON", "ANON", 1, 1))
	r1.expectNone(uidIs("ANON"), "unauthenticated tcp traffic", 500*time.Millisecond)
	tcp.send(`<auth><cot username="blue1" password="password3" uid="ANON"/></auth>`)
	tcp.send(saXML("ANON2", "ANON2", 1, 1))
	defer func() {
		if t.Failed() {
			dumpLogs(t, s)
		}
	}()
	b1.expect(uidIs("ANON2"), "tcp client after <auth>")
	bad := dialTCP(t, s)
	bad.send(`<auth><cot username="blue1" password="wrong-password" uid="X"/></auth>`)
	bad.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		if _, err := bad.r.Next(); err != nil {
			break
		}
	}
	if err := s.dir.RevokeCert(pki.SerialHex(mustLeaf(t, b1c))); err != nil {
		t.Fatal(err)
	}
	if c, err := dialTLS(t, s, &b1c); err == nil {
		c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, rerr := c.r.Next(); rerr == nil {
			t.Fatal("revoked certificate accepted")
		}
	}
	other, _ := pki.NewCA(x509Name("Other CA"), 2048, 1)
	k, _ := pki.NewKey(2048)
	foreign, _ := other.IssueClient("red1", &k.PublicKey, false, time.Hour)
	fc := tls.Certificate{Certificate: [][]byte{foreign.Raw}, PrivateKey: k}
	forced := &tls.Config{RootCAs: s.pki.ClientPool(), ServerName: "127.0.0.1", GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &fc, nil }}
	if fcConn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", "127.0.0.1:"+strconv.Itoa(s.Config().Ports.TLS), forced); err == nil {
		fcConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 16)
		if _, rerr := fcConn.Read(buf); rerr == nil {
			t.Fatal("certificate from foreign CA accepted")
		}
		fcConn.Close()
	}
}

func mustLeaf(t *testing.T, c tls.Certificate) *x509.Certificate {
	l, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestGeofenceAndEmergency(t *testing.T) {
	s := newTestServer(t, func(c *Config) { c.Repeater.IntervalSec = 1 })
	a := dialTCP(t, s)
	b := dialTCP(t, s)
	f := cot.New("filter", "t-x-c-f", "h-g-i-g-o", time.Minute)
	gf := f.Detail.AddNew("subscription").AddNew("geospatialFilter")
	gf.AddNew("boundingBox", "minLatitude", "10", "minLongitude", "10", "maxLatitude", "20", "maxLongitude", "20")
	b.send(f.String())
	time.Sleep(200 * time.Millisecond)
	a.send(saXML("OUT", "OUT", 50, 50))
	a.send(saXML("IN", "IN", 15, 15))
	b.expect(uidIs("IN"), "event inside geofence")
	b.expectNone(uidIs("OUT"), "event outside geofence", 400*time.Millisecond)
	em := cot.New("A-9-1-1", "b-a-o-tbl", "h-e", time.Minute)
	em.Detail.AddNew("emergency", "type", "911 Alert").Text = "ALPHA"
	a.send(em.String())
	b.expect(uidIs("A-9-1-1"), "emergency")
	b.expect(uidIs("A-9-1-1"), "repeated emergency")
	cancel := cot.New("A-9-1-1", "b-a-o-can", "h-e", time.Minute)
	cancel.Detail.AddNew("emergency", "cancel", "true").Text = "ALPHA"
	a.send(cancel.String())
	b.expect(func(e *cot.Event) bool { return e.Type == "b-a-o-can" }, "cancel")
	time.Sleep(300 * time.Millisecond)
	b.expectNone(func(e *cot.Event) bool { return e.Type == "b-a-o-tbl" }, "repeat after cancel", 2500*time.Millisecond)
}

func x509Name(cn string) pkix.Name { return pkix.Name{CommonName: cn} }

func TestManyClients(t *testing.T) {
	s := newTestServer(t, nil)
	var clients []*testClient
	for i := 0; i < 50; i++ {
		clients = append(clients, dialTCP(t, s))
	}
	clients[0].send(saXML("SRC", "SRC", 1, 1))
	for _, c := range clients[1:] {
		c.expect(uidIs("SRC"), "broadcast to all")
	}
	if n := s.hub.Count(); n != 50 {
		t.Fatalf("count %d", n)
	}
	if !strings.Contains(s.hub.View(s.hub.Clients()[0]).Protocol, "xml") {
		t.Fatal("view")
	}
}

func dumpLogs(t *testing.T, s *Server) {
	t.Log("server log:\n" + strings.Join(s.logs.Tail(60), "\n"))
}
