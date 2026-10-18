package quic

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestInitialKeysRFC9001(t *testing.T) {
	rx, tx := initialKeys(unhex(t, "8394c8f03e515708"), true)
	if hex.EncodeToString(rx.secret) != "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea" {
		t.Fatalf("client secret %x", rx.secret)
	}
	if hex.EncodeToString(rx.iv) != "fa044b2f42a3fd3b46fb255c" {
		t.Fatalf("client iv %x", rx.iv)
	}
	if hex.EncodeToString(tx.secret) != "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b" {
		t.Fatalf("server secret %x", tx.secret)
	}
	if hex.EncodeToString(tx.iv) != "0ac1493ca1905853b0bba03e" {
		t.Fatalf("server iv %x", tx.iv)
	}
	if m := rx.mask(unhex(t, "d1b1c98dd7689fb8ec11d242b123dc9b")); hex.EncodeToString(m[:]) != "437b9aec36" {
		t.Fatalf("client mask %x", m)
	}
	if m := tx.mask(unhex(t, "2cd0991cd25b0aac406a5816b6394100")); hex.EncodeToString(m[:]) != "2ec0d8356a" {
		t.Fatalf("server mask %x", m)
	}
}

func TestChaChaShortHeaderRFC9001(t *testing.T) {
	k, err := newKeys(tls.TLS_CHACHA20_POLY1305_SHA256, unhex(t, "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(k.iv) != "e0459b3474bdd0e44a41c144" {
		t.Fatalf("iv %x", k.iv)
	}
	nk, err := k.next()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(nk.secret) != "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9" {
		t.Fatalf("ku %x", nk.secret)
	}
	pkt := unhex(t, "4cfe4189655e5cd55c41f69080575d7999c25a5bfb")
	h, err := parseHeader(pkt, 0)
	if err != nil {
		t.Fatal(err)
	}
	pn, payload, _, err := unprotectTry(k, pkt, h, 654360563)
	if err != nil {
		t.Fatal(err)
	}
	if pn != 654360564 || !bytes.Equal(payload, []byte{0x01}) {
		t.Fatalf("pn %d payload %x", pn, payload)
	}
}

func TestChaCha20Poly1305RFC8439(t *testing.T) {
	a, _ := newChaCha20Poly1305(unhex(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"))
	pt := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	nonce := unhex(t, "070000004041424344454647")
	ad := unhex(t, "50515253c0c1c2c3c4c5c6c7")
	out := a.Seal(nil, nonce, pt, ad)
	want := "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116" + "1ae10b594f09e26a7e902ecbd0600691"
	if hex.EncodeToString(out) != want {
		t.Fatalf("seal %x", out)
	}
	back, err := a.Open(nil, nonce, out, ad)
	if err != nil || !bytes.Equal(back, pt) {
		t.Fatalf("open %v", err)
	}
	out[3] ^= 1
	if _, err := a.Open(nil, nonce, out, ad); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

func TestPacketRoundTrip(t *testing.T) {
	_, tx := initialKeys(unhex(t, "0102030405060708"), true)
	rx, _ := initialKeys(unhex(t, "0102030405060708"), false)
	dcid, scid := randomCID(), randomCID()
	payload := appendCrypto(nil, 0, bytes.Repeat([]byte{7}, 300))
	pkt := seal(tx, longHeader(ptInitial, dcid, scid, nil, 5, len(payload)), 5, payload, false)
	h, err := parseHeader(pkt, cidLen)
	if err != nil {
		t.Fatal(err)
	}
	pn, got, _, err := unprotectTry(rx, pkt, h, 4)
	if err != nil || pn != 5 || !bytes.Equal(got, payload) {
		t.Fatalf("pn %d err %v", pn, err)
	}
	frames, err := parseFrames(got)
	if err != nil || len(frames) != 1 || frames[0].typ != frCrypto || len(frames[0].data) != 300 {
		t.Fatalf("frames %v %v", frames, err)
	}
}

func TestAckFrameRoundTrip(t *testing.T) {
	var rs rangeSet
	for _, v := range []uint64{1, 2, 3, 7, 8, 12, 20, 21, 22} {
		rs.add(v, v)
	}
	frames, err := parseFrames(appendAck(nil, rs.descending(32)))
	if err != nil {
		t.Fatal(err)
	}
	got := frames[0].ackRanges
	want := []ackRange{{20, 22}, {12, 12}, {7, 8}, {1, 3}}
	if len(got) != len(want) {
		t.Fatalf("ranges %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ranges %v", got)
		}
	}
}

func TestDecodePN(t *testing.T) {
	if got := decodePN(0xa82f30ea, 0x9b32, 2); got != 0xa82f9b32 {
		t.Fatalf("got %x", got)
	}
}

type lossyConn struct {
	net.PacketConn
	n    atomic.Int64
	drop int64
}

func (l *lossyConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if l.drop > 0 && l.n.Add(1)%l.drop == 0 {
		return len(b), nil
	}
	return l.PacketConn.WriteTo(b, addr)
}

func (l *lossyConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, a, err := l.PacketConn.ReadFrom(b)
		if err != nil || l.drop <= 0 || l.n.Add(1)%l.drop != 0 {
			return n, a, err
		}
	}
}

func testPKI(t *testing.T) (server, client tls.Certificate, pool *x509.CertPool) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	pool = x509.NewCertPool()
	pool.AddCert(ca)
	leaf := func(cn string, usage x509.ExtKeyUsage, serial int64) tls.Certificate {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
			NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{usage}, DNSNames: []string{cn}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: k}
	}
	return leaf("localhost", x509.ExtKeyUsageServerAuth, 2), leaf("ALPHA-1", x509.ExtKeyUsageClientAuth, 3), pool
}

func runEcho(t *testing.T, drop int64, size int) {
	srvCert, cliCert, pool := testPKI(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := Listen(&lossyConn{PacketConn: pc, drop: drop}, &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}, 30*time.Second)
	defer l.Close()
	cnCh := make(chan string, 1)
	go func() {
		st, err := l.Accept()
		if err != nil {
			return
		}
		cs := st.ConnectionState()
		cn := ""
		if len(cs.PeerCertificates) > 0 {
			cn = cs.PeerCertificates[0].Subject.CommonName
		}
		cnCh <- cn + "/" + cs.NegotiatedProtocol
		io.Copy(st, st)
		st.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := Dial(ctx, l.Addr().String(), &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cliCert}, ServerName: "localhost"}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	data := make([]byte, size)
	rand.Read(data)
	go func() {
		st.Write(data)
	}()
	st.SetReadDeadline(time.Now().Add(30 * time.Second))
	got := make([]byte, size)
	if _, err := io.ReadFull(st, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("echo mismatch")
	}
	select {
	case v := <-cnCh:
		if v != "ALPHA-1/takstream" {
			t.Fatalf("identity %q", v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no accept")
	}
}

func TestEcho(t *testing.T) {
	runEcho(t, 0, 64<<10)
}

func TestEchoLargeWithLoss(t *testing.T) {
	runEcho(t, 7, 3<<20)
}

func TestRejectsUntrustedClient(t *testing.T) {
	srvCert, _, pool := testPKI(t)
	_, otherCli, _ := testPKI(t)
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	l := Listen(pc, &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}, 30*time.Second)
	defer l.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		if _, err := l.Accept(); err == nil {
			accepted <- struct{}{}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := Dial(ctx, l.Addr().String(), &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{otherCli}, ServerName: "localhost"}, 30*time.Second)
	if err == nil {
		st.Write([]byte("hello"))
		st.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 10)
		st.Read(buf)
		st.Close()
	}
	select {
	case <-accepted:
		t.Fatal("untrusted client accepted")
	case <-time.After(500 * time.Millisecond):
	}
}

func TestIdleTimeout(t *testing.T) {
	srvCert, cliCert, pool := testPKI(t)
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	l := Listen(pc, &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}, 300*time.Millisecond)
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := Dial(ctx, l.Addr().String(), &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cliCert}, ServerName: "localhost"}, 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	st.Write([]byte("x"))
	sst, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	st.c.mu.Lock()
	st.c.pc.Close()
	st.c.mu.Unlock()
	sst.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 8)
	sst.Read(buf)
	start := time.Now()
	for {
		if _, err := sst.Read(buf); err != nil {
			break
		}
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("idle timeout did not close server stream")
	}
	deadline := time.Now().Add(2 * time.Second)
	for l.Conns() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if l.Conns() != 0 {
		t.Fatal("connection not removed after idle timeout")
	}
}

func TestJunkDatagramsDoNotStopTheListener(t *testing.T) {
	srvCert, cliCert, pool := testPKI(t)
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	l := Listen(pc, &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}, 30*time.Second)
	defer l.Close()
	c, err := net.Dial("udp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range [][]byte{nil, {0x00}, {0x80}, {0xc0, 0, 0, 0, 1}, bytes.Repeat([]byte{0xff}, 1300), bytes.Repeat([]byte{0x40}, 9)} {
		c.Write(d)
	}
	c.Close()
	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := Dial(ctx, l.Addr().String(), &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cliCert}, ServerName: "localhost"}, 30*time.Second)
	if err != nil {
		t.Fatalf("listener stopped after junk datagrams: %v", err)
	}
	st.Close()
}

func TestStreamGapFloodIsRefused(t *testing.T) {
	c := newConn(false, nil, nil, 0)
	st := newStream(c, 0)
	var err error
	for i := 0; i < 3*maxStreamGaps && err == nil; i++ {
		err = st.receive(uint64(2+2*i), []byte{1}, false)
	}
	if err != errFlowControl {
		t.Fatalf("gap flood not refused: %v", err)
	}
	if len(st.rparts) > maxStreamGaps {
		t.Fatalf("%d fragments buffered", len(st.rparts))
	}
	ok := newStream(newConn(false, nil, nil, 0), 0)
	for i := 0; i < 3*maxStreamGaps; i++ {
		if err := ok.receive(uint64(i), []byte{byte(i)}, false); err != nil {
			t.Fatalf("in-order data refused at %d: %v", i, err)
		}
	}
}
