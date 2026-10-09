package mumble

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestOCB2Vectors(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	c := &cryptState{}
	c.block, _ = aes.NewCipher(key)
	var nonce [16]byte
	copy(nonce[:], key)
	tag := c.ocbEncrypt(nil, nil, nonce)
	if hex.EncodeToString(tag[:]) != "bf3108130773ad5ec70ec69e7875a7b0" {
		t.Fatalf("blank tag %x", tag)
	}
	src := make([]byte, 40)
	for i := range src {
		src[i] = byte(i)
	}
	enc := make([]byte, 40)
	tag = c.ocbEncrypt(src, enc, nonce)
	if hex.EncodeToString(tag[:]) != "9db0cdf880f73e3e10d4eb3217766688" || hex.EncodeToString(enc) != "f75d6bc8b4dc8d66b836a2b08b32a6369f1cd3c5228d79fd6c267f5f6aa7b231c7dfb9d59951ae9c" {
		t.Fatalf("long tag %x enc %x", tag, enc)
	}
	plain := make([]byte, 40)
	dtag, ok := c.ocbDecrypt(enc, plain, nonce)
	if !ok || dtag != tag || !bytes.Equal(plain, src) {
		t.Fatal("decrypt mismatch")
	}
}

func pairedStates() (*cryptState, *cryptState) {
	a := newCryptState()
	b := &cryptState{key: a.key, block: a.block}
	b.encryptIV = a.decryptIV
	b.decryptIV = a.encryptIV
	return a, b
}

func TestCryptOrderingAndReplay(t *testing.T) {
	server, client := pairedStates()
	var pkts [][]byte
	for i := 0; i < 300; i++ {
		pkts = append(pkts, client.encrypt([]byte{byte(i), 1, 2, 3, byte(i >> 8)}))
	}
	for i := 0; i < 250; i++ {
		if _, err := server.decrypt(pkts[i]); err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
	}
	if _, err := server.decrypt(pkts[249]); err == nil {
		t.Fatal("replayed packet accepted")
	}
	if _, err := server.decrypt(pkts[260]); err != nil {
		t.Fatal(err)
	}
	if p, err := server.decrypt(pkts[255]); err != nil || p[0] != 255 {
		t.Fatalf("late packet: %v", err)
	}
	if server.lost.Load() == 0 || server.late.Load() == 0 {
		t.Fatal("lost and late not counted")
	}
	tampered := append([]byte(nil), pkts[270]...)
	tampered[6] ^= 0xff
	if _, err := server.decrypt(tampered); err == nil {
		t.Fatal("tampered packet accepted")
	}
	back := server.encrypt([]byte("hello"))
	if p, err := client.decrypt(back); err != nil || string(p) != "hello" {
		t.Fatal("server to client failed")
	}
}

func testTLS(t *testing.T) *tls.Config {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}}
}

type testClient struct {
	t       *testing.T
	nc      net.Conn
	br      *bufio.Reader
	session uint32
	crypt   *cryptState
	chans   map[string]uint32
	msgs    chan [2]any
}

func dialClient(t *testing.T, addr, user, pass string) (*testClient, error) {
	nc, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	c := &testClient{t: t, nc: nc, br: bufio.NewReader(nc), chans: map[string]uint32{}, msgs: make(chan [2]any, 1000)}
	c.write(msgVersion, pbBuf(nil).Uint(1, serverVersion))
	c.write(msgAuthenticate, pbBuf(nil).Str(1, user).Str(2, pass).Bool(5, true))
	for {
		typ, payload, err := c.read()
		if err != nil {
			return nil, err
		}
		m, _ := pbParse(payload)
		switch typ {
		case msgReject:
			return nil, errors.New(m.str(2))
		case msgCryptSetup:
			cs := &cryptState{}
			copy(cs.key[:], m.bytes(1))
			copy(cs.encryptIV[:], m.bytes(2))
			copy(cs.decryptIV[:], m.bytes(3))
			cs.block, _ = aes.NewCipher(cs.key[:])
			c.crypt = cs
		case msgChannelState:
			c.chans[m.str(3)] = uint32(m.uint(1))
		case msgServerSync:
			c.session = uint32(m.uint(1))
			go c.loop()
			return c, nil
		}
	}
}

func (c *testClient) write(typ uint16, payload []byte) {
	c.nc.Write(frame(typ, payload))
}

func (c *testClient) read() (uint16, []byte, error) {
	c.nc.SetReadDeadline(time.Now().Add(5 * time.Second))
	var hdr [6]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return 0, nil, err
	}
	p := make([]byte, binary.BigEndian.Uint32(hdr[2:]))
	_, err := io.ReadFull(c.br, p)
	return binary.BigEndian.Uint16(hdr[:]), p, err
}

func (c *testClient) loop() {
	for {
		c.nc.SetReadDeadline(time.Now().Add(time.Minute))
		var hdr [6]byte
		if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
			close(c.msgs)
			return
		}
		p := make([]byte, binary.BigEndian.Uint32(hdr[2:]))
		if _, err := io.ReadFull(c.br, p); err != nil {
			close(c.msgs)
			return
		}
		c.msgs <- [2]any{binary.BigEndian.Uint16(hdr[:]), p}
	}
}

func (c *testClient) expect(typ uint16, pred func([]byte) bool) []byte {
	c.t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case m, ok := <-c.msgs:
			if !ok {
				c.t.Fatal("connection closed")
			}
			if m[0].(uint16) == typ && (pred == nil || pred(m[1].([]byte))) {
				return m[1].([]byte)
			}
		case <-deadline:
			c.t.Fatalf("message type %d not received", typ)
			return nil
		}
	}
}

func (c *testClient) expectNone(typ uint16, wait time.Duration) {
	c.t.Helper()
	deadline := time.After(wait)
	for {
		select {
		case m, ok := <-c.msgs:
			if !ok {
				return
			}
			if m[0].(uint16) == typ {
				c.t.Fatalf("unexpected message type %d", typ)
			}
		case <-deadline:
			return
		}
	}
}

func startTestServer(t *testing.T) (*Server, string) {
	s := NewServer("Test TAK")
	s.Auth = func(user, pass, remote string) (*Identity, error) {
		switch {
		case user == "alpha" && pass == "a":
			return &Identity{Name: "alpha", Groups: []string{"Blue"}}, nil
		case user == "bravo" && pass == "b":
			return &Identity{Name: "bravo", Groups: []string{"Red"}}, nil
		}
		return nil, ErrRejected
	}
	s.SetChannels([]Channel{{Name: "Blue", Group: "Blue"}, {Name: "Red", Group: "Red"}, {Name: "Lobby"}})
	var ln net.Listener
	var uc *net.UDPConn
	for attempt := 0; ; attempt++ {
		l, err := tls.Listen("tcp", "127.0.0.1:0", testTLS(t))
		if err != nil {
			t.Fatal(err)
		}
		ta := l.Addr().(*net.TCPAddr)
		u, err := net.ListenUDP("udp", &net.UDPAddr{IP: ta.IP, Port: ta.Port})
		if err == nil {
			ln, uc = l, u
			break
		}
		l.Close()
		if attempt == 20 {
			t.Fatal(err)
		}
	}
	s.ListenUDP(uc)
	go s.Serve(ln)
	t.Cleanup(s.Close)
	return s, ln.Addr().String()
}

func opusPacket(target byte, seq int) []byte {
	pkt := []byte{4<<5 | target}
	pkt = appendVarint(pkt, uint64(seq))
	pkt = appendVarint(pkt, 3)
	return append(pkt, 0xaa, 0xbb, 0xcc)
}

func TestVoiceSession(t *testing.T) {
	s, addr := startTestServer(t)
	if _, err := dialClient(t, addr, "alpha", "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
	a, err := dialClient(t, addr, "alpha", "a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := dialClient(t, addr, "bravo", "b")
	if err != nil {
		t.Fatal(err)
	}
	a.expect(msgUserState, func(p []byte) bool { m, _ := pbParse(p); return m.str(3) == "bravo" })
	for deadline := time.Now().Add(2 * time.Second); len(s.Users()) != 2 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if len(s.Users()) != 2 {
		t.Fatalf("users %v", s.Users())
	}

	a.write(msgUDPTunnel, opusPacket(0, 1))
	got := b.expect(msgUDPTunnel, nil)
	want := append([]byte{4 << 5}, appendVarint(nil, uint64(a.session))...)
	if !bytes.HasPrefix(got, want) || !bytes.HasSuffix(got, []byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("relayed voice %x", got)
	}

	a.write(msgTextMessage, pbBuf(nil).Uint(3, 0).Str(5, "hello root"))
	txt := b.expect(msgTextMessage, nil)
	if m, _ := pbParse(txt); m.str(5) != "hello root" || uint32(m.uint(1)) != a.session {
		t.Fatal("text message wrong")
	}

	b.write(msgUserState, pbBuf(nil).Uint(5, uint64(b.chans["Blue"])))
	b.expect(msgPermissionDenied, nil)
	a.write(msgUserState, pbBuf(nil).Uint(5, uint64(a.chans["Blue"])))
	b.expect(msgUserState, func(p []byte) bool { m, _ := pbParse(p); return uint32(m.uint(1)) == a.session && m.has(5) })
	a.write(msgUDPTunnel, opusPacket(0, 2))
	b.expectNone(msgUDPTunnel, 500*time.Millisecond)

	a.write(msgVoiceTarget, pbBuf(nil).Uint(1, 5).Bytes(2, pbBuf(nil).Uint(1, uint64(b.session))))
	time.Sleep(100 * time.Millisecond)
	a.write(msgUDPTunnel, opusPacket(5, 3))
	got = b.expect(msgUDPTunnel, nil)
	if got[0] != 4<<5|2 {
		t.Fatalf("whisper header %x", got[0])
	}

	raddr, _ := net.ResolveUDPAddr("udp", addr)
	ua, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	defer ua.Close()
	a.write(msgUserState, pbBuf(nil).Uint(5, 0))
	b.expect(msgUserState, func(p []byte) bool { m, _ := pbParse(p); return uint32(m.uint(1)) == a.session && m.has(5) })
	ua.Write(a.crypt.encrypt(opusPacket(0, 4)))
	got = b.expect(msgUDPTunnel, nil)
	if !bytes.HasSuffix(got, []byte{0xaa, 0xbb, 0xcc}) {
		t.Fatal("udp voice not relayed")
	}
	b.write(msgUDPTunnel, opusPacket(0, 5))
	ua.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, err := ua.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := a.crypt.decrypt(buf[:n])
	if err != nil || !bytes.HasSuffix(plain, []byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("udp voice to client: %v", err)
	}

	ping := make([]byte, 12)
	copy(ping[4:], "abcdefgh")
	ua.Write(ping)
	n, err = ua.Read(buf)
	if err != nil || n != 24 || string(buf[4:12]) != "abcdefgh" || binary.BigEndian.Uint32(buf[12:]) != 2 {
		t.Fatalf("server ping: %v %x", err, buf[:n])
	}

	a.nc.Close()
	b.expect(msgUserRemove, nil)
}
